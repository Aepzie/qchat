// Package client manages the client side of a qchat server connection: the
// pinned, post-quantum-hybrid transport from package transport, the session
// handshake and keepalive from package protocol, and reconnection.
//
// A Session reports everything that happens as Events, so a user interface
// can stay a pure consumer:
//
//	s, err := client.New(client.Options{Addr: addr, Pin: pin})
//	...
//	go s.Run(ctx)
//	for ev := range s.Events() {
//		...
//	}
//
// # Security behaviour
//
// If the server presents a public key that does not match the pin, the
// session emits a SecurityAlert, moves to the Failed state and stops. It
// never retries on its own: a mismatch is what a machine-in-the-middle attack
// looks like, and silently retrying would hide it or, worse, train users to
// ignore it. The same applies to handshakes that are not TLS 1.3 with
// X25519MLKEM768 and to servers speaking an incompatible protocol version.
// A malformed server address (transport.ErrInvalidAddress) also stops the
// session at once, since retrying cannot fix a configuration mistake.
//
// Every other failure (network errors, server restarts, keepalive timeouts,
// errors reported by the server) leads to a reconnect with exponential
// backoff from one second up to one minute, with random jitter so that many
// clients do not reconnect in lockstep after a server restart.
//
// A refused authentication is permanent in the same way: a registration the
// relay denies (RegistrationDenied, Conflict or a bundle it cannot verify)
// and an Unauthorized reply during authentication stop the session with an
// error wrapping ErrAuthFailed. RateLimited and other errors during
// authentication lead to a reconnect.
//
// # Identities and requests
//
// With Options.Auth set, every connection registers the local bundle and
// authenticates before it counts as Connected: Hello/Welcome, then
// Register/Registered, AuthBegin/AuthChallenge and AuthProof/AuthOK, all
// within one handshake timeout. While connected, Request sends KeyRequest,
// Send, SendMulti, Register, PrekeyUpload, PrekeyRequest or SetAccessKey
// frames and returns the matching response, payloads routed to the local
// identity arrive as Delivery events, and Ack tells the relay that a
// delivered payload has been processed and may be deleted. The session
// carries ciphertext only; end-to-end encryption is the caller's concern.
//
// # Anonymous sessions (sealed sender)
//
// With Options.Anonymous set, connections neither register nor
// authenticate, and Request allows only SealedSend, SealedSendMulti and
// KeyRequest or PrekeyRequest carrying an access proof (see SealedSend,
// SealedSendMulti, AnonKeyRequest and AnonPrekeyRequest). The relay
// accepts these only on such connections and refuses them on
// authenticated ones, so a client keeps one authenticated Session to
// receive and one anonymous Session to send and to fetch its contacts'
// keys. An authenticated Session refuses sealed requests and lookups with
// a proof locally with ErrWrongSession, before anything reaches the relay;
// an anonymous one does the same for everything else.
//
// Over Tor the two Sessions must use different circuits, or the shared
// circuit links them: build each Session's Dialer with its own isolation
// token (NewIsolationToken). Without Tor the relay can link them by the
// client's address, so sealed sending then hides the sender only from the
// stored queue, not from the live relay.
//
// An anonymous Session does not reconnect: when its connection fails or
// ends, Run emits StateChanged{State: Failed} with an error wrapping
// ErrAnonymousSessionEnded and returns it. A reconnect would reuse the
// Dialer and thus its isolation token, putting the new connection on the
// circuit of the old one, which lets the relay or the exit link the
// recipient sets of both. The caller starts a new Session with a fresh
// token (NewIsolationToken) instead. Options.AnonymousReconnect restores
// automatic reconnection for callers that accept that linkage.
package client

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/transport"
)

// Authenticator supplies the local identity. A Session with a nil
// Authenticator neither registers nor authenticates.
type Authenticator interface {
	// ID returns the identity ID.
	ID() [32]byte
	// Bundle returns the encoded, self-signed identity bundle.
	Bundle() []byte
	// Invite returns the invite code to register with, or "" for none.
	Invite() string
	// SignAuth signs the relay's authentication challenge nonce, bound to
	// the relay fingerprint serverFP and to binding, the TLS channel
	// binding (transport.AuthBinding) of the connection the proof is sent
	// on. identity.Identity.SignAuth has this signature.
	SignAuth(serverFP transport.Fingerprint, nonce, binding []byte) ([]byte, error)
}

// Default timing parameters.
const (
	defaultBackoffMin  = time.Second
	defaultBackoffMax  = time.Minute
	handshakeTimeout   = 20 * time.Second
	writeTimeout       = 10 * time.Second
	dialTimeout        = 45 * time.Second
	defaultIdleGrace   = 10 * time.Second
	stableConnection   = 30 * time.Second
	closeTimeout       = 2 * time.Second
	maxOutstandingPing = 8
)

// helloID is the frame ID of the client's Hello and the server's Welcome.
const helloID = 1

// Errors reported in StateChanged events and returned by Run. Each wraps
// more detail where available; classify them with errors.Is.
var (
	// ErrHandshakeTimeout means the server did not complete the handshake,
	// including authentication, in time.
	ErrHandshakeTimeout = errors.New("client: server did not complete the handshake in time")
	// ErrKeepaliveTimeout means the server stopped answering keepalives.
	ErrKeepaliveTimeout = errors.New("client: server stopped responding")
	// ErrProtocolViolation means the server sent something the protocol does
	// not allow at that point.
	ErrProtocolViolation = errors.New("client: server violated the protocol")
	// ErrIncompatibleVersion means the server speaks a protocol version this
	// client does not. Updating the client (or server) is the only fix, so
	// the session does not retry.
	ErrIncompatibleVersion = errors.New("client: server speaks an incompatible protocol version")
	// ErrConnectionLost means an established connection broke.
	ErrConnectionLost = errors.New("client: connection lost")
	// ErrAuthFailed means the relay refused to register or authenticate the
	// local identity, or the identity could not be presented to it. Retrying
	// cannot fix that, so the session does not retry.
	ErrAuthFailed = errors.New("client: authentication failed")
	// ErrNotConnected is returned by Request while the session has no
	// authenticated connection.
	ErrNotConnected = errors.New("client: not connected")
	// ErrWrongSession is returned by Request for a request the kind of
	// session does not allow: sealed sends and lookups with an access
	// proof on an authenticated session, anything else on an anonymous
	// one.
	ErrWrongSession = errors.New("client: request not allowed on this kind of session")
	// ErrAnonymousSessionEnded is wrapped by the error that ends an
	// anonymous Session once its connection is gone, unless
	// Options.AnonymousReconnect is set. Start a new Session with a fresh
	// isolation token to continue.
	ErrAnonymousSessionEnded = errors.New("client: anonymous session ended")
)

// RemoteError is the error recorded when the server sends an Error frame.
type RemoteError struct {
	Code    protocol.ErrorCode
	Message string
}

func (e *RemoteError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("server error %s", e.Code)
	}
	return fmt.Sprintf("server error %s: %s", e.Code, e.Message)
}

// Options configures a Session.
type Options struct {
	// Addr is the server address, "host:port", as accepted by
	// transport.ValidateHostPort. The session uses its canonical form.
	Addr string
	// Pin is the SHA-256 SPKI fingerprint of the server's public key. It is
	// required; the zero value is rejected.
	Pin transport.Fingerprint
	// Dialer, if non-nil, opens the TCP connection, for example through a
	// SOCKS5 proxy such as Tor. TLS still runs end to end over it.
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
	// Auth, if non-nil, registers and authenticates every connection as
	// the local identity.
	Auth Authenticator
	// SkipRegister authenticates without sending Register first. Profile
	// recovery uses it to fetch the bundle the relay already holds: a newly
	// signed bundle would be rejected as a conflict. Authentication then
	// fails with NotFound if the relay does not know the identity.
	SkipRegister bool
	// Anonymous opens connections that neither register nor authenticate
	// and carry only sealed sends and lookups with an access proof. It
	// excludes Auth and SkipRegister. Such a Session ends instead of
	// reconnecting, unless AnonymousReconnect is set.
	Anonymous bool
	// AnonymousReconnect lets an anonymous Session reconnect like an
	// authenticated one. Every reconnect reuses Dialer, and with it the
	// Tor isolation token, so the connections share a circuit and can be
	// linked to each other. It requires Anonymous.
	AnonymousReconnect bool
}

// Session is one logical connection to a qchat server, kept alive across
// network failures. Create it with New, start it with Run and read Events
// until the channel is closed.
type Session struct {
	opts   Options
	events *eventQueue

	started atomic.Bool

	mu        sync.Mutex
	info      ConnectionInfo
	connected bool
	live      *liveConn

	backoffMin time.Duration
	backoffMax time.Duration
	handshake  time.Duration
	idleGrace  time.Duration
}

// New validates opts and returns an idle Session.
func New(opts Options) (*Session, error) {
	addr, err := transport.ValidateHostPort(opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	opts.Addr = addr
	if opts.Pin.IsZero() {
		return nil, errors.New("client: a server fingerprint (pin) is required")
	}
	if opts.Anonymous && (opts.Auth != nil || opts.SkipRegister) {
		return nil, errors.New("client: an anonymous session cannot authenticate")
	}
	if opts.AnonymousReconnect && !opts.Anonymous {
		return nil, errors.New("client: AnonymousReconnect requires an anonymous session")
	}
	return &Session{
		opts:       opts,
		events:     newEventQueue(),
		backoffMin: defaultBackoffMin,
		backoffMax: defaultBackoffMax,
		handshake:  handshakeTimeout,
		idleGrace:  defaultIdleGrace,
	}, nil
}

// Events returns the channel on which the session reports events. The
// channel is closed after Run returns and all pending events have been
// delivered. Consumers should keep reading until it is closed.
func (s *Session) Events() <-chan Event { return s.events.out }

// Addr returns the configured server address in canonical form.
func (s *Session) Addr() string { return s.opts.Addr }

// Pin returns the pinned server fingerprint.
func (s *Session) Pin() transport.Fingerprint { return s.opts.Pin }

// Info returns details of the current connection. ok is false while no
// connection is established.
func (s *Session) Info() (info ConnectionInfo, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info, s.connected
}

// Run connects and keeps the session alive until ctx is cancelled or a
// permanent failure occurs. It returns nil after cancellation, and otherwise
// the error that stopped the session (for example one wrapping
// transport.ErrPinMismatch). Run may be called only once.
func (s *Session) Run(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("client: Run called more than once")
	}
	defer s.events.close()

	attempt := 0
	failures := 0
	for {
		if ctx.Err() != nil {
			s.emit(StateChanged{State: Disconnected})
			return nil
		}
		attempt++
		s.emit(StateChanged{State: Connecting, Attempt: attempt})

		res := s.connectOnce(ctx)
		s.setDisconnected()

		if ctx.Err() != nil {
			s.emit(StateChanged{State: Disconnected})
			return nil
		}
		if err, stop := s.classify(res.err); stop {
			s.emit(StateChanged{State: Failed, Err: err})
			return err
		}
		if s.opts.Anonymous && !s.opts.AnonymousReconnect {
			err := anonymousEnded(res.err)
			s.emit(StateChanged{State: Failed, Err: err})
			return err
		}
		if res.established {
			attempt = 0
			if res.uptime >= stableConnection {
				failures = 0
			}
		}

		delay := backoffDelay(s.backoffMin, s.backoffMax, failures)
		failures++
		s.emit(StateChanged{State: Disconnected, Err: res.err, RetryIn: delay})

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			s.emit(StateChanged{State: Disconnected})
			return nil
		case <-timer.C:
		}
	}
}

// anonymousEnded returns the error that ends an anonymous Session whose
// connection ended with cause.
func anonymousEnded(cause error) error {
	if cause == nil {
		return ErrAnonymousSessionEnded
	}
	return fmt.Errorf("%w: %w", ErrAnonymousSessionEnded, cause)
}

// classify decides whether err ends the session. A pin mismatch also
// raises a SecurityAlert.
func (s *Session) classify(err error) (error, bool) {
	var mismatch *transport.PinMismatchError
	if errors.As(err, &mismatch) {
		s.emit(SecurityAlert{Expected: mismatch.Expected, Presented: mismatch.Presented})
		return err, true
	}
	if errors.Is(err, transport.ErrPinMismatch) {
		s.emit(SecurityAlert{Expected: s.opts.Pin})
		return err, true
	}
	if errors.Is(err, transport.ErrWeakHandshake) || errors.Is(err, ErrIncompatibleVersion) || errors.Is(err, transport.ErrInvalidAddress) || errors.Is(err, ErrAuthFailed) {
		return err, true
	}
	var remote *RemoteError
	if errors.As(err, &remote) && remote.Code == protocol.ErrCodeUnsupportedVersion {
		return fmt.Errorf("%w: %w", ErrIncompatibleVersion, err), true
	}
	return err, false
}

func (s *Session) emit(ev Event) { s.events.push(ev) }

func (s *Session) setConnected(info ConnectionInfo, c *liveConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.info = info
	s.connected = true
	s.live = c
}

func (s *Session) setDisconnected() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = false
	s.live = nil
}

// Request sends one request frame of type t with the given body and waits
// for the response with the same frame ID. On an authenticated session t
// must be TypeKeyRequest, TypeSend, TypeSendMulti, TypeRegister,
// TypePrekeyUpload, TypePrekeyRequest or TypeSetAccessKey, and a
// KeyRequest or PrekeyRequest must not carry an access proof; on an
// anonymous session (Options.Anonymous) it must be TypeSealedSend,
// TypeSealedSendMulti, or a protocol.KeyRequest or protocol.PrekeyRequest
// carrying an access proof. Any other combination fails with
// ErrWrongSession before anything is sent. Request is only allowed while the session is
// connected (and, unless anonymous, authenticated); otherwise it returns
// ErrNotConnected. An Error frame in reply is returned as a *RemoteError.
// If ctx ends or the connection is lost first, Request returns an error and
// does not resend the request; whether the server received it is unknown.
// Request may be called concurrently.
func (s *Session) Request(ctx context.Context, t protocol.FrameType, body any) (protocol.Frame, error) {
	want, ok := responseType(t)
	if !ok {
		return protocol.Frame{}, fmt.Errorf("client: %v is not a request frame", t)
	}
	if anonymousOnly(t, body) != s.opts.Anonymous {
		return protocol.Frame{}, fmt.Errorf("%w: %v", ErrWrongSession, t)
	}
	s.mu.Lock()
	c := s.live
	s.mu.Unlock()
	if c == nil || (s.opts.Auth == nil && !s.opts.Anonymous) {
		return protocol.Frame{}, ErrNotConnected
	}
	f, err := protocol.NewFrame(t, 0, body)
	if err != nil {
		return protocol.Frame{}, fmt.Errorf("client: build %v frame: %w", t, err)
	}
	resp, err := c.request(ctx, f)
	if err != nil {
		return protocol.Frame{}, err
	}
	if resp.Type == protocol.TypeError {
		remote, err := decodeRemoteError(resp)
		if err != nil {
			return protocol.Frame{}, err
		}
		return protocol.Frame{}, remote
	}
	if resp.Type != want {
		return protocol.Frame{}, fmt.Errorf("%w: %v answered with %v", ErrProtocolViolation, t, resp.Type)
	}
	return resp, nil
}

// responseType returns the frame type answering a request of type t, and
// whether t may be sent with Request.
func responseType(t protocol.FrameType) (protocol.FrameType, bool) {
	switch t {
	case protocol.TypeKeyRequest:
		return protocol.TypeKeyResponse, true
	case protocol.TypeSend:
		return protocol.TypeSendResult, true
	case protocol.TypeSendMulti:
		return protocol.TypeSendMultiResult, true
	case protocol.TypeRegister:
		return protocol.TypeRegistered, true
	case protocol.TypePrekeyUpload:
		return protocol.TypePrekeyStatus, true
	case protocol.TypePrekeyRequest:
		return protocol.TypePrekeyResponse, true
	case protocol.TypeSetAccessKey:
		return protocol.TypeAccessKeySet, true
	case protocol.TypeSealedSend:
		return protocol.TypeSendResult, true
	case protocol.TypeSealedSendMulti:
		return protocol.TypeSendMultiResult, true
	}
	return 0, false
}

// anonymousOnly reports whether a request of type t with body is one only
// anonymous sessions may send: a sealed send, or a key or prekey lookup
// carrying an access proof. Every other request is for authenticated
// sessions only.
func anonymousOnly(t protocol.FrameType, body any) bool {
	switch t {
	case protocol.TypeSealedSend, protocol.TypeSealedSendMulti:
		return true
	case protocol.TypeKeyRequest, protocol.TypePrekeyRequest:
		return carriesProof(body)
	}
	return false
}

// carriesProof reports whether body is a KeyRequest or PrekeyRequest with
// an access proof.
func carriesProof(body any) bool {
	switch req := body.(type) {
	case protocol.KeyRequest:
		return req.AccessProof != nil
	case *protocol.KeyRequest:
		return req != nil && req.AccessProof != nil
	case protocol.PrekeyRequest:
		return req.AccessProof != nil
	case *protocol.PrekeyRequest:
		return req != nil && req.AccessProof != nil
	}
	return false
}

// Ack tells the relay that the delivery with the given queue ID (see
// [Delivery.QueueID]) has been processed, so that the relay deletes its
// stored copy. The relay sends no response: Ack returns as soon as the frame
// is written and reports an error only if it could not be. Like Request it
// is allowed only while the session is authenticated and returns
// ErrNotConnected otherwise. A lost Ack is harmless: the relay delivers the
// message again after the next authentication. queueID must not be 0. Ack
// may be called concurrently.
func (s *Session) Ack(queueID uint64) error {
	s.mu.Lock()
	c := s.live
	s.mu.Unlock()
	if c == nil || s.opts.Auth == nil {
		return ErrNotConnected
	}
	f, err := protocol.NewFrame(protocol.TypeAck, c.newID(), protocol.Ack{QueueID: queueID})
	if err != nil {
		return fmt.Errorf("client: build %v frame: %w", protocol.TypeAck, err)
	}
	return c.writeFrame(c.life, f)
}

// backoffDelay returns the wait before the next attempt after failures
// consecutive failed attempts: min·2^failures capped at max, with "equal
// jitter" (a uniformly random value between half and all of it).
func backoffDelay(minDelay, maxDelay time.Duration, failures int) time.Duration {
	if minDelay <= 0 {
		minDelay = time.Millisecond
	}
	if maxDelay < minDelay {
		maxDelay = minDelay
	}
	d := minDelay
	for i := 0; i < failures && d < maxDelay; i++ {
		d *= 2
	}
	d = min(d, maxDelay)
	half := d / 2
	if half <= 0 {
		return d
	}
	return half + rand.N(d-half+1) // #nosec G404 -- backoff jitter, not a secret
}
