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
// In this phase the session carries no chat messages and therefore no end to
// end encryption: it only proves that the transport and handshake work.
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

// Default timing parameters.
const (
	defaultBackoffMin  = time.Second
	defaultBackoffMax  = time.Minute
	handshakeTimeout   = 10 * time.Second
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
	// ErrHandshakeTimeout means the server did not answer Hello in time.
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
	if errors.Is(err, transport.ErrWeakHandshake) || errors.Is(err, ErrIncompatibleVersion) || errors.Is(err, transport.ErrInvalidAddress) {
		return err, true
	}
	var remote *RemoteError
	if errors.As(err, &remote) && remote.Code == protocol.ErrCodeUnsupportedVersion {
		return fmt.Errorf("%w: %w", ErrIncompatibleVersion, err), true
	}
	return err, false
}

func (s *Session) emit(ev Event) { s.events.push(ev) }

func (s *Session) setConnected(info ConnectionInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.info = info
	s.connected = true
}

func (s *Session) setDisconnected() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = false
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
	return half + rand.N(d-half+1)
}
