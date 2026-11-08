package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/transport"
)

// outcome describes how one connection attempt ended.
type outcome struct {
	err         error
	established bool
	uptime      time.Duration
}

// readResult is one message (or the terminal error) from the reader
// goroutine.
type readResult struct {
	kind websocket.MessageType
	msg  []byte
	err  error
}

// pendingPing is a Ping awaiting its Pong.
type pendingPing struct {
	nonce uint64
	sent  time.Time
}

// connectOnce runs a single connection from dial to teardown.
func (s *Session) connectOnce(ctx context.Context) outcome {
	dialCtx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	conn, state, err := transport.DialWithState(dialCtx, s.opts.Addr, s.opts.Pin, transport.DialOptions{
		NetDialContext: s.opts.Dialer,
		ReadLimit:      protocol.MaxFrameSize,
	})
	cancelDial()
	if err != nil {
		return outcome{err: err}
	}
	defer conn.CloseNow()
	binding, err := transport.AuthBinding(&state)
	if err != nil {
		return outcome{err: err}
	}

	// The reader uses its own context: cancelling the context passed to
	// Read tears the connection down immediately, which would prevent the
	// orderly close below.
	readCtx, cancelRead := context.WithCancel(context.Background())
	defer cancelRead()
	frames := make(chan readResult)
	go readLoop(readCtx, conn, frames)

	lifeCtx, cancelLife := context.WithCancel(ctx)
	defer cancelLife()
	c := &liveConn{
		session: s,
		conn:    conn,
		binding: binding,
		frames:  frames,
		life:    lifeCtx,
		nextID:  helloID + 1,
		pending: make(map[uint64]chan protocol.Frame),
		done:    make(chan struct{}),
	}
	info, err := c.handshake(ctx)
	if err != nil {
		c.shutdown(err)
		c.closeWith(err)
		return outcome{err: err}
	}
	s.setConnected(info, c)
	s.emit(StateChanged{State: Connected, Info: info})

	err = c.keepalive(ctx, info.PingInterval)
	s.setDisconnected()
	c.shutdown(err)
	c.closeWith(err)
	return outcome{err: err, established: true, uptime: time.Since(info.ConnectedAt)}
}

// readLoop forwards incoming messages until an error occurs or ctx ends.
func readLoop(ctx context.Context, conn *websocket.Conn, out chan<- readResult) {
	for {
		kind, msg, err := conn.Read(ctx)
		select {
		case out <- readResult{kind: kind, msg: msg, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

// liveConn is the state of one established WebSocket connection.
//
// Only the goroutine running connectOnce reads frames and touches
// outstanding. Writes from that goroutine and from Session.Request are
// serialised by writeMu, so the WebSocket has a single writer at a time.
type liveConn struct {
	session *Session
	conn    *websocket.Conn
	// binding is the TLS channel binding of this connection, signed into
	// the authentication proof. It is secret and never logged.
	binding []byte
	frames  <-chan readResult
	// life ends when the connection does; it bounds writes made on behalf
	// of Request, whose own context must not tear the connection down.
	life        context.Context
	outstanding map[uint64]pendingPing

	writeMu sync.Mutex

	mu sync.Mutex
	// nextID is the next frame ID, shared by pings and requests.
	nextID uint64
	// pending maps the frame IDs of requests to the channel awaiting their
	// response. A nil channel marks a request whose caller gave up; its
	// response is discarded when it arrives.
	pending map[uint64]chan protocol.Frame
	closed  bool
	cause   error
	done    chan struct{}
}

// newID returns a fresh frame ID.
func (c *liveConn) newID() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextID
	c.nextID++
	return id
}

// handshake sends Hello, waits for the matching Welcome and, when the
// session has an Authenticator, registers and authenticates. All steps share
// one timeout.
func (c *liveConn) handshake(ctx context.Context) (ConnectionInfo, error) {
	timer := time.NewTimer(c.session.handshake)
	defer timer.Stop()

	if err := c.send(ctx, protocol.TypeHello, helloID, protocol.ClientHello()); err != nil {
		return ConnectionInfo{}, err
	}
	f, err := c.await(ctx, timer)
	if err != nil {
		return ConnectionInfo{}, err
	}
	switch f.Type {
	case protocol.TypeError:
		return ConnectionInfo{}, c.remoteError(f)
	case protocol.TypeWelcome:
	default:
		return ConnectionInfo{}, fmt.Errorf("%w: expected Welcome, got %v", ErrProtocolViolation, f.Type)
	}
	if f.ID != helloID {
		return ConnectionInfo{}, fmt.Errorf("%w: Welcome has ID %d, want %d", ErrProtocolViolation, f.ID, helloID)
	}
	welcome, err := protocol.DecodeBody[protocol.Welcome](f, protocol.TypeWelcome)
	if errors.Is(err, protocol.ErrUnsupportedVersion) {
		return ConnectionInfo{}, fmt.Errorf("%w: %w", ErrIncompatibleVersion, err)
	}
	if err != nil {
		return ConnectionInfo{}, fmt.Errorf("%w: invalid Welcome: %w", ErrProtocolViolation, err)
	}
	if welcome.Version != protocol.Version {
		return ConnectionInfo{}, fmt.Errorf("%w: server selected version %d, client speaks %d", ErrIncompatibleVersion, welcome.Version, protocol.Version)
	}
	if auth := c.session.opts.Auth; auth != nil {
		c.session.emit(StateChanged{State: Authenticating})
		if err := c.authenticate(ctx, timer, auth); err != nil {
			return ConnectionInfo{}, err
		}
	}
	return ConnectionInfo{
		Addr:            c.session.opts.Addr,
		Fingerprint:     c.session.opts.Pin,
		ProtocolVersion: welcome.Version,
		PingInterval:    time.Duration(welcome.PingInterval) * time.Second,
		MaxFrameSize:    welcome.MaxFrameSize,
		Transport:       TransportDescription,
		ConnectedAt:     time.Now(),
	}, nil
}

// authenticate registers the local bundle and proves possession of the
// identity key: Register, AuthBegin and AuthProof, each answered before the
// next is sent. Register is skipped when Options.SkipRegister is set.
func (c *liveConn) authenticate(ctx context.Context, timer *time.Timer, auth Authenticator) error {
	if !c.session.opts.SkipRegister {
		register := protocol.Register{Bundle: auth.Bundle(), Invite: auth.Invite()}
		if _, err := c.step(ctx, timer, protocol.TypeRegister, register, protocol.TypeRegistered); err != nil {
			return err
		}
	}
	id := auth.ID()
	f, err := c.step(ctx, timer, protocol.TypeAuthBegin, protocol.AuthBegin{ID: id[:]}, protocol.TypeAuthChallenge)
	if err != nil {
		return err
	}
	challenge, err := protocol.DecodeBody[protocol.AuthChallenge](f, protocol.TypeAuthChallenge)
	if err != nil {
		return fmt.Errorf("%w: invalid AuthChallenge: %w", ErrProtocolViolation, err)
	}
	sig, err := auth.SignAuth(c.session.opts.Pin, bytes.Clone(challenge.Nonce), bytes.Clone(c.binding))
	if err != nil {
		return fmt.Errorf("%w: sign challenge: %w", ErrAuthFailed, err)
	}
	if _, err := c.step(ctx, timer, protocol.TypeAuthProof, protocol.AuthProof{Sig: sig}, protocol.TypeAuthOK); err != nil {
		return err
	}
	c.session.emit(Authenticated{ID: id})
	return nil
}

// step sends one handshake request and waits for its response of type want.
// An Error frame in reply is classified by authError.
func (c *liveConn) step(ctx context.Context, timer *time.Timer, t protocol.FrameType, body any, want protocol.FrameType) (protocol.Frame, error) {
	id := c.newID()
	f, err := protocol.NewFrame(t, id, body)
	if err != nil {
		return protocol.Frame{}, fmt.Errorf("%w: build %v frame: %w", ErrAuthFailed, t, err)
	}
	if err := c.writeFrame(ctx, f); err != nil {
		return protocol.Frame{}, err
	}
	resp, err := c.await(ctx, timer)
	if err != nil {
		return protocol.Frame{}, err
	}
	if resp.Type == protocol.TypeError {
		return protocol.Frame{}, c.authError(resp, t)
	}
	if resp.Type != want {
		return protocol.Frame{}, fmt.Errorf("%w: expected %v, got %v", ErrProtocolViolation, want, resp.Type)
	}
	if resp.ID != id {
		return protocol.Frame{}, fmt.Errorf("%w: %v has ID %d, want %d", ErrProtocolViolation, resp.Type, resp.ID, id)
	}
	return resp, nil
}

// authError turns an Error frame received in reply to the handshake request
// of type t into an error. Rejections that retrying cannot fix are wrapped
// in ErrAuthFailed, which stops the session: a refused registration
// (reported as a RegistrationDenied event) and Unauthorized, which means the
// key or proof is wrong. Everything else, such as RateLimited, is transient.
func (c *liveConn) authError(f protocol.Frame, t protocol.FrameType) error {
	remote, err := decodeRemoteError(f)
	if err != nil {
		return err
	}
	if t == protocol.TypeRegister && isRegistrationRefusal(remote.Code) {
		c.session.emit(RegistrationDenied{Code: remote.Code, Message: remote.Message})
		return fmt.Errorf("%w: %w", ErrAuthFailed, remote)
	}
	c.session.emit(ServerError{Code: remote.Code, Message: remote.Message})
	if remote.Code == protocol.ErrCodeUnauthorized {
		return fmt.Errorf("%w: %w", ErrAuthFailed, remote)
	}
	return remote
}

// isRegistrationRefusal reports whether code, in reply to Register, means
// the relay will not accept the bundle however often it is sent.
func isRegistrationRefusal(code protocol.ErrorCode) bool {
	switch code {
	case protocol.ErrCodeRegistrationDenied, protocol.ErrCodeConflict, protocol.ErrCodeBadRequest:
		return true
	}
	return false
}

// await returns the next frame received during the handshake.
func (c *liveConn) await(ctx context.Context, timer *time.Timer) (protocol.Frame, error) {
	select {
	case <-ctx.Done():
		return protocol.Frame{}, ctx.Err()
	case <-timer.C:
		return protocol.Frame{}, ErrHandshakeTimeout
	case r := <-c.frames:
		return decodeMessage(r)
	}
}

// keepalive pings the server every interval and handles incoming frames
// until the connection fails or ctx ends. It always returns a non-nil error.
//
// The connection is considered dead once nothing at all has been received
// for 2*interval plus the idle grace period. That deadline is tracked by its
// own timer, restarted on every received frame, rather than checked on the
// ping ticker: with long server-announced intervals, checking only on ticks
// would let a dead peer go unnoticed for up to one more interval.
func (c *liveConn) keepalive(ctx context.Context, interval time.Duration) error {
	c.outstanding = make(map[uint64]pendingPing)
	idleLimit := 2*interval + c.session.idleGrace
	lastRecv := time.Now()

	if err := c.ping(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	idle := time.NewTimer(idleLimit)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case r := <-c.frames:
			lastRecv = time.Now()
			idle.Reset(idleLimit)
			if err := c.handleFrame(ctx, r); err != nil {
				return err
			}
		case <-idle.C:
			return fmt.Errorf("%w: nothing received for %s", ErrKeepaliveTimeout, time.Since(lastRecv).Round(time.Second))
		case now := <-ticker.C:
			c.expirePings(now, idleLimit)
			if err := c.ping(ctx); err != nil {
				return err
			}
		}
	}
}

// handleFrame processes one message received after the handshake.
func (c *liveConn) handleFrame(ctx context.Context, r readResult) error {
	f, err := decodeMessage(r)
	if err != nil {
		return err
	}
	switch f.Type {
	case protocol.TypePong:
		pong, err := protocol.DecodeBody[protocol.Pong](f, protocol.TypePong)
		if err != nil {
			return fmt.Errorf("%w: invalid Pong: %w", ErrProtocolViolation, err)
		}
		p, ok := c.outstanding[f.ID]
		if !ok || p.nonce != pong.Nonce {
			return nil
		}
		delete(c.outstanding, f.ID)
		c.session.emit(RTT{time.Since(p.sent)})
		return nil
	case protocol.TypePing:
		ping, err := protocol.DecodeBody[protocol.Ping](f, protocol.TypePing)
		if err != nil {
			return fmt.Errorf("%w: invalid Ping: %w", ErrProtocolViolation, err)
		}
		return c.send(ctx, protocol.TypePong, f.ID, protocol.Pong(ping))
	case protocol.TypeDeliver:
		if c.session.opts.Anonymous {
			return fmt.Errorf("%w: Deliver on an anonymous connection", ErrProtocolViolation)
		}
		deliver, err := protocol.DecodeBody[protocol.Deliver](f, protocol.TypeDeliver)
		if err != nil {
			return fmt.Errorf("%w: invalid Deliver: %w", ErrProtocolViolation, err)
		}
		c.session.emit(Delivery{From: [protocol.IDSize]byte(deliver.From), Payload: bytes.Clone(deliver.Payload), QueueID: deliver.QueueID})
		return nil
	case protocol.TypeRegistered, protocol.TypeAuthChallenge, protocol.TypeAuthOK,
		protocol.TypeKeyResponse, protocol.TypeSendResult, protocol.TypeSendMultiResult, protocol.TypePrekeyStatus, protocol.TypePrekeyResponse,
		protocol.TypeAccessKeySet:
		c.resolve(f)
		return nil
	case protocol.TypeError:
		if c.resolve(f) {
			return nil
		}
		return c.remoteError(f)
	default:
		return fmt.Errorf("%w: unexpected %v frame", ErrProtocolViolation, f.Type)
	}
}

// resolve hands f to the request with the same frame ID and reports whether
// that ID belongs to a request, pending or abandoned. Responses to unknown
// IDs are left to the caller.
func (c *liveConn) resolve(f protocol.Frame) bool {
	c.mu.Lock()
	ch, ok := c.pending[f.ID]
	if ok {
		delete(c.pending, f.ID)
	}
	c.mu.Unlock()
	if ch != nil {
		ch <- f
	}
	return ok
}

// request sends f with a fresh frame ID and waits for the frame answering
// it, ctx to end or the connection to close.
func (c *liveConn) request(ctx context.Context, f protocol.Frame) (protocol.Frame, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Frame{}, err
	}
	reply := make(chan protocol.Frame, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return protocol.Frame{}, c.lostError()
	}
	f.ID = c.nextID
	c.nextID++
	c.pending[f.ID] = reply
	c.mu.Unlock()

	if err := c.writeFrame(c.life, f); err != nil {
		c.abandon(f.ID)
		select {
		case <-c.done:
			return protocol.Frame{}, c.lostError()
		default:
		}
		return protocol.Frame{}, err
	}
	select {
	case resp := <-reply:
		return resp, nil
	case <-ctx.Done():
		c.abandon(f.ID)
		return protocol.Frame{}, ctx.Err()
	case <-c.done:
		select {
		case resp := <-reply:
			return resp, nil
		default:
		}
		return protocol.Frame{}, c.lostError()
	}
}

// abandon marks the request id as given up, so that its late response is
// discarded rather than treated as unsolicited.
func (c *liveConn) abandon(id uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.pending[id]; ok {
		c.pending[id] = nil
	}
}

// shutdown records why the connection ended and fails every pending
// request.
func (c *liveConn) shutdown(cause error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.cause = cause
	c.pending = nil
	close(c.done)
}

// lostError is the error returned to requests cut off by the end of the
// connection.
func (c *liveConn) lostError() error {
	c.mu.Lock()
	cause := c.cause
	c.mu.Unlock()
	if errors.Is(cause, ErrConnectionLost) {
		return cause
	}
	return fmt.Errorf("%w: %w", ErrConnectionLost, cause)
}

// ping sends a Ping with a fresh ID and random nonce.
func (c *liveConn) ping(ctx context.Context) error {
	if len(c.outstanding) >= maxOutstandingPing {
		return fmt.Errorf("%w: %d keepalives unanswered", ErrKeepaliveTimeout, len(c.outstanding))
	}
	id := c.newID()
	nonce := rand.Uint64()
	c.outstanding[id] = pendingPing{nonce: nonce, sent: time.Now()}
	return c.send(ctx, protocol.TypePing, id, protocol.Ping{Nonce: nonce})
}

// expirePings forgets Pings older than limit, so a lost Pong does not count
// against maxOutstandingPing forever.
func (c *liveConn) expirePings(now time.Time, limit time.Duration) {
	for id, p := range c.outstanding {
		if now.Sub(p.sent) > limit {
			delete(c.outstanding, id)
		}
	}
}

// remoteError decodes an Error frame, reports it and returns it as an error.
func (c *liveConn) remoteError(f protocol.Frame) error {
	remote, err := decodeRemoteError(f)
	if err != nil {
		return err
	}
	c.session.emit(ServerError{Code: remote.Code, Message: remote.Message})
	return remote
}

// decodeRemoteError decodes an Error frame into a *RemoteError with a
// sanitised message.
func decodeRemoteError(f protocol.Frame) (*RemoteError, error) {
	body, err := protocol.DecodeBody[protocol.ErrorBody](f, protocol.TypeError)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid Error frame: %w", ErrProtocolViolation, err)
	}
	return &RemoteError{Code: body.Code, Message: SanitizeASCII(body.Message, protocol.MaxErrorMessageLen)}, nil
}

// send encodes body as a frame of type t with the given ID and writes it.
func (c *liveConn) send(ctx context.Context, t protocol.FrameType, id uint64, body any) error {
	f, err := protocol.NewFrame(t, id, body)
	if err != nil {
		return fmt.Errorf("client: build %v frame: %w", t, err)
	}
	return c.writeFrame(ctx, f)
}

// writeFrame encodes f and writes it with the write timeout, holding
// writeMu.
func (c *liveConn) writeFrame(ctx context.Context, f protocol.Frame) error {
	raw, err := protocol.Encode(f)
	if err != nil {
		return fmt.Errorf("client: encode %v frame: %w", f.Type, err)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := c.conn.Write(wctx, websocket.MessageBinary, raw); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: write: %w", ErrConnectionLost, err)
	}
	return nil
}

// closeWith ends the connection. For protocol violations the server is told
// why, best effort, before the WebSocket is closed.
func (c *liveConn) closeWith(cause error) {
	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()
	if errors.Is(cause, ErrProtocolViolation) {
		_ = c.send(ctx, protocol.TypeError, 0, protocol.ErrorBody{Code: protocol.ErrCodeBadRequest, Message: "protocol violation"})
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.conn.Close(websocket.StatusNormalClosure, "")
	}()
	select {
	case <-done:
	case <-ctx.Done():
		_ = c.conn.CloseNow()
	}
}

// decodeMessage turns a read result into a frame, mapping every failure to
// an error suitable for StateChanged.
func decodeMessage(r readResult) (protocol.Frame, error) {
	if r.err != nil {
		if status := websocket.CloseStatus(r.err); status != -1 {
			return protocol.Frame{}, fmt.Errorf("%w: server closed the connection (%v)", ErrConnectionLost, status)
		}
		return protocol.Frame{}, fmt.Errorf("%w: %w", ErrConnectionLost, r.err)
	}
	if r.kind != websocket.MessageBinary {
		return protocol.Frame{}, fmt.Errorf("%w: text message received", ErrProtocolViolation)
	}
	f, err := protocol.Decode(r.msg)
	if errors.Is(err, protocol.ErrUnsupportedVersion) {
		return protocol.Frame{}, fmt.Errorf("%w: %w", ErrIncompatibleVersion, err)
	}
	if err != nil {
		return protocol.Frame{}, fmt.Errorf("%w: %w", ErrProtocolViolation, err)
	}
	return f, nil
}
