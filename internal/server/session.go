package server

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
)

// closeReason names why a session ended. It is the only per-session detail
// that is logged.
type closeReason string

const (
	reasonClient             closeReason = "client"
	reasonDisconnected       closeReason = "disconnected"
	reasonHandshakeTimeout   closeReason = "handshake_timeout"
	reasonIdle               closeReason = "idle"
	reasonBadRequest         closeReason = "bad_request"
	reasonUnsupportedVersion closeReason = "unsupported_version"
	reasonRateLimited        closeReason = "rate_limited"
	reasonTooLarge           closeReason = "too_large"
	reasonUnauthorized       closeReason = "unauthorized"
	reasonUnsupportedData    closeReason = "unsupported_data"
	reasonWriteFailed        closeReason = "write_failed"
	reasonInternal           closeReason = "internal"
	reasonTooManySessions    closeReason = "too_many_sessions"
	reasonShutdown           closeReason = "shutdown"
)

// WebSocket close reasons. They are fixed strings: a close reason must never
// echo client data.
const (
	closeTextShutdown         = "server shutting down"
	closeTextHandshakeTimeout = "handshake timeout"
	closeTextIdle             = "idle timeout"
	closeTextBinaryOnly       = "binary messages only"
	closeTextProtocolError    = "protocol error"
	closeTextTooLarge         = "frame too large"
	closeTextInternal         = "internal error"
)

// outboundQueueSize is the number of encoded frames a session buffers for
// its writer. The bytes those frames hold are bounded separately, per
// session by limits.max_queue_bytes and across all sessions by
// limits.max_total_queue_bytes. Responses to the session's own requests
// wait for room; deliveries from other sessions are dropped when either
// bound is reached.
const outboundQueueSize = 64

// errorMessages holds the Error frame message for each code. Messages are
// short fixed ASCII strings that never contain client data or internals.
var errorMessages = map[protocol.ErrorCode]string{
	protocol.ErrCodeBadRequest:         "bad request",
	protocol.ErrCodeUnsupportedVersion: "unsupported version",
	protocol.ErrCodeRateLimited:        "rate limit exceeded",
	protocol.ErrCodeTooLarge:           "frame too large",
	protocol.ErrCodeInternal:           "internal error",
	protocol.ErrCodeUnauthorized:       "unauthorized",
	protocol.ErrCodeNotFound:           "not found",
	protocol.ErrCodeRegistrationDenied: "registration denied",
	protocol.ErrCodeConflict:           "conflict",
	protocol.ErrCodeQueueFull:          "queue full",
}

// errorReasons maps the code of a fatal Error frame to the matching close
// reason.
var errorReasons = map[protocol.ErrorCode]closeReason{
	protocol.ErrCodeBadRequest:         reasonBadRequest,
	protocol.ErrCodeUnsupportedVersion: reasonUnsupportedVersion,
	protocol.ErrCodeRateLimited:        reasonRateLimited,
	protocol.ErrCodeTooLarge:           reasonTooLarge,
	protocol.ErrCodeInternal:           reasonInternal,
	protocol.ErrCodeUnauthorized:       reasonUnauthorized,
}

// closeRequest is a close decided by the reader, carried out once the
// writer has flushed the frames queued before it (normally the Error frame
// explaining the close).
type closeRequest struct {
	reason closeReason
	status websocket.StatusCode
	text   string
}

// challenge is the single outstanding authentication challenge of a
// session.
type challenge struct {
	bundle  *identity.Bundle
	nonce   []byte
	expires time.Time
}

// session runs the protocol for one upgraded WebSocket connection.
//
// Two goroutines serve a session. The reader (run and everything it calls)
// reads, decides and queues responses; it alone touches the protocol state
// below. The writer (writeLoop) is the only goroutine that writes data
// frames to the connection, so deliveries queued by other sessions never
// interleave with responses. Timers and server shutdown end a session by
// closing its connection from yet another goroutine, which makes the
// pending read fail.
type session struct {
	srv         *Server
	conn        *websocket.Conn
	number      uint64
	limiter     *rate.Limiter
	authLimiter *rate.Limiter
	// multiLimiter counts the recipients named in SendMulti requests.
	multiLimiter *rate.Limiter
	// prekeyLimiter bounds PrekeyRequest and uploadLimiter PrekeyUpload.
	prekeyLimiter *rate.Limiter
	uploadLimiter *rate.Limiter
	// sealedLimiter counts the recipients named in sealed sends.
	sealedLimiter *rate.Limiter
	timer         *time.Timer

	out        chan []byte
	queue      *byteBudget
	stopping   chan struct{}
	writerDone chan struct{}

	closeOnce sync.Once
	closed    chan struct{}
	reason    closeReason

	// binding is the TLS channel binding of this connection, which every
	// authentication proof on it must sign. It is secret and never logged.
	binding []byte

	// ipKey is the connection-limit key of the client's address, used only
	// for the per-IP sealed sender bucket. It is never logged.
	ipKey netip.Addr

	pendingClose  *closeRequest
	challenge     *challenge
	mode          sessionMode
	authenticated bool
	id            identity.ID
	backlog       backlog

	// liveFloor is the lowest queue ID pushed to this session by deliver,
	// or 0. It is written by the senders' sessions and read by the reader.
	liveFloor atomic.Uint64
}

func newSession(srv *Server, conn *websocket.Conn, binding []byte) *session {
	limits := srv.cfg.Limits
	return &session{
		srv:           srv,
		conn:          conn,
		binding:       binding,
		number:        rand.Uint64(),
		limiter:       rate.NewLimiter(rate.Limit(limits.FramesPerSecond), limits.Burst),
		authLimiter:   rate.NewLimiter(srv.authRate, srv.authBurst),
		prekeyLimiter: rate.NewLimiter(srv.prekeyRate, srv.prekeyBurst),
		multiLimiter:  rate.NewLimiter(rate.Limit(float64(limits.MultiRecipientsPerMinute)/60), MultiRecipientsBurst),
		uploadLimiter: rate.NewLimiter(srv.uploadRate, srv.uploadBurst),
		sealedLimiter: rate.NewLimiter(rate.Limit(float64(limits.SealedRecipientsPerMinute)/60), SealedRecipientsBurst),
		out:           make(chan []byte, outboundQueueSize),
		queue:         newByteBudget(limits.MaxQueueBytes),
		stopping:      make(chan struct{}),
		writerDone:    make(chan struct{}),
		closed:        make(chan struct{}),
	}
}

// run serves the session until it ends and logs the outcome.
func (s *session) run() {
	logger := s.srv.logger.With("session", s.number)
	logger.Debug("session opened")
	s.timer = time.AfterFunc(s.srv.handshakeTimeout, func() {
		s.terminate(reasonHandshakeTimeout, websocket.StatusPolicyViolation, closeTextHandshakeTimeout)
	})
	go s.writeLoop()
	s.serve()
	s.timer.Stop()
	s.srv.unroute(s)
	close(s.stopping)
	<-s.writerDone
	s.discardQueued()
	if s.pendingClose != nil {
		s.terminate(s.pendingClose.reason, s.pendingClose.status, s.pendingClose.text)
	}
	s.terminate(reasonInternal, websocket.StatusInternalError, closeTextInternal)
	logger.Debug("session closed", "reason", string(s.reason))
}

// serve implements the session protocol: a Hello/Welcome handshake followed
// by requests. It returns once the session must end.
func (s *session) serve() {
	first, ok := s.nextFrame()
	if !ok {
		return
	}
	if !s.handleHello(first) {
		return
	}
	s.armIdleTimer()
	for {
		frame, ok := s.nextFrame()
		if !ok {
			return
		}
		s.armIdleTimer()
		if !s.dispatch(frame) {
			return
		}
	}
}

// dispatch handles one frame after the handshake and reports whether the
// session continues. Frame types a client must not send, including a
// second Hello, are protocol violations.
func (s *session) dispatch(frame protocol.Frame) bool {
	switch frame.Type {
	case protocol.TypePing:
		return s.handlePing(frame)
	case protocol.TypeRegister:
		return s.handleRegister(frame)
	case protocol.TypeAuthBegin:
		return s.handleAuthBegin(frame)
	case protocol.TypeAuthProof:
		return s.handleAuthProof(frame)
	case protocol.TypeKeyRequest:
		return s.handleKeyRequest(frame)
	case protocol.TypePrekeyUpload:
		return s.handlePrekeyUpload(frame)
	case protocol.TypePrekeyRequest:
		return s.handlePrekeyRequest(frame)
	case protocol.TypeAck:
		return s.handleAck(frame)
	case protocol.TypeSend:
		return s.handleSend(frame)
	case protocol.TypeSendMulti:
		return s.handleSendMulti(frame)
	case protocol.TypeSetAccessKey:
		return s.handleSetAccessKey(frame)
	case protocol.TypeSealedSend:
		return s.handleSealedSend(frame)
	case protocol.TypeSealedSendMulti:
		return s.handleSealedSendMulti(frame)
	default:
		return s.fail(frame.ID, protocol.ErrCodeBadRequest)
	}
}

// armIdleTimer (re)starts the idle timeout. If the previous timer already
// fired, the session is being closed and the extra expiry is harmless.
func (s *session) armIdleTimer() {
	s.timer.Stop()
	s.timer = time.AfterFunc(s.srv.idleTimeout, func() {
		s.terminate(reasonIdle, websocket.StatusPolicyViolation, closeTextIdle)
	})
}

// nextFrame reads, rate-limits and decodes the next message. On any failure
// it arranges for the session to end and returns false.
//
// Only data messages reach the token bucket. WebSocket control frames are
// consumed inside conn.Read: client Pings are answered with a Pong and
// Pongs are dropped, without passing through this code. That is an
// accepted residual risk:
//
//   - there is no amplification: a Pong echoes at most the 125-byte Ping
//     payload, and the client's masked Ping is larger than the Pong it
//     gets back;
//   - the cost is bounded by the client's own bandwidth, the per-IP
//     connection limit and the frame write timeout;
//   - control frames do not count as activity, so a client that sends
//     only control frames is still closed by the handshake or idle timer.
//
// coder/websocket offers AcceptOptions.OnPingReceived, which would let
// Pings spend tokens here, but the options are fixed inside
// transport.Accept, so wiring it in needs a change to that function.
func (s *session) nextFrame() (protocol.Frame, bool) {
	msgType, msg, err := s.conn.Read(context.Background())
	if err != nil {
		s.endAfterReadError(err)
		return protocol.Frame{}, false
	}
	if msgType != websocket.MessageBinary {
		s.terminate(reasonUnsupportedData, websocket.StatusUnsupportedData, closeTextBinaryOnly)
		return protocol.Frame{}, false
	}
	if !s.limiter.Allow() {
		return protocol.Frame{}, s.fail(0, protocol.ErrCodeRateLimited)
	}
	frame, err := protocol.Decode(msg)
	if err != nil {
		return protocol.Frame{}, s.fail(0, protocol.ErrorCodeFor(err))
	}
	return frame, true
}

// handleHello answers the client's first frame with a Welcome.
func (s *session) handleHello(frame protocol.Frame) bool {
	hello, err := protocol.DecodeBody[protocol.Hello](frame, protocol.TypeHello)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	version, err := protocol.Negotiate(hello)
	if err != nil {
		return s.fail(frame.ID, protocol.ErrCodeUnsupportedVersion)
	}
	limits := s.srv.cfg.Limits
	welcome := protocol.Welcome{
		Version:      version,
		MaxFrameSize: uint32(limits.MaxFrameSize),
		PingInterval: uint32(limits.PingInterval.Std() / time.Second),
	}
	return respond(s, protocol.TypeWelcome, frame.ID, welcome)
}

// handlePing answers a Ping with a Pong carrying the same ID and nonce.
func (s *session) handlePing(frame protocol.Frame) bool {
	ping, err := protocol.DecodeBody[protocol.Ping](frame, protocol.TypePing)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	return respond(s, protocol.TypePong, frame.ID, protocol.Pong{Nonce: ping.Nonce})
}

// requestErrorCode maps a body decoding error to an error code. Anything the
// protocol package does not classify is still the client's fault here.
func requestErrorCode(err error) protocol.ErrorCode {
	code := protocol.ErrorCodeFor(err)
	if code == protocol.ErrCodeInternal {
		return protocol.ErrCodeBadRequest
	}
	return code
}

// encodeFrame builds and encodes one frame. The concrete body type lets the
// protocol package check that body and frame type match.
func encodeFrame[T any](frameType protocol.FrameType, id uint64, body T) ([]byte, error) {
	frame, err := protocol.NewFrame(frameType, id, body)
	if err != nil {
		return nil, err
	}
	return protocol.Encode(frame)
}

// respond queues a response for the writer and reports whether the session
// continues. A body that cannot be encoded is answered with a non-fatal
// Internal error instead.
func respond[T any](s *session, frameType protocol.FrameType, id uint64, body T) bool {
	encoded, err := encodeFrame(frameType, id, body)
	if err != nil {
		s.srv.logger.Error("cannot encode response", "type", frameType.String())
		return s.reject(id, protocol.ErrCodeInternal)
	}
	return s.enqueue(encoded)
}

// enqueue hands an encoded frame to the writer, waiting for room in the
// queue, in the session's byte budget and in the server-wide byte budget.
// It returns false once the writer has stopped after a failed write or the
// connection was closed.
func (s *session) enqueue(encoded []byte) bool {
	size := int64(len(encoded))
	global := s.srv.queueBudget
	for {
		localFreed, globalFreed := s.queue.changed(), global.changed()
		if acquirePair(s.queue, global, size) {
			break
		}
		select {
		case <-localFreed:
		case <-globalFreed:
		case <-s.writerDone:
			return false
		case <-s.closed:
			return false
		}
	}
	select {
	case s.out <- encoded:
		return true
	case <-s.writerDone:
	case <-s.closed:
	}
	s.releaseQueued(size)
	return false
}

// offer queues a frame pushed by another session without waiting. It
// reports false if the queue is full, the session's or the server's byte
// budget is exhausted, or the session is ending; the frame is then dropped.
func (s *session) offer(encoded []byte) bool {
	select {
	case <-s.stopping:
		return false
	default:
	}
	size := int64(len(encoded))
	if !acquirePair(s.queue, s.srv.queueBudget, size) {
		return false
	}
	select {
	case s.out <- encoded:
		return true
	default:
		s.releaseQueued(size)
		return false
	}
}

// releaseQueued returns the bytes of a frame that left the queue to the
// session's and the server's budgets.
func (s *session) releaseQueued(size int64) {
	s.queue.release(size)
	s.srv.queueBudget.release(size)
}

// discardQueued drops the frames the writer left behind and releases their
// bytes. It runs after the session was unrouted and the writer stopped, so
// nothing can be queued concurrently.
func (s *session) discardQueued() {
	for {
		select {
		case encoded := <-s.out:
			s.releaseQueued(int64(len(encoded)))
		default:
			return
		}
	}
}

// writeLoop writes queued frames until the reader stops, then flushes what
// is still queued (such as the Error frame preceding a close). A failed
// write ends the session.
func (s *session) writeLoop() {
	defer close(s.writerDone)
	for {
		select {
		case encoded := <-s.out:
			if !s.write(encoded) {
				return
			}
		case <-s.stopping:
			s.flush()
			return
		}
	}
}

// flush writes the frames left in the queue without waiting for more.
func (s *session) flush() {
	for {
		select {
		case encoded := <-s.out:
			if !s.write(encoded) {
				return
			}
		default:
			return
		}
	}
}

// write writes one encoded frame within writeTimeout and terminates the
// session if that fails. The frame's bytes are released in either case.
func (s *session) write(encoded []byte) bool {
	defer s.releaseQueued(int64(len(encoded)))
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	if err := s.conn.Write(ctx, websocket.MessageBinary, encoded); err != nil {
		s.terminate(reasonWriteFailed, websocket.StatusInternalError, closeTextInternal)
		return false
	}
	return true
}

// queueError queues an Error frame with the fixed message for code.
func (s *session) queueError(id uint64, code protocol.ErrorCode) bool {
	encoded, err := encodeFrame(protocol.TypeError, id, protocol.ErrorBody{Code: code, Message: errorMessages[code]})
	if err != nil {
		return false
	}
	return s.enqueue(encoded)
}

// reject answers a request with a non-fatal Error frame: the request failed
// but the session continues. It reports whether the session continues.
func (s *session) reject(id uint64, code protocol.ErrorCode) bool {
	return s.queueError(id, code)
}

// fail answers with a fatal Error frame and arranges for the session to be
// closed with a policy violation once the frame is written. It always
// returns false, so handlers can return its result.
func (s *session) fail(id uint64, code protocol.ErrorCode) bool {
	if !code.Valid() {
		code = protocol.ErrCodeInternal
	}
	s.queueError(id, code)
	reason, ok := errorReasons[code]
	if !ok {
		reason = reasonBadRequest
	}
	s.pendingClose = &closeRequest{reason: reason, status: websocket.StatusPolicyViolation, text: closeTextProtocolError}
	return false
}

// endAfterReadError classifies a failed read and closes the session.
func (s *session) endAfterReadError(err error) {
	switch {
	case errors.Is(err, websocket.ErrMessageTooBig):
		s.terminate(reasonTooLarge, websocket.StatusMessageTooBig, closeTextTooLarge)
	case websocket.CloseStatus(err) != -1:
		s.terminate(reasonClient, websocket.StatusNormalClosure, "")
	default:
		s.terminate(reasonDisconnected, websocket.StatusGoingAway, "")
	}
}

// terminate closes the connection once. The first caller decides the
// logged reason; later callers block until the close has completed.
func (s *session) terminate(reason closeReason, code websocket.StatusCode, text string) {
	s.closeOnce.Do(func() {
		s.reason = reason
		close(s.closed)
		_ = s.conn.Close(code, text)
	})
}
