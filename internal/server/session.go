package server

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

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
	reasonUnsupportedData    closeReason = "unsupported_data"
	reasonWriteFailed        closeReason = "write_failed"
	reasonInternal           closeReason = "internal"
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

// errorMessages holds the Error frame message for each code. Messages are
// short fixed ASCII strings that never contain client data or internals.
var errorMessages = map[protocol.ErrorCode]string{
	protocol.ErrCodeBadRequest:         "bad request",
	protocol.ErrCodeUnsupportedVersion: "unsupported version",
	protocol.ErrCodeRateLimited:        "rate limit exceeded",
	protocol.ErrCodeTooLarge:           "frame too large",
	protocol.ErrCodeInternal:           "internal error",
}

// errorReasons maps an Error frame code to the matching close reason.
var errorReasons = map[protocol.ErrorCode]closeReason{
	protocol.ErrCodeBadRequest:         reasonBadRequest,
	protocol.ErrCodeUnsupportedVersion: reasonUnsupportedVersion,
	protocol.ErrCodeRateLimited:        reasonRateLimited,
	protocol.ErrCodeTooLarge:           reasonTooLarge,
	protocol.ErrCodeInternal:           reasonInternal,
}

// session runs the protocol for one upgraded WebSocket connection.
//
// All reads and writes happen on the session goroutine. Timers and server
// shutdown end a session by closing its connection from another goroutine,
// which makes the pending read fail.
type session struct {
	srv     *Server
	conn    *websocket.Conn
	number  uint64
	limiter *rate.Limiter
	timer   *time.Timer

	closeOnce sync.Once
	reason    closeReason
}

func newSession(srv *Server, conn *websocket.Conn) *session {
	limits := srv.cfg.Limits
	return &session{
		srv:     srv,
		conn:    conn,
		number:  rand.Uint64(),
		limiter: rate.NewLimiter(rate.Limit(limits.FramesPerSecond), limits.Burst),
	}
}

// run serves the session until it ends and logs the outcome.
func (s *session) run() {
	logger := s.srv.logger.With("session", s.number)
	logger.Debug("session opened")
	s.timer = time.AfterFunc(s.srv.handshakeTimeout, func() {
		s.terminate(reasonHandshakeTimeout, websocket.StatusPolicyViolation, closeTextHandshakeTimeout)
	})
	s.serve()
	s.timer.Stop()
	s.terminate(reasonInternal, websocket.StatusInternalError, closeTextInternal)
	logger.Debug("session closed", "reason", string(s.reason))
}

// serve implements the session protocol: a Hello/Welcome handshake followed
// by Ping/Pong keepalives. It returns once the session has been terminated.
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
		if !s.handlePing(frame) {
			return
		}
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
// it terminates the session and returns false.
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
		s.fail(0, protocol.ErrCodeRateLimited)
		return protocol.Frame{}, false
	}
	frame, err := protocol.Decode(msg)
	if err != nil {
		s.fail(0, protocol.ErrorCodeFor(err))
		return protocol.Frame{}, false
	}
	return frame, true
}

// handleHello answers the client's first frame with a Welcome.
func (s *session) handleHello(frame protocol.Frame) bool {
	hello, err := protocol.DecodeBody[protocol.Hello](frame, protocol.TypeHello)
	if err != nil {
		s.fail(frame.ID, requestErrorCode(err))
		return false
	}
	version, err := protocol.Negotiate(hello)
	if err != nil {
		s.fail(frame.ID, protocol.ErrCodeUnsupportedVersion)
		return false
	}
	limits := s.srv.cfg.Limits
	welcome := protocol.Welcome{
		Version:      version,
		MaxFrameSize: uint32(limits.MaxFrameSize),
		PingInterval: uint32(limits.PingInterval.Std() / time.Second),
	}
	return s.send(protocol.TypeWelcome, frame.ID, welcome)
}

// handlePing answers a Ping with a Pong carrying the same ID and nonce. Any
// other frame type is a protocol violation once the session is established;
// this includes a second Hello.
func (s *session) handlePing(frame protocol.Frame) bool {
	ping, err := protocol.DecodeBody[protocol.Ping](frame, protocol.TypePing)
	if err != nil {
		s.fail(frame.ID, requestErrorCode(err))
		return false
	}
	return s.send(protocol.TypePong, frame.ID, protocol.Pong{Nonce: ping.Nonce})
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

// send writes one frame and terminates the session if that fails.
func (s *session) send(frameType protocol.FrameType, id uint64, body any) bool {
	if err := s.writeFrame(frameType, id, body); err != nil {
		s.terminate(reasonWriteFailed, websocket.StatusInternalError, closeTextInternal)
		return false
	}
	return true
}

// writeFrame encodes and writes one frame within writeTimeout.
func (s *session) writeFrame(frameType protocol.FrameType, id uint64, body any) error {
	frame, err := newTypedFrame(frameType, id, body)
	if err != nil {
		return err
	}
	encoded, err := protocol.Encode(frame)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	return s.conn.Write(ctx, websocket.MessageBinary, encoded)
}

// newTypedFrame calls protocol.NewFrame with the concrete body type, so the
// protocol package can check that body and frame type match.
func newTypedFrame(frameType protocol.FrameType, id uint64, body any) (protocol.Frame, error) {
	switch b := body.(type) {
	case protocol.Welcome:
		return protocol.NewFrame(frameType, id, b)
	case protocol.Pong:
		return protocol.NewFrame(frameType, id, b)
	case protocol.ErrorBody:
		return protocol.NewFrame(frameType, id, b)
	default:
		return protocol.Frame{}, errors.New("server: unsupported frame body")
	}
}

// fail sends an Error frame with a fixed message and closes the session
// with a policy violation. A failure to send the Error frame is ignored,
// since the connection is being closed anyway.
func (s *session) fail(id uint64, code protocol.ErrorCode) {
	if !code.Valid() {
		code = protocol.ErrCodeInternal
	}
	_ = s.writeFrame(protocol.TypeError, id, protocol.ErrorBody{Code: code, Message: errorMessages[code]})
	s.terminate(errorReasons[code], websocket.StatusPolicyViolation, closeTextProtocolError)
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
		_ = s.conn.Close(code, text)
	})
}
