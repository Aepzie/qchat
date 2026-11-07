package server

import (
	"context"
	"errors"

	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/store/serverdb"
)

// handleSendMulti stores one copy of a payload for every recipient and
// pushes each copy to the recipient's live connections as an ordinary
// Deliver with its own queue ID.
//
// The request counts as one send per recipient: it spends one frame token
// per recipient, and each copy counts toward its recipient's queue limits.
// Either every copy is stored or none is. An unknown recipient is answered
// with NotFound and a full queue with QueueFull, without saying which
// recipient caused it; the sender itself is not a valid recipient.
func (s *session) handleSendMulti(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.SendMulti](frame, protocol.TypeSendMulti)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if !s.authenticated {
		return s.reject(frame.ID, protocol.ErrCodeUnauthorized)
	}
	if len(req.Payload) > s.srv.cfg.Limits.MaxMessageSize {
		return s.reject(frame.ID, protocol.ErrCodeTooLarge)
	}
	recipients := make([][32]byte, len(req.To))
	for i, to := range req.To {
		recipients[i] = [32]byte(to)
		if identity.ID(recipients[i]) == s.id {
			return s.reject(frame.ID, protocol.ErrCodeBadRequest)
		}
	}
	if !s.spendFrameTokens(len(recipients) - 1) {
		return s.reject(frame.ID, protocol.ErrCodeRateLimited)
	}
	qids, code, ok := s.srv.storeMulti(recipients, s.id, req.Payload)
	if !ok {
		return s.reject(frame.ID, code)
	}
	for i, to := range recipients {
		deliver, err := encodeFrame(protocol.TypeDeliver, 0, protocol.Deliver{From: s.id[:], Payload: req.Payload, QueueID: qids[i]})
		if err != nil {
			s.srv.logger.Error("cannot encode delivery")
			continue
		}
		s.srv.deliver(identity.ID(to), qids[i], deliver)
	}
	return respond(s, protocol.TypeSendResult, frame.ID, protocol.SendResult{Status: protocol.SendAccepted})
}

// spendFrameTokens takes n additional tokens from the session's frame
// limiter, waiting for them at the sustained rate for at most
// s.srv.multiSendWait, and reports whether it got them. Tokens are taken in
// portions no larger than the burst, so requests costing more than the
// burst still succeed at the sustained rate. It gives up at once if the
// wait would exceed the bound or the session is closed; portions already
// taken stay spent.
func (s *session) spendFrameTokens(n int) bool {
	if n <= 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.srv.multiSendWait)
	defer cancel()
	go func() {
		select {
		case <-s.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	burst := max(s.limiter.Burst(), 1)
	for n > 0 {
		portion := min(n, burst)
		if err := s.limiter.WaitN(ctx, portion); err != nil {
			return false
		}
		n -= portion
	}
	return true
}

// storeMulti stores payload from sender for every recipient until
// undelivered_ttl expires and returns the queue IDs in the order of
// recipients. On failure it returns the error code to answer with.
func (s *Server) storeMulti(recipients [][32]byte, sender identity.ID, payload []byte) ([]uint64, protocol.ErrorCode, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	now := s.now()
	limits := serverdb.QueueLimits{MaxMessages: s.cfg.Limits.MaxQueuedMessages, MaxBytes: s.cfg.Limits.MaxQueuedBytes}
	qids, err := s.db.EnqueueMulti(ctx, recipients, sender, payload, now, now.Add(s.cfg.UndeliveredTTL.Std()), limits)
	switch {
	case err == nil:
		return qids, 0, true
	case errors.Is(err, serverdb.ErrNotFound):
		return nil, protocol.ErrCodeNotFound, false
	case errors.Is(err, serverdb.ErrQueueFull):
		return nil, protocol.ErrCodeQueueFull, false
	default:
		s.logger.Error("cannot store message", "err", err)
		return nil, protocol.ErrCodeInternal, false
	}
}
