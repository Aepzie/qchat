package server

import (
	"context"
	"errors"
	"time"

	"golang.org/x/time/rate"

	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/store/serverdb"
)

// handleSendMulti stores a payload once for every recipient that can take
// it and pushes each copy to the recipient's live connections as an
// ordinary Deliver with its own queue ID.
//
// The request spends one frame token like any other frame and one token
// per recipient from the session's recipient budget. Each copy counts
// toward its recipient's queue limits with the full payload size. An
// unknown recipient or a full queue does not block the others: the
// SendMultiResult lists the recipients the message was not stored for,
// with NotFound or QueueFull for each. The sender itself is not a valid
// recipient and makes the whole request fail.
func (s *session) handleSendMulti(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.SendMulti](frame, protocol.TypeSendMulti)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if !s.authenticated {
		return s.reject(frame.ID, protocol.ErrCodeUnauthorized)
	}
	if len(req.Payload) > s.srv.cfg.Limits.MaxMessageSize || len(req.Payload)*len(req.To) > maxMultiSendBytes {
		return s.reject(frame.ID, protocol.ErrCodeTooLarge)
	}
	recipients := make([][32]byte, len(req.To))
	for i, to := range req.To {
		recipients[i] = [32]byte(to)
		if identity.ID(recipients[i]) == s.id {
			return s.reject(frame.ID, protocol.ErrCodeBadRequest)
		}
	}
	if !s.spendRecipients(len(recipients)) {
		return s.reject(frame.ID, protocol.ErrCodeRateLimited)
	}
	outcomes, code, ok := s.srv.storeMulti(recipients, s.id, req.Payload)
	if !ok {
		return s.reject(frame.ID, code)
	}
	result := protocol.SendMultiResult{Status: protocol.SendAccepted}
	for i, outcome := range outcomes {
		if outcome.Err != nil {
			result.Failed = append(result.Failed, req.To[i])
			result.Reasons = append(result.Reasons, storeErrorCode(outcome.Err))
			continue
		}
		s.srv.deliverStored(identity.ID(recipients[i]), outcome.QID, s.id, req.Payload)
	}
	return respond(s, protocol.TypeSendMultiResult, frame.ID, result)
}

// spendRecipients takes n tokens from the session's recipient budget and
// reports whether it got them. If the budget lacks them, it waits for at
// most s.srv.multiSendWait; when the wait would be longer, or the session
// closes while waiting, it gives up without spending anything.
func (s *session) spendRecipients(n int) bool {
	now := s.srv.now()
	return s.await(now, s.multiLimiter.ReserveN(now, n))
}

// await waits until every reservation, made at now, may act and reports
// whether all of them were granted. If one of them is nil or cannot be
// granted, or the longest wait exceeds s.srv.multiSendWait, or the session
// closes while waiting, every reservation is cancelled and await reports
// false.
func (s *session) await(now time.Time, reservations ...*rate.Reservation) bool {
	cancel := func(at time.Time) {
		for _, r := range reservations {
			if r != nil {
				r.CancelAt(at)
			}
		}
	}
	var delay time.Duration
	for _, r := range reservations {
		if r == nil || !r.OK() {
			cancel(now)
			return false
		}
		delay = max(delay, r.DelayFrom(now))
	}
	if delay <= 0 {
		return true
	}
	if delay > s.srv.multiSendWait {
		cancel(now)
		return false
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-s.closed:
		cancel(s.srv.now())
		return false
	}
}

// storeMulti stores payload from sender for every recipient that can take
// it until undelivered_ttl expires and returns one outcome per recipient,
// in the order of recipients. On a failure of the whole request it returns
// the error code to answer with.
func (s *Server) storeMulti(recipients [][32]byte, sender identity.ID, payload []byte) ([]serverdb.Enqueued, protocol.ErrorCode, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	now := s.now()
	limits := serverdb.QueueLimits{MaxMessages: s.cfg.Limits.MaxQueuedMessages, MaxBytes: s.cfg.Limits.MaxQueuedBytes}
	outcomes, err := s.db.EnqueueMulti(ctx, recipients, sender, payload, now, now.Add(s.cfg.UndeliveredTTL.Std()), limits)
	if err != nil {
		s.logger.Error("cannot store message", "err", err)
		return nil, protocol.ErrCodeInternal, false
	}
	return outcomes, 0, true
}

// storeErrorCode maps the reason a message was not stored for one
// recipient to the error code reported for it.
func storeErrorCode(err error) protocol.ErrorCode {
	switch {
	case errors.Is(err, serverdb.ErrNotFound):
		return protocol.ErrCodeNotFound
	case errors.Is(err, serverdb.ErrQueueFull):
		return protocol.ErrCodeQueueFull
	default:
		return protocol.ErrCodeInternal
	}
}

// deliverStored pushes the stored message qid from sender to every live
// session of to. The Deliver frame is encoded only if to has a live
// session, so a request for many offline recipients costs no encoding.
func (s *Server) deliverStored(to identity.ID, qid uint64, sender identity.ID, payload []byte) {
	if !s.isRouted(to) {
		return
	}
	encoded, err := encodeFrame(protocol.TypeDeliver, 0, protocol.Deliver{From: sender[:], Payload: payload, QueueID: qid})
	if err != nil {
		s.logger.Error("cannot encode delivery")
		return
	}
	s.deliver(to, qid, encoded)
}

// isRouted reports whether id has at least one live authenticated session.
func (s *Server) isRouted(id identity.ID) bool {
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	return len(s.routes[id]) > 0
}
