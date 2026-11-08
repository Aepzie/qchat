package server

import (
	"context"
	"errors"
	"time"

	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/protocol"
	"github.com/Aepzie/qchat/internal/store/serverdb"
)

// Offline delivery parameters that are not part of the configuration file.
const (
	// backlogWindow is the largest number of stored messages a session
	// pushes after authentication before the client acknowledges some of
	// them. Each Ack lets the session push the next stored message.
	backlogWindow = 32
	// pruneInterval is how often expired messages are deleted.
	pruneInterval = 10 * time.Minute
	// multiSendMaxWait bounds how long a session waits for the recipient
	// budget a SendMulti needs. The wait is also capped at half the idle
	// timeout.
	multiSendMaxWait = 10 * time.Second
	// maxMultiSendBytes bounds the payload size times the number of
	// recipients of one SendMulti, which is what the request costs in
	// recipients' queue limits and in Deliver frames.
	maxMultiSendBytes = 64 << 20
)

// backlog tracks the stored messages a session pushes after
// authentication. Only the session's reader touches it.
type backlog struct {
	// cursor is the highest queue ID pushed so far.
	cursor uint64
	// inFlight holds the queue IDs pushed and not yet acknowledged.
	inFlight map[uint64]struct{}
	// drained is set once every stored message older than the first live
	// delivery has been pushed, or after a database failure.
	drained bool
}

// handleSend stores a payload for a registered recipient and pushes it to
// every live connection of the recipient. The answer is SendAccepted
// whether or not the recipient is online, so it reveals nothing about
// presence.
func (s *session) handleSend(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.Send](frame, protocol.TypeSend)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if !s.authenticated {
		return s.reject(frame.ID, protocol.ErrCodeUnauthorized)
	}
	if len(req.Payload) > s.srv.cfg.Limits.MaxMessageSize {
		return s.reject(frame.ID, protocol.ErrCodeTooLarge)
	}
	to := identity.ID(req.To)
	if to == s.id {
		return s.reject(frame.ID, protocol.ErrCodeBadRequest)
	}
	qid, code, ok := s.srv.storeMessage(to, s.id, req.Payload)
	if !ok {
		return s.reject(frame.ID, code)
	}
	deliver, err := encodeFrame(protocol.TypeDeliver, 0, protocol.Deliver{From: s.id[:], Payload: req.Payload, QueueID: qid})
	if err != nil {
		return s.reject(frame.ID, protocol.ErrCodeInternal)
	}
	s.srv.deliver(to, qid, deliver)
	return respond(s, protocol.TypeSendResult, frame.ID, protocol.SendResult{Status: protocol.SendAccepted})
}

// handleAck deletes an acknowledged message of the session's identity and
// pushes the next stored message, if any. Ack has no response; acknowledging
// a message that does not exist, or belongs to someone else, is silently
// ignored.
func (s *session) handleAck(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.Ack](frame, protocol.TypeAck)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if !s.authenticated {
		return s.reject(frame.ID, protocol.ErrCodeUnauthorized)
	}
	s.srv.ackMessage(s.id, req.QueueID)
	delete(s.backlog.inFlight, req.QueueID)
	return s.pumpBacklog()
}

// pumpBacklog pushes stored messages of the session's identity, in queue
// order, until backlogWindow of them await acknowledgement or none is left.
// Messages from the first live delivery onwards are skipped: they were
// pushed when they arrived. It reports whether the session continues.
func (s *session) pumpBacklog() bool {
	for !s.backlog.drained && len(s.backlog.inFlight) < backlogWindow {
		want := backlogWindow - len(s.backlog.inFlight)
		stored, ok := s.srv.queuedFor(s.id, s.backlog.cursor, want)
		if !ok {
			s.backlog.drained = true
			return true
		}
		if len(stored) < want {
			s.backlog.drained = true
		}
		for _, msg := range stored {
			if floor := s.liveFloor.Load(); floor != 0 && msg.QID >= floor {
				s.backlog.drained = true
				return true
			}
			if !s.pushStored(msg) {
				return false
			}
		}
	}
	return true
}

// pushStored queues one stored message for the writer, waiting for room
// like a response, and records it as awaiting acknowledgement.
func (s *session) pushStored(msg serverdb.Queued) bool {
	encoded, err := encodeFrame(protocol.TypeDeliver, 0, protocol.Deliver{From: msg.Sender[:], Payload: msg.Payload, QueueID: msg.QID})
	if err != nil {
		s.srv.logger.Error("cannot encode stored message")
		s.backlog.cursor = msg.QID
		return true
	}
	if !s.enqueue(encoded) {
		return false
	}
	s.backlog.cursor = msg.QID
	if s.backlog.inFlight == nil {
		s.backlog.inFlight = make(map[uint64]struct{})
	}
	s.backlog.inFlight[msg.QID] = struct{}{}
	return true
}

// noteLive records that the message qid was pushed to the session as it
// arrived. The lowest such queue ID bounds the backlog the session still
// has to push.
func (s *session) noteLive(qid uint64) {
	for {
		floor := s.liveFloor.Load()
		if floor != 0 && floor <= qid {
			return
		}
		if s.liveFloor.CompareAndSwap(floor, qid) {
			return
		}
	}
}

// deliver offers an encoded Deliver frame for the stored message qid to
// every live session of to, without waiting for any of them, and reports
// whether at least one session accepted it. A session whose queue or byte
// budget is full, or that finds the server-wide byte budget exhausted,
// misses the frame; the message stays stored and is pushed again after the
// recipient's next authentication.
func (s *Server) deliver(to identity.ID, qid uint64, encoded []byte) bool {
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	delivered := false
	for sess := range s.routes[to] {
		if sess.offer(encoded) {
			sess.noteLive(qid)
			delivered = true
		}
	}
	return delivered
}

// queueLimits returns the limits of the messages stored for one
// recipient. The sealed caps apply only to messages without a sender:
// sealed messages may take at most max_queued_sealed_messages rows and
// half of max_queued_bytes.
func (s *Server) queueLimits() serverdb.QueueLimits {
	limits := s.cfg.Limits
	return serverdb.QueueLimits{
		MaxMessages:       limits.MaxQueuedMessages,
		MaxBytes:          limits.MaxQueuedBytes,
		MaxSealedMessages: limits.MaxQueuedSealedMessages,
		MaxSealedBytes:    limits.MaxQueuedBytes / 2,
	}
}

// queueExpiry returns when a message stored at now expires:
// undelivered_ttl later, rounded up to the next full hour. Rounding makes
// the stored expiry, which a copy of the database reveals, say only in
// which hour a message was stored, for sealed and identified messages
// alike.
func (s *Server) queueExpiry(now time.Time) time.Time {
	return roundUpToHour(now.Add(s.cfg.UndeliveredTTL.Std()))
}

// roundUpToHour returns the first full hour (UTC) at or after t.
func roundUpToHour(t time.Time) time.Time {
	rounded := t.Truncate(time.Hour)
	if rounded.Before(t) {
		rounded = rounded.Add(time.Hour)
	}
	return rounded
}

// storeMessage stores a payload for to until undelivered_ttl expires and
// returns its queue ID. On failure it returns the error code to answer
// with.
func (s *Server) storeMessage(to, from identity.ID, payload []byte) (uint64, protocol.ErrorCode, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	now := s.now()
	qid, err := s.db.Enqueue(ctx, to, from, payload, now, s.queueExpiry(now), s.queueLimits())
	switch {
	case err == nil:
		return qid, 0, true
	case errors.Is(err, serverdb.ErrNotFound):
		return 0, protocol.ErrCodeNotFound, false
	case errors.Is(err, serverdb.ErrQueueFull):
		return 0, protocol.ErrCodeQueueFull, false
	default:
		s.logger.Error("cannot store message", "err", err)
		return 0, protocol.ErrCodeInternal, false
	}
}

// queuedFor loads up to limit unexpired stored messages of id after the
// queue ID after. It reports false after a database failure.
func (s *Server) queuedFor(id identity.ID, after uint64, limit int) ([]serverdb.Queued, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	stored, err := s.db.QueuedFor(ctx, id, after, limit, s.now())
	if err != nil {
		s.logger.Error("cannot read stored messages", "err", err)
		return nil, false
	}
	return stored, true
}

// ackMessage deletes the stored message qid of id, if there is one.
func (s *Server) ackMessage(id identity.ID, qid uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	if err := s.db.Ack(ctx, id, qid); err != nil && !errors.Is(err, serverdb.ErrNotFound) {
		s.logger.Error("cannot delete acknowledged message", "err", err)
	}
}

// pruneLoop deletes expired messages at once and then every
// s.pruneInterval until ctx is cancelled, and closes done when it returns.
func (s *Server) pruneLoop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(s.pruneInterval)
	defer ticker.Stop()
	for {
		s.pruneQueue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pruneQueue deletes the messages that have expired by now.
func (s *Server) pruneQueue(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	if _, err := s.db.PruneQueue(ctx, s.now()); err != nil && ctx.Err() == nil {
		s.logger.Error("cannot delete expired messages", "err", err)
	}
}
