package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/store/serverdb"
)

// sessionMode records which kind of requests a session has committed to.
// A session starts undecided; Register, AuthBegin or AuthProof make it
// identified and a sealed send makes it anonymous, and it never changes
// again, so the relay never sees a sealed message and an identity on the
// same connection.
type sessionMode uint8

const (
	modeUndecided sessionMode = iota
	modeIdentified
	modeAnonymous
)

// Parameters of the per-IP sealed sender buckets.
const (
	// ipBucketSweepInterval is how often buckets that have refilled
	// completely are dropped.
	ipBucketSweepInterval = time.Minute
	// maxIPBuckets bounds the number of per-IP buckets held at once. When
	// it is reached and no bucket can be dropped, sealed sends from new
	// addresses are refused with RateLimited.
	maxIPBuckets = 1 << 16
)

// dummyVerifier stands in for the verifier of a recipient that has none,
// so that every sealed send runs the same comparison. A match against it
// never grants access.
var dummyVerifier [protocol.AccessVerifierSize]byte

// enterMode commits the session to mode and reports whether that is
// consistent with what it did before.
func (s *session) enterMode(mode sessionMode) bool {
	if s.mode != modeUndecided && s.mode != mode {
		return false
	}
	s.mode = mode
	return true
}

// handleSetAccessKey stores the verifier of the authenticated identity's
// access key. It shares the authentication token bucket, since clients set
// their key rarely.
func (s *session) handleSetAccessKey(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.SetAccessKey](frame, protocol.TypeSetAccessKey)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if !s.authenticated {
		return s.reject(frame.ID, protocol.ErrCodeUnauthorized)
	}
	if !s.authLimiter.Allow() {
		return s.reject(frame.ID, protocol.ErrCodeRateLimited)
	}
	key := serverdb.AccessKey{Verifier: [protocol.AccessVerifierSize]byte(req.Verifier), AllowUnidentified: req.AllowUnidentified}
	if code, ok := s.srv.storeAccessKey(s.id, key); !ok {
		return s.reject(frame.ID, code)
	}
	return respond(s, protocol.TypeAccessKeySet, frame.ID, protocol.AccessKeySet{})
}

// handleSealedSend stores a payload without a sender for a recipient whose
// access the request proves, and pushes it to the recipient's live
// connections with the zero sender. An unknown recipient and a wrong proof
// are both answered NotFound.
func (s *session) handleSealedSend(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.SealedSend](frame, protocol.TypeSealedSend)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if !s.enterMode(modeAnonymous) {
		return s.fail(frame.ID, protocol.ErrCodeBadRequest)
	}
	if len(req.Payload) > s.srv.cfg.Limits.MaxMessageSize {
		return s.reject(frame.ID, protocol.ErrCodeTooLarge)
	}
	if !s.spendSealed(1) {
		return s.reject(frame.ID, protocol.ErrCodeRateLimited)
	}
	to := identity.ID(req.To)
	allowed, ok := s.srv.sealedAccess([]protocol.SealedRecipient{{To: req.To, AccessProof: req.AccessProof}})
	if !ok {
		return s.reject(frame.ID, protocol.ErrCodeInternal)
	}
	if !allowed[0] {
		return s.reject(frame.ID, protocol.ErrCodeNotFound)
	}
	outcomes, code, ok := s.srv.storeSealed([][32]byte{to}, req.Payload)
	if !ok {
		return s.reject(frame.ID, code)
	}
	if outcomes[0].Err != nil {
		return s.reject(frame.ID, storeErrorCode(outcomes[0].Err))
	}
	s.srv.deliverStored(to, outcomes[0].QID, identity.ID(protocol.SealedFrom), req.Payload)
	return respond(s, protocol.TypeSendResult, frame.ID, protocol.SendResult{Status: protocol.SendAccepted})
}

// handleSealedSendMulti stores one payload without a sender for every
// recipient whose access the request proves and whose queue has room, and
// pushes each copy as a Deliver with the zero sender. Recipients with an
// unknown ID or a wrong proof are listed as NotFound alike.
func (s *session) handleSealedSendMulti(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.SealedSendMulti](frame, protocol.TypeSealedSendMulti)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if !s.enterMode(modeAnonymous) {
		return s.fail(frame.ID, protocol.ErrCodeBadRequest)
	}
	if len(req.Payload) > s.srv.cfg.Limits.MaxMessageSize || len(req.Payload)*len(req.Entries) > maxMultiSendBytes {
		return s.reject(frame.ID, protocol.ErrCodeTooLarge)
	}
	if !s.spendSealed(len(req.Entries)) {
		return s.reject(frame.ID, protocol.ErrCodeRateLimited)
	}
	allowed, ok := s.srv.sealedAccess(req.Entries)
	if !ok {
		return s.reject(frame.ID, protocol.ErrCodeInternal)
	}
	accepted := make([]int, 0, len(req.Entries))
	recipients := make([][32]byte, 0, len(req.Entries))
	for i, entry := range req.Entries {
		if allowed[i] {
			accepted = append(accepted, i)
			recipients = append(recipients, [32]byte(entry.To))
		}
	}
	reasons := make([]protocol.ErrorCode, len(req.Entries))
	for i := range reasons {
		reasons[i] = protocol.ErrCodeNotFound
	}
	if len(recipients) > 0 {
		outcomes, code, ok := s.srv.storeSealed(recipients, req.Payload)
		if !ok {
			return s.reject(frame.ID, code)
		}
		for j, outcome := range outcomes {
			i := accepted[j]
			if outcome.Err != nil {
				reasons[i] = storeErrorCode(outcome.Err)
				continue
			}
			reasons[i] = 0
			s.srv.deliverStored(identity.ID(recipients[j]), outcome.QID, identity.ID(protocol.SealedFrom), req.Payload)
		}
	}
	result := protocol.SendMultiResult{Status: protocol.SendAccepted}
	for i, reason := range reasons {
		if reason != 0 {
			result.Failed = append(result.Failed, req.Entries[i].To)
			result.Reasons = append(result.Reasons, reason)
		}
	}
	return respond(s, protocol.TypeSendMultiResult, frame.ID, result)
}

// spendSealed takes n tokens from the session's sealed recipient budget
// and from the budget of the client's address, waiting briefly like
// spendRecipients, and reports whether it got them from both.
func (s *session) spendSealed(n int) bool {
	now := s.srv.now()
	return s.await(now, s.sealedLimiter.ReserveN(now, n), s.srv.sealedIP.reserve(s.ipKey, n, now))
}

// sealedAccess reports, for every entry, whether its proof grants access to
// its recipient: the recipient is a stored identity with an access key,
// and either it allows unidentified senders or the proof equals its
// verifier. Every entry costs one lookup and one constant-time comparison
// whatever the outcome, so the answer is the only thing that differs
// between an unknown recipient and a wrong proof. ok is false after a
// database failure.
func (s *Server) sealedAccess(entries []protocol.SealedRecipient) (allowed []bool, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	allowed = make([]bool, len(entries))
	for i, entry := range entries {
		key, err := s.db.GetAccessKey(ctx, [32]byte(entry.To))
		found := err == nil
		if err != nil && !errors.Is(err, serverdb.ErrNotFound) {
			s.logger.Error("cannot read access key", "err", err)
			return nil, false
		}
		if !found {
			key = serverdb.AccessKey{Verifier: dummyVerifier}
		}
		match := subtle.ConstantTimeCompare(key.Verifier[:], entry.AccessProof) == 1
		allowed[i] = found && (match || key.AllowUnidentified)
	}
	return allowed, true
}

// storeAccessKey stores the access setting of id. On failure it returns the
// error code to answer with.
func (s *Server) storeAccessKey(id identity.ID, key serverdb.AccessKey) (protocol.ErrorCode, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	err := s.db.SetAccessKey(ctx, id, key)
	switch {
	case err == nil:
		return 0, true
	case errors.Is(err, serverdb.ErrNotFound):
		return protocol.ErrCodeNotFound, false
	default:
		s.logger.Error("cannot store access key", "err", err)
		return protocol.ErrCodeInternal, false
	}
}

// storeSealed stores payload without a sender for every recipient that can
// take it until undelivered_ttl expires and returns one outcome per
// recipient. On a failure of the whole request it returns the error code to
// answer with.
func (s *Server) storeSealed(recipients [][32]byte, payload []byte) ([]serverdb.Enqueued, protocol.ErrorCode, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	now := s.now()
	limits := serverdb.QueueLimits{MaxMessages: s.cfg.Limits.MaxQueuedMessages, MaxBytes: s.cfg.Limits.MaxQueuedBytes}
	outcomes, err := s.db.EnqueueSealedMulti(ctx, recipients, payload, now, now.Add(s.cfg.UndeliveredTTL.Std()), limits)
	if err != nil {
		s.logger.Error("cannot store message", "err", err)
		return nil, protocol.ErrCodeInternal, false
	}
	return outcomes, 0, true
}

// ipBuckets holds one token bucket per client address for sealed sends.
//
// Privacy: addresses are held in memory only, and only while their bucket
// is not full again; a full bucket is indistinguishable from a new one, so
// dropping it changes nothing. Addresses are never logged or persisted.
type ipBuckets struct {
	mu        sync.Mutex
	limit     rate.Limit
	burst     int
	maxKeys   int
	buckets   map[netip.Addr]*rate.Limiter
	lastSweep time.Time
}

func newIPBuckets(perMinute, burst, maxKeys int) *ipBuckets {
	return &ipBuckets{
		limit:   rate.Limit(float64(perMinute) / 60),
		burst:   burst,
		maxKeys: maxKeys,
		buckets: make(map[netip.Addr]*rate.Limiter),
	}
}

// reserve reserves n tokens at now from the bucket of key. It returns nil
// when no bucket can be created because maxKeys addresses are held.
func (b *ipBuckets) reserve(key netip.Addr, n int, now time.Time) *rate.Reservation {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.lastSweep) >= ipBucketSweepInterval {
		b.sweep(now)
	}
	bucket, ok := b.buckets[key]
	if !ok {
		if len(b.buckets) >= b.maxKeys {
			b.sweep(now)
		}
		if len(b.buckets) >= b.maxKeys {
			return nil
		}
		bucket = rate.NewLimiter(b.limit, b.burst)
		b.buckets[key] = bucket
	}
	return bucket.ReserveN(now, n)
}

// sweep drops every bucket that is full again at now.
func (b *ipBuckets) sweep(now time.Time) {
	for key, bucket := range b.buckets {
		if bucket.TokensAt(now) >= float64(b.burst) {
			delete(b.buckets, key)
		}
	}
	b.lastSweep = now
}

// size returns the number of buckets held.
func (b *ipBuckets) size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buckets)
}
