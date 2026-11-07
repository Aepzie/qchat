package server

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/coder/websocket"

	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/store/serverdb"
)

// Relay defaults that are not part of the configuration file.
const (
	// challengeTTL is how long an authentication challenge stays valid.
	challengeTTL = 30 * time.Second
	// dbTimeout bounds every database operation done for a request.
	dbTimeout = 5 * time.Second
	// authBurst and authInterval define the per-session token bucket for
	// Register and AuthBegin: a burst of 5, then one every 12 seconds (5 per
	// minute). Invite codes carry 128 bits, so this is DoS protection for
	// the signature checks and database writes rather than a guard against
	// guessing.
	authBurst    = 5
	authInterval = 12 * time.Second
)

// handleRegister verifies and stores an identity bundle. It is allowed
// before and after authentication; a client rotates its keys by
// registering a bundle with a higher serial.
func (s *session) handleRegister(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.Register](frame, protocol.TypeRegister)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if !s.authLimiter.Allow() {
		return s.reject(frame.ID, protocol.ErrCodeRateLimited)
	}
	bundle, err := identity.ParseBundle(req.Bundle)
	if err != nil {
		return s.reject(frame.ID, protocol.ErrCodeBadRequest)
	}
	if code, ok := s.srv.storeIdentity(bundle, req.Invite); !ok {
		return s.reject(frame.ID, code)
	}
	return respond(s, protocol.TypeRegistered, frame.ID, protocol.Registered{})
}

// handleAuthBegin issues a fresh challenge for a registered identity. A new
// AuthBegin replaces any challenge still outstanding, so a session holds at
// most one.
func (s *session) handleAuthBegin(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.AuthBegin](frame, protocol.TypeAuthBegin)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if s.authenticated {
		return s.fail(frame.ID, protocol.ErrCodeBadRequest)
	}
	s.challenge = nil
	if !s.authLimiter.Allow() {
		return s.reject(frame.ID, protocol.ErrCodeRateLimited)
	}
	bundle, code, ok := s.srv.lookupBundle(identity.ID(req.ID))
	if !ok {
		return s.reject(frame.ID, code)
	}
	nonce := make([]byte, protocol.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return s.reject(frame.ID, protocol.ErrCodeInternal)
	}
	s.challenge = &challenge{bundle: bundle, nonce: nonce, expires: s.srv.now().Add(s.srv.challengeTTL)}
	return respond(s, protocol.TypeAuthChallenge, frame.ID, protocol.AuthChallenge{Nonce: nonce})
}

// handleAuthProof checks the answer to the outstanding challenge. A missing,
// expired or wrong proof closes the session; the challenge is consumed in
// every case, so each nonce can be tried once.
func (s *session) handleAuthProof(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.AuthProof](frame, protocol.TypeAuthProof)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if s.authenticated {
		return s.fail(frame.ID, protocol.ErrCodeBadRequest)
	}
	pending := s.challenge
	s.challenge = nil
	if pending == nil || s.srv.now().After(pending.expires) {
		return s.fail(frame.ID, protocol.ErrCodeUnauthorized)
	}
	if err := identity.VerifyAuth(pending.bundle, s.srv.fingerprint, pending.nonce, s.binding, req.Sig); err != nil {
		return s.fail(frame.ID, protocol.ErrCodeUnauthorized)
	}
	if !s.srv.route(s, pending.bundle.ID) {
		return s.failTooManySessions(frame.ID)
	}
	return respond(s, protocol.TypeAuthOK, frame.ID, protocol.AuthOK{})
}

// failTooManySessions answers an AuthProof for an identity that already has
// limits.max_sessions_per_identity sessions with a fatal RateLimited error.
// The session stays unauthenticated.
func (s *session) failTooManySessions(id uint64) bool {
	s.queueError(id, protocol.ErrCodeRateLimited)
	s.pendingClose = &closeRequest{reason: reasonTooManySessions, status: websocket.StatusPolicyViolation, text: closeTextProtocolError}
	return false
}

// handleKeyRequest returns the stored bundle of an identity.
func (s *session) handleKeyRequest(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.KeyRequest](frame, protocol.TypeKeyRequest)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if !s.authenticated {
		return s.reject(frame.ID, protocol.ErrCodeUnauthorized)
	}
	raw, code, ok := s.srv.loadBundle(identity.ID(req.ID))
	if !ok {
		return s.reject(frame.ID, code)
	}
	return respond(s, protocol.TypeKeyResponse, frame.ID, protocol.KeyResponse{Bundle: raw})
}

// handleSend routes a payload to every live connection of a registered
// recipient. The payload is never stored.
//
// The SendResult is a presence oracle: any authenticated user learns from
// it whether a registered ID currently has a live session, without knowing
// anything else about it. This is accepted until Phase 3, when the relay
// queues messages for offline recipients and the result no longer tells the
// two cases apart.
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
	if _, code, ok := s.srv.loadBundle(to); !ok {
		return s.reject(frame.ID, code)
	}
	deliver, err := encodeFrame(protocol.TypeDeliver, 0, protocol.Deliver{From: s.id[:], Payload: req.Payload})
	if err != nil {
		return s.reject(frame.ID, protocol.ErrCodeInternal)
	}
	status := protocol.SendRecipientOffline
	if s.srv.deliver(to, deliver) {
		status = protocol.SendDelivered
	}
	return respond(s, protocol.TypeSendResult, frame.ID, protocol.SendResult{Status: status})
}

// storeIdentity stores a verified bundle according to the registration
// mode. On failure it returns the error code to answer with.
func (s *Server) storeIdentity(bundle *identity.Bundle, invite string) (protocol.ErrorCode, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	var err error
	if s.cfg.Registration == RegistrationOpen {
		_, err = s.db.PutIdentity(ctx, bundle.ID, bundle.Raw, bundle.Serial)
	} else {
		_, err = s.db.RedeemInviteAndPut(ctx, invite, bundle.ID, bundle.Raw, bundle.Serial, s.now())
	}
	switch {
	case err == nil:
		return 0, true
	case errors.Is(err, serverdb.ErrInviteInvalid):
		return protocol.ErrCodeRegistrationDenied, false
	case errors.Is(err, serverdb.ErrConflict):
		return protocol.ErrCodeConflict, false
	default:
		s.logger.Error("cannot store identity", "err", err)
		return protocol.ErrCodeInternal, false
	}
}

// loadBundle returns the stored encoding of the bundle of id. On failure it
// returns the error code to answer with.
func (s *Server) loadBundle(id identity.ID) ([]byte, protocol.ErrorCode, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	raw, _, err := s.db.GetBundle(ctx, id)
	switch {
	case err == nil:
		return raw, 0, true
	case errors.Is(err, serverdb.ErrNotFound):
		return nil, protocol.ErrCodeNotFound, false
	default:
		s.logger.Error("cannot read identity", "err", err)
		return nil, protocol.ErrCodeInternal, false
	}
}

// lookupBundle loads and parses the stored bundle of id. Stored bundles
// were verified on registration, so a parse failure means the database is
// damaged.
func (s *Server) lookupBundle(id identity.ID) (*identity.Bundle, protocol.ErrorCode, bool) {
	raw, code, ok := s.loadBundle(id)
	if !ok {
		return nil, code, false
	}
	bundle, err := identity.ParseBundle(raw)
	if err != nil || bundle.ID != id {
		s.logger.Error("stored identity bundle does not verify")
		return nil, protocol.ErrCodeInternal, false
	}
	return bundle, 0, true
}

// route authenticates sess as id and makes it reachable under that ID. It
// reports false, leaving sess unauthenticated, if id already has
// limits.max_sessions_per_identity sessions.
func (s *Server) route(sess *session, id identity.ID) bool {
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	set := s.routes[id]
	if len(set) >= s.cfg.Limits.MaxSessionsPerIdentity {
		return false
	}
	if set == nil {
		set = make(map[*session]struct{})
		s.routes[id] = set
	}
	set[sess] = struct{}{}
	sess.authenticated = true
	sess.id = id
	return true
}

// unroute removes a session from the routing table. It is a no-op for a
// session that never authenticated.
func (s *Server) unroute(sess *session) {
	if !sess.authenticated {
		return
	}
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	set := s.routes[sess.id]
	delete(set, sess)
	if len(set) == 0 {
		delete(s.routes, sess.id)
	}
}

// deliver offers an encoded Deliver frame to every live session of to,
// without waiting for any of them. It reports whether at least one session
// accepted it; a session whose queue or byte budget is full, or that finds
// the server-wide byte budget exhausted, misses the frame.
func (s *Server) deliver(to identity.ID, encoded []byte) bool {
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	delivered := false
	for sess := range s.routes[to] {
		if sess.offer(encoded) {
			delivered = true
		}
	}
	return delivered
}
