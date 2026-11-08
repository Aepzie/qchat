package server

import (
	"context"
	"errors"
	"time"

	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/prekey"
	"github.com/Aepzie/qchat/internal/protocol"
	"github.com/Aepzie/qchat/internal/store/serverdb"
)

// uploadBurst and uploadInterval define the per-session token bucket for
// PrekeyUpload: a burst of 10, then one per minute. An upload can carry
// 101 prekeys whose signatures must all be verified, while clients upload
// a few times a week, so the bucket bounds the verification work a session
// can cause without hindering normal use.
const (
	uploadBurst    = 10
	uploadInterval = time.Minute
)

// handlePrekeyUpload verifies the uploaded prekeys against the session
// identity's stored bundle, stores them and answers with the resulting
// PrekeyStatus. If any prekey fails to verify, nothing is stored.
func (s *session) handlePrekeyUpload(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.PrekeyUpload](frame, protocol.TypePrekeyUpload)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if !s.authenticated {
		return s.reject(frame.ID, protocol.ErrCodeUnauthorized)
	}
	if !s.uploadLimiter.Allow() {
		return s.reject(frame.ID, protocol.ErrCodeRateLimited)
	}
	owner, code, ok := s.srv.lookupBundle(s.id)
	if !ok {
		return s.reject(frame.ID, code)
	}
	var signed *prekey.SignedPrekey
	if req.SignedPrekey != nil {
		signed, err = prekey.ParseSignedPrekey(req.SignedPrekey, owner, s.srv.now())
		if err != nil {
			return s.reject(frame.ID, protocol.ErrCodeBadRequest)
		}
	}
	oneTime := make([]serverdb.OneTimePrekey, 0, len(req.OneTimePrekeys))
	for _, raw := range req.OneTimePrekeys {
		parsed, err := prekey.ParseOneTimePrekey(raw, owner)
		if err != nil {
			return s.reject(frame.ID, protocol.ErrCodeBadRequest)
		}
		oneTime = append(oneTime, serverdb.OneTimePrekey{KeyID: parsed.KeyID, Prekey: parsed.Raw})
	}
	status, code, ok := s.srv.storePrekeys(s.id, signed, oneTime)
	if !ok {
		return s.reject(frame.ID, code)
	}
	return respond(s, protocol.TypePrekeyStatus, frame.ID, status)
}

// handlePrekeyRequest hands out the prekey bundle of an identity, including
// at most once each of its one-time prekeys. A request with an access
// proof is an anonymous lookup (handleAnonymousPrekeyRequest).
func (s *session) handlePrekeyRequest(frame protocol.Frame) bool {
	req, err := protocol.DecodeBody[protocol.PrekeyRequest](frame, protocol.TypePrekeyRequest)
	if err != nil {
		return s.fail(frame.ID, requestErrorCode(err))
	}
	if req.AccessProof != nil {
		return s.handleAnonymousPrekeyRequest(frame, req)
	}
	if !s.authenticated {
		return s.reject(frame.ID, protocol.ErrCodeUnauthorized)
	}
	if !s.prekeyLimiter.Allow() {
		return s.reject(frame.ID, protocol.ErrCodeRateLimited)
	}
	response, code, ok := s.srv.takePrekeys(identity.ID(req.ID))
	if !ok {
		return s.reject(frame.ID, code)
	}
	return respond(s, protocol.TypePrekeyResponse, frame.ID, response)
}

// storePrekeys stores verified prekeys of id and returns the resulting
// status. On failure it returns the error code to answer with.
func (s *Server) storePrekeys(id identity.ID, signed *prekey.SignedPrekey, oneTime []serverdb.OneTimePrekey) (protocol.PrekeyStatus, protocol.ErrorCode, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	if signed != nil {
		if err := s.db.PutSignedPrekey(ctx, id, signed.KeyID, signed.Raw, signed.Expires); err != nil {
			return protocol.PrekeyStatus{}, s.prekeyErrorCode(err), false
		}
	}
	if len(oneTime) > 0 {
		if _, err := s.db.AddOneTimePrekeys(ctx, id, oneTime); err != nil {
			return protocol.PrekeyStatus{}, s.prekeyErrorCode(err), false
		}
	}
	stored, err := s.db.GetPrekeyStatus(ctx, id)
	if err != nil {
		return protocol.PrekeyStatus{}, s.prekeyErrorCode(err), false
	}
	status := protocol.PrekeyStatus{OneTimeRemaining: uint32(stored.OneTimeRemaining)} // #nosec G115 -- count is at most serverdb.MaxOneTimePrekeys (200)
	if !stored.SignedPrekeyExpires.IsZero() {
		status.SignedPrekeyExpires = max(stored.SignedPrekeyExpires.Unix(), 0)
	}
	return status, 0, true
}

// takePrekeys returns the prekey bundle of id, consuming one of its
// one-time prekeys if any is left. On failure it returns the error code to
// answer with.
func (s *Server) takePrekeys(id identity.ID) (protocol.PrekeyResponse, protocol.ErrorCode, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	bundle, signed, oneTime, err := s.db.TakePrekeys(ctx, id, s.now())
	if err != nil {
		return protocol.PrekeyResponse{}, s.prekeyErrorCode(err), false
	}
	return protocol.PrekeyResponse{Bundle: bundle, SignedPrekey: signed, OneTimePrekey: oneTime}, 0, true
}

// prekeyErrorCode maps a database error of a prekey operation to the code
// to answer with, logging unexpected failures.
func (s *Server) prekeyErrorCode(err error) protocol.ErrorCode {
	if errors.Is(err, serverdb.ErrNotFound) {
		return protocol.ErrCodeNotFound
	}
	s.logger.Error("cannot access prekeys", "err", err)
	return protocol.ErrCodeInternal
}
