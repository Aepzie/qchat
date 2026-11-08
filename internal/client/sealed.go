package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/Aepzie/qchat/internal/protocol"
)

// isolationTokenSize is the number of random bytes in an isolation token.
const isolationTokenSize = 16

// NewIsolationToken returns a fresh random token, 32 hexadecimal digits,
// for the isolation argument of transport.SOCKS5Dialer. Tor puts streams
// with different tokens on different circuits, so giving the anonymous
// Session a token of its own keeps its connections off the authenticated
// Session's circuit. A Session reuses its dialer, and thus its token, for
// every reconnect; that is why an anonymous Session does not reconnect
// unless Options.AnonymousReconnect is set, and each new anonymous Session
// should get a new token.
func NewIsolationToken() (string, error) {
	var token [isolationTokenSize]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("client: isolation token: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}

// SetAccessKey uploads the verifier of the local identity's access key
// (sealed.AccessKey.Verifier), replacing the one the relay held. With
// allowUnidentified, anyone may send sealed messages to the identity. It
// needs an authenticated session; an Error reply is returned as a
// *RemoteError.
func (s *Session) SetAccessKey(ctx context.Context, verifier [protocol.AccessVerifierSize]byte, allowUnidentified bool) error {
	_, err := s.Request(ctx, protocol.TypeSetAccessKey, protocol.SetAccessKey{Verifier: verifier[:], AllowUnidentified: allowUnidentified})
	return err
}

// SealedSend asks the relay to store payload for to without naming the
// sender, proving access with proof, the verifier of to's access key. It
// needs an anonymous session (Options.Anonymous). It returns nil once the
// relay accepted the message; a *RemoteError with ErrCodeNotFound means
// that to is unknown or the proof is wrong, which the relay does not
// distinguish.
func (s *Session) SealedSend(ctx context.Context, to [protocol.IDSize]byte, proof [protocol.AccessVerifierSize]byte, payload []byte) error {
	resp, err := s.Request(ctx, protocol.TypeSealedSend, protocol.SealedSend{To: to[:], AccessProof: proof[:], Payload: payload})
	if err != nil {
		return err
	}
	result, err := protocol.DecodeBody[protocol.SendResult](resp, protocol.TypeSendResult)
	if err != nil {
		return fmt.Errorf("%w: invalid SendResult: %w", ErrProtocolViolation, err)
	}
	if result.Status != protocol.SendAccepted {
		return fmt.Errorf("%w: SealedSend answered %v", ErrProtocolViolation, result.Status)
	}
	return nil
}

// AnonKeyRequest fetches the identity bundle of id on an anonymous
// session, proving access with proof, the verifier of id's access key, so
// that the relay does not learn who looks the bundle up. It returns the
// bundle exactly as the relay sent it: the caller must verify it and check
// that its ID is id, as for any KeyResponse. A *RemoteError with
// ErrCodeNotFound means that id is unknown or the proof is wrong, which
// the relay does not distinguish.
func (s *Session) AnonKeyRequest(ctx context.Context, id [protocol.IDSize]byte, proof [protocol.AccessVerifierSize]byte) ([]byte, error) {
	resp, err := s.Request(ctx, protocol.TypeKeyRequest, protocol.KeyRequest{ID: id[:], AccessProof: proof[:]})
	if err != nil {
		return nil, err
	}
	body, err := protocol.DecodeBody[protocol.KeyResponse](resp, protocol.TypeKeyResponse)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid KeyResponse: %w", ErrProtocolViolation, err)
	}
	return body.Bundle, nil
}

// AnonPrekeyRequest fetches the prekey bundle of id on an anonymous
// session, proving access with proof, and consumes one of id's one-time
// prekeys at the relay. The caller must verify the bundle and both
// prekeys, as for any PrekeyResponse. A *RemoteError with ErrCodeNotFound
// means that id is unknown, has no signed prekey or the proof is wrong.
func (s *Session) AnonPrekeyRequest(ctx context.Context, id [protocol.IDSize]byte, proof [protocol.AccessVerifierSize]byte) (protocol.PrekeyResponse, error) {
	resp, err := s.Request(ctx, protocol.TypePrekeyRequest, protocol.PrekeyRequest{ID: id[:], AccessProof: proof[:]})
	if err != nil {
		return protocol.PrekeyResponse{}, err
	}
	body, err := protocol.DecodeBody[protocol.PrekeyResponse](resp, protocol.TypePrekeyResponse)
	if err != nil {
		return protocol.PrekeyResponse{}, fmt.Errorf("%w: invalid PrekeyResponse: %w", ErrProtocolViolation, err)
	}
	return body, nil
}

// SealedSendMulti asks the relay to store one payload for every entry
// without naming the sender, as SealedSend does for one recipient. It
// needs an anonymous session. The result lists the entries the message was
// not stored for: NotFound for an unknown recipient or a wrong proof alike,
// QueueFull for a full queue. Every ID it lists is one of the request's.
func (s *Session) SealedSendMulti(ctx context.Context, entries []protocol.SealedRecipient, payload []byte) (protocol.SendMultiResult, error) {
	resp, err := s.Request(ctx, protocol.TypeSealedSendMulti, protocol.SealedSendMulti{Entries: entries, Payload: payload})
	if err != nil {
		return protocol.SendMultiResult{}, err
	}
	result, err := protocol.DecodeBody[protocol.SendMultiResult](resp, protocol.TypeSendMultiResult)
	if err != nil {
		return protocol.SendMultiResult{}, fmt.Errorf("%w: invalid SendMultiResult: %w", ErrProtocolViolation, err)
	}
	requested := make(map[[protocol.IDSize]byte]struct{}, len(entries))
	for _, entry := range entries {
		requested[[protocol.IDSize]byte(entry.To)] = struct{}{}
	}
	for _, id := range result.Failed {
		if _, ok := requested[[protocol.IDSize]byte(id)]; !ok {
			return protocol.SendMultiResult{}, fmt.Errorf("%w: SendMultiResult names a recipient that was not requested", ErrProtocolViolation)
		}
	}
	return result, nil
}
