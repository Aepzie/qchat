package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/craguS/qchat/internal/protocol"
)

// isolationTokenSize is the number of random bytes in an isolation token.
const isolationTokenSize = 16

// NewIsolationToken returns a fresh random token, 32 hexadecimal digits,
// for the isolation argument of transport.SOCKS5Dialer. Tor puts streams
// with different tokens on different circuits, so giving the anonymous
// Session a token of its own keeps its connections off the authenticated
// Session's circuit. A Session reuses its dialer, and thus its token, for
// every reconnect.
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
