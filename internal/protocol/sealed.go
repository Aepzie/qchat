package protocol

import (
	"crypto/subtle"
	"fmt"
)

// Sizes and limits of the sealed sender bodies.
const (
	// AccessVerifierSize is the length, in bytes, of an access key verifier
	// and of an access proof: HMAC-SHA256(AccessKey,
	// "qchat/v1/access-verifier"), as computed by package sealed.
	AccessVerifierSize = 32
	// MaxSealedMultiPayloadSize is the largest ciphertext, in bytes, a
	// [SealedSendMulti] may carry. It is smaller than MaxPayloadSize by the
	// space MaxMultiRecipients entries of recipient ID and access proof
	// take, so a maximal SealedSendMulti always fits in a frame.
	MaxSealedMultiPayloadSize = MaxPayloadSize - 24<<10
)

// SealedFrom is the From of every [Deliver] of a message sent with
// [SealedSend] or [SealedSendMulti]: 32 zero bytes. No identity has this ID,
// which would be a SHA-256 preimage of zero, so it cannot be confused with
// an authenticated sender. The recipient learns the sender only from inside
// the end-to-end encrypted payload.
var SealedFrom = [IDSize]byte{}

// SetAccessKey uploads the verifier of the authenticated identity's access
// key. It is allowed only on an authenticated connection. The relay stores
// it in place of any earlier verifier, which revokes the earlier access
// key, and answers with [AccessKeySet] or an [ErrorBody].
type SetAccessKey struct {
	// Verifier is HMAC-SHA256(AccessKey, "qchat/v1/access-verifier"),
	// exactly AccessVerifierSize bytes and not all zero. Sealed senders
	// present the same value as their access proof. The relay stores only
	// its SHA-256 hash.
	Verifier []byte `cbor:"1,keyasint"`
	// AllowUnidentified lets anyone send sealed messages to the identity
	// without a matching access proof. False is encoded by omitting the
	// field; an explicitly encoded false is not canonical and is rejected.
	AllowUnidentified bool `cbor:"2,keyasint,omitempty"`
}

func (SetAccessKey) frameType() FrameType { return TypeSetAccessKey }

func (s SetAccessKey) validate() error {
	if err := checkFixed("access verifier", s.Verifier, AccessVerifierSize); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(s.Verifier, make([]byte, AccessVerifierSize)) == 1 {
		return fmt.Errorf("%w: access verifier is zero", ErrMalformed)
	}
	return nil
}

// AccessKeySet confirms that the verifier of a [SetAccessKey] is stored.
// Its only valid encoding is the empty map.
type AccessKeySet struct{}

func (AccessKeySet) frameType() FrameType { return TypeAccessKeySet }

func (AccessKeySet) validate() error { return nil }

// SealedSend asks the relay to route Payload to the identity To without
// naming the sender. It is allowed only on an anonymous connection: one
// that completed the handshake and never registered or began
// authentication. The relay checks AccessProof against the verifier To
// uploaded and answers with a [SendResult], or with an [ErrorBody]
// carrying ErrCodeNotFound when To is unknown, has no verifier or the
// proof does not match; the three cases are indistinguishable.
type SealedSend struct {
	// To is the recipient identity, exactly IDSize bytes.
	To []byte `cbor:"1,keyasint"`
	// AccessProof is the recipient's access verifier, exactly
	// AccessVerifierSize bytes. It is ignored for recipients that allow
	// unidentified senders, but must still be present.
	AccessProof []byte `cbor:"2,keyasint"`
	// Payload is end-to-end encrypted ciphertext, between 1 and
	// MaxPayloadSize bytes. It is opaque to the relay.
	Payload []byte `cbor:"3,keyasint"`
}

func (SealedSend) frameType() FrameType { return TypeSealedSend }

func (s SealedSend) validate() error {
	if err := checkFixed("recipient ID", s.To, IDSize); err != nil {
		return err
	}
	if err := checkFixed("access proof", s.AccessProof, AccessVerifierSize); err != nil {
		return err
	}
	return checkBounded("payload", s.Payload, MaxPayloadSize)
}

// SealedRecipient is one entry of a [SealedSendMulti].
type SealedRecipient struct {
	// To is the recipient identity, exactly IDSize bytes.
	To []byte `cbor:"1,keyasint"`
	// AccessProof is the recipient's access verifier, exactly
	// AccessVerifierSize bytes.
	AccessProof []byte `cbor:"2,keyasint"`
}

// SealedSendMulti asks the relay to route the identical Payload to every
// recipient of Entries without naming the sender, for example a group
// message whose sender is named only inside its encrypted header. It is
// allowed only on an anonymous connection. The relay stores the message for
// every entry whose proof it accepts and whose queue has room, and answers
// with a [SendMultiResult] listing the others: ErrCodeNotFound for an
// unknown recipient or a wrong proof alike, ErrCodeQueueFull for a full
// queue. If it rejects the request as a whole it answers with an
// [ErrorBody] and stores nothing.
type SealedSendMulti struct {
	// Entries lists between 1 and MaxMultiRecipients recipients with
	// distinct IDs.
	Entries []SealedRecipient `cbor:"1,keyasint"`
	// Payload is end-to-end encrypted ciphertext, between 1 and
	// MaxSealedMultiPayloadSize bytes. It is opaque to the relay.
	Payload []byte `cbor:"2,keyasint"`
}

func (SealedSendMulti) frameType() FrameType { return TypeSealedSendMulti }

func (s SealedSendMulti) validate() error {
	if len(s.Entries) == 0 || len(s.Entries) > MaxMultiRecipients {
		return fmt.Errorf("%w: %d recipients, want 1 to %d", ErrMalformed, len(s.Entries), MaxMultiRecipients)
	}
	seen := make(map[[IDSize]byte]struct{}, len(s.Entries))
	for _, entry := range s.Entries {
		if err := checkFixed("recipient ID", entry.To, IDSize); err != nil {
			return err
		}
		if err := checkFixed("access proof", entry.AccessProof, AccessVerifierSize); err != nil {
			return err
		}
		id := [IDSize]byte(entry.To)
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: duplicate recipient ID", ErrMalformed)
		}
		seen[id] = struct{}{}
	}
	return checkBounded("payload", s.Payload, MaxSealedMultiPayloadSize)
}
