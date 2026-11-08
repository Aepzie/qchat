package protocol

import "fmt"

// Size limits for the prekey frames.
const (
	// MaxPrekeySize is the largest encoded signed or one-time prekey, in
	// bytes, a prekey frame may carry.
	MaxPrekeySize = 8 << 10
	// MaxOneTimePrekeysPerUpload is the largest number of one-time prekeys a
	// single [PrekeyUpload] may carry.
	MaxOneTimePrekeysPerUpload = 100
)

// PrekeyUpload stores prekeys of the authenticated identity on the relay. The
// relay verifies every prekey against the identity's registered bundle and
// answers with a [PrekeyStatus] or an [ErrorBody]. An upload carrying neither
// field only asks for the current status; its encoding is the empty map.
type PrekeyUpload struct {
	// SignedPrekey is an encoded signed prekey, between 1 and MaxPrekeySize
	// bytes. An absent signed prekey is encoded by omitting the field; an
	// explicitly encoded empty byte string is not canonical and is rejected.
	SignedPrekey []byte `cbor:"1,keyasint,omitempty"`
	// OneTimePrekeys holds at most MaxOneTimePrekeysPerUpload encoded
	// one-time prekeys, each between 1 and MaxPrekeySize bytes. An empty list
	// is encoded by omitting the field; an explicitly encoded empty array is
	// not canonical and is rejected.
	OneTimePrekeys [][]byte `cbor:"2,keyasint,omitempty"`
}

func (PrekeyUpload) frameType() FrameType { return TypePrekeyUpload }

func (p PrekeyUpload) validate() error {
	if p.SignedPrekey != nil {
		if err := checkBounded("signed prekey", p.SignedPrekey, MaxPrekeySize); err != nil {
			return err
		}
	}
	if len(p.OneTimePrekeys) > MaxOneTimePrekeysPerUpload {
		return fmt.Errorf("%w: %d one-time prekeys, want at most %d",
			ErrMalformed, len(p.OneTimePrekeys), MaxOneTimePrekeysPerUpload)
	}
	for _, otp := range p.OneTimePrekeys {
		if err := checkBounded("one-time prekey", otp, MaxPrekeySize); err != nil {
			return err
		}
	}
	return nil
}

// PrekeyStatus reports the prekeys the relay holds for the authenticated
// identity, in answer to a [PrekeyUpload].
type PrekeyStatus struct {
	// OneTimeRemaining is the number of one-time prekeys not yet handed out.
	OneTimeRemaining uint32 `cbor:"1,keyasint"`
	// SignedPrekeyExpires is the expiry of the stored signed prekey in Unix
	// seconds, or 0 if the relay holds none. It is never negative.
	SignedPrekeyExpires int64 `cbor:"2,keyasint"`
}

func (PrekeyStatus) frameType() FrameType { return TypePrekeyStatus }

func (p PrekeyStatus) validate() error {
	if p.SignedPrekeyExpires < 0 {
		return fmt.Errorf("%w: negative signed prekey expiry", ErrMalformed)
	}
	return nil
}

// PrekeyRequest asks the relay for the prekey bundle of the identity ID. The
// relay answers with a [PrekeyResponse] or an [ErrorBody].
//
// AccessProof follows the rules of [KeyRequest]: absent on an
// authenticated connection, required on an anonymous one, where a missing
// grant is answered with ErrCodeNotFound like an unknown ID or an ID
// without prekeys.
type PrekeyRequest struct {
	// ID is the identity to look up, exactly IDSize bytes.
	ID []byte `cbor:"1,keyasint"`
	// AccessProof is the access verifier of ID, exactly
	// AccessVerifierSize bytes, or absent; see [KeyRequest.AccessProof].
	AccessProof []byte `cbor:"2,keyasint,omitempty"`
}

func (PrekeyRequest) frameType() FrameType { return TypePrekeyRequest }

func (p PrekeyRequest) validate() error {
	if err := checkFixed("ID", p.ID, IDSize); err != nil {
		return err
	}
	return checkOptionalProof(p.AccessProof)
}

// PrekeyResponse returns the prekey bundle requested by a [PrekeyRequest].
// The relay hands out each one-time prekey at most once. The receiver must
// verify the identity bundle as for a [KeyResponse] and verify both prekeys
// against it; the relay is not trusted to do so.
type PrekeyResponse struct {
	// Bundle is the encoded, self-signed identity bundle, between 1 and
	// MaxBundleSize bytes.
	Bundle []byte `cbor:"1,keyasint"`
	// SignedPrekey is the encoded signed prekey, between 1 and MaxPrekeySize
	// bytes.
	SignedPrekey []byte `cbor:"2,keyasint"`
	// OneTimePrekey is an encoded one-time prekey, between 1 and
	// MaxPrekeySize bytes, or absent once the relay has none left. An absent
	// prekey is encoded by omitting the field.
	OneTimePrekey []byte `cbor:"3,keyasint,omitempty"`
}

func (PrekeyResponse) frameType() FrameType { return TypePrekeyResponse }

func (p PrekeyResponse) validate() error {
	if err := checkBounded("bundle", p.Bundle, MaxBundleSize); err != nil {
		return err
	}
	if err := checkBounded("signed prekey", p.SignedPrekey, MaxPrekeySize); err != nil {
		return err
	}
	if p.OneTimePrekey == nil {
		return nil
	}
	return checkBounded("one-time prekey", p.OneTimePrekey, MaxPrekeySize)
}

// Ack tells the relay that the message delivered with QueueID has been
// processed, so the relay deletes it. The relay sends no response.
type Ack struct {
	// QueueID is the [Deliver.QueueID] being acknowledged; it is at least 1.
	QueueID uint64 `cbor:"1,keyasint"`
}

func (Ack) frameType() FrameType { return TypeAck }

func (a Ack) validate() error { return checkQueueID(a.QueueID) }
