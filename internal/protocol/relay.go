package protocol

import "fmt"

// Size limits for the bodies of the identity, authentication and messaging
// frames.
const (
	// IDSize is the length, in bytes, of an identity ID.
	IDSize = 32
	// NonceSize is the length, in bytes, of an authentication challenge nonce.
	NonceSize = 32
	// MaxBundleSize is the largest identity bundle, in bytes, a [Register] or
	// [KeyResponse] may carry.
	MaxBundleSize = 16 << 10
	// MaxInviteLen is the maximum length, in bytes, of [Register.Invite].
	MaxInviteLen = 64
	// MaxSignatureSize is the largest authentication signature, in bytes, an
	// [AuthProof] may carry.
	MaxSignatureSize = 8 << 10
	// MaxPayloadSize is the largest ciphertext, in bytes, a [Send] or
	// [Deliver] may carry. It leaves 1 KiB of MaxFrameSize for the frame and
	// body overhead, so a maximal payload always fits in a frame.
	MaxPayloadSize = MaxFrameSize - 1<<10
)

// Register uploads a signed identity bundle to the relay. It is allowed
// before authentication. The relay answers with [Registered] or an
// [ErrorBody].
type Register struct {
	// Bundle is the encoded, self-signed identity bundle, between 1 and
	// MaxBundleSize bytes. The relay verifies it and derives the ID from it.
	Bundle []byte `cbor:"1,keyasint"`
	// Invite is the invite code required to register a new ID on relays that
	// restrict registration: printable ASCII, at most MaxInviteLen bytes. An
	// empty Invite is encoded by omitting the field; an explicitly encoded
	// empty string is not canonical and is rejected.
	Invite string `cbor:"2,keyasint,omitempty"`
}

func (Register) frameType() FrameType { return TypeRegister }

func (r Register) validate() error {
	if err := checkBounded("bundle", r.Bundle, MaxBundleSize); err != nil {
		return err
	}
	if len(r.Invite) > MaxInviteLen {
		return fmt.Errorf("%w: invite is %d bytes", ErrMalformed, len(r.Invite))
	}
	return checkPrintableASCII("invite", r.Invite)
}

// Registered confirms that the bundle of a [Register] is stored. Its only
// valid encoding is the empty map.
type Registered struct{}

func (Registered) frameType() FrameType { return TypeRegistered }

func (Registered) validate() error { return nil }

// AuthBegin starts authentication of the connection as the identity ID. The
// relay answers with an [AuthChallenge].
type AuthBegin struct {
	// ID is the identity to authenticate as, exactly IDSize bytes.
	ID []byte `cbor:"1,keyasint"`
}

func (AuthBegin) frameType() FrameType { return TypeAuthBegin }

func (a AuthBegin) validate() error { return checkFixed("ID", a.ID, IDSize) }

// AuthChallenge carries the fresh nonce the client must sign in its
// [AuthProof].
type AuthChallenge struct {
	// Nonce is chosen at random by the relay, exactly NonceSize bytes.
	Nonce []byte `cbor:"1,keyasint"`
}

func (AuthChallenge) frameType() FrameType { return TypeAuthChallenge }

func (a AuthChallenge) validate() error { return checkFixed("nonce", a.Nonce, NonceSize) }

// AuthProof answers an [AuthChallenge] with a signature by the identity key
// over the relay fingerprint, the nonce and the ID. The relay answers with
// [AuthOK] or an [ErrorBody].
type AuthProof struct {
	// Sig is the encoded signature, between 1 and MaxSignatureSize bytes.
	Sig []byte `cbor:"1,keyasint"`
}

func (AuthProof) frameType() FrameType { return TypeAuthProof }

func (a AuthProof) validate() error { return checkBounded("signature", a.Sig, MaxSignatureSize) }

// AuthOK confirms that the connection is authenticated as the ID named in the
// preceding [AuthBegin]. Its only valid encoding is the empty map.
type AuthOK struct{}

func (AuthOK) frameType() FrameType { return TypeAuthOK }

func (AuthOK) validate() error { return nil }

// KeyRequest asks the relay for the identity bundle registered for ID. The
// relay answers with a [KeyResponse] or an [ErrorBody].
type KeyRequest struct {
	// ID is the identity to look up, exactly IDSize bytes.
	ID []byte `cbor:"1,keyasint"`
}

func (KeyRequest) frameType() FrameType { return TypeKeyRequest }

func (k KeyRequest) validate() error { return checkFixed("ID", k.ID, IDSize) }

// KeyResponse returns the identity bundle requested by a [KeyRequest]. The
// receiver must verify the bundle and check that its ID equals the requested
// ID; the relay is not trusted to do so.
type KeyResponse struct {
	// Bundle is the encoded, self-signed identity bundle, between 1 and
	// MaxBundleSize bytes.
	Bundle []byte `cbor:"1,keyasint"`
}

func (KeyResponse) frameType() FrameType { return TypeKeyResponse }

func (k KeyResponse) validate() error { return checkBounded("bundle", k.Bundle, MaxBundleSize) }

// Send asks the relay to route Payload to the identity To. The relay answers
// with a [SendResult] or an [ErrorBody].
type Send struct {
	// To is the recipient identity, exactly IDSize bytes.
	To []byte `cbor:"1,keyasint"`
	// Payload is end-to-end encrypted ciphertext, between 1 and
	// MaxPayloadSize bytes. It is opaque to the relay.
	Payload []byte `cbor:"2,keyasint"`
}

func (Send) frameType() FrameType { return TypeSend }

func (s Send) validate() error {
	if err := checkFixed("recipient ID", s.To, IDSize); err != nil {
		return err
	}
	return checkBounded("payload", s.Payload, MaxPayloadSize)
}

// SendStatus is the outcome of a [Send] reported in a [SendResult].
type SendStatus uint8

// Send outcomes defined by wire version 1.
const (
	// SendDelivered means the payload was pushed to at least one connection
	// of the recipient. Relays that store messages for offline recipients
	// answer SendAccepted instead.
	SendDelivered SendStatus = 1
	// SendRecipientOffline means the recipient has no authenticated
	// connection and the relay did not store the payload. Relays that store
	// messages for offline recipients answer SendAccepted instead.
	SendRecipientOffline SendStatus = 2
	// SendAccepted means the relay stored the payload for the recipient. The
	// relay pushes it to the recipient's connections until it is
	// acknowledged or expires. The status deliberately does not reveal
	// whether the recipient is online.
	SendAccepted SendStatus = 3
)

// String returns the name of the status, or "SendStatus(n)" for values that
// are not defined.
func (s SendStatus) String() string {
	switch s {
	case SendDelivered:
		return "Delivered"
	case SendRecipientOffline:
		return "RecipientOffline"
	case SendAccepted:
		return "Accepted"
	default:
		return fmt.Sprintf("SendStatus(%d)", uint8(s))
	}
}

// Valid reports whether s is a send status defined by this version of the
// protocol.
func (s SendStatus) Valid() bool {
	return s >= SendDelivered && s <= SendAccepted
}

// SendResult reports the outcome of a [Send].
type SendResult struct {
	// Status is the outcome; it must be a defined SendStatus.
	Status SendStatus `cbor:"1,keyasint"`
}

func (SendResult) frameType() FrameType { return TypeSendResult }

func (s SendResult) validate() error {
	if !s.Status.Valid() {
		return fmt.Errorf("%w: undefined send status %d", ErrMalformed, uint8(s.Status))
	}
	return nil
}

// Deliver pushes a payload routed by the relay to its recipient. The
// recipient answers with an [Ack] carrying QueueID once it has processed the
// payload; until then the relay may deliver the same message again, for
// example after the next authentication, so recipients must tolerate
// duplicates.
type Deliver struct {
	// From is the authenticated identity of the sender, exactly IDSize
	// bytes, or SealedFrom for a message sent with SealedSend or
	// SealedSendMulti, whose sender the relay does not know.
	From []byte `cbor:"1,keyasint"`
	// Payload is the end-to-end encrypted ciphertext exactly as sent, between
	// 1 and MaxPayloadSize bytes.
	Payload []byte `cbor:"2,keyasint"`
	// QueueID identifies the stored message on the relay; it is at least 1.
	// Queue IDs increase in the order in which the relay accepted messages.
	QueueID uint64 `cbor:"3,keyasint"`
}

// IsSealed reports whether d carries a sealed message, one whose From is
// SealedFrom.
func (d Deliver) IsSealed() bool {
	return len(d.From) == IDSize && [IDSize]byte(d.From) == SealedFrom
}

func (Deliver) frameType() FrameType { return TypeDeliver }

func (d Deliver) validate() error {
	if err := checkFixed("sender ID", d.From, IDSize); err != nil {
		return err
	}
	if err := checkBounded("payload", d.Payload, MaxPayloadSize); err != nil {
		return err
	}
	return checkQueueID(d.QueueID)
}

// checkQueueID reports ErrMalformed for the reserved queue ID 0.
func checkQueueID(id uint64) error {
	if id == 0 {
		return fmt.Errorf("%w: queue ID is 0", ErrMalformed)
	}
	return nil
}

// checkFixed reports ErrMalformed unless b is exactly size bytes long.
func checkFixed(field string, b []byte, size int) error {
	if len(b) != size {
		return fmt.Errorf("%w: %s is %d bytes, want %d", ErrMalformed, field, len(b), size)
	}
	return nil
}

// checkBounded reports ErrMalformed unless b holds between 1 and limit bytes.
func checkBounded(field string, b []byte, limit int) error {
	if len(b) == 0 || len(b) > limit {
		return fmt.Errorf("%w: %s is %d bytes, want 1 to %d", ErrMalformed, field, len(b), limit)
	}
	return nil
}

// Limits of the [SendMulti] body.
const (
	// MaxMultiRecipients is the largest number of recipients a [SendMulti]
	// may name.
	MaxMultiRecipients = 256
	// MaxMultiPayloadSize is the largest ciphertext, in bytes, a
	// [SendMulti] may carry. It is smaller than MaxPayloadSize by the space
	// MaxMultiRecipients IDs take, so a maximal SendMulti always fits in a
	// frame. Each copy the relay delivers is an ordinary [Deliver].
	MaxMultiPayloadSize = MaxPayloadSize - 8<<10
)

// SendMulti asks the relay to route the identical Payload to every identity
// in To, for example a group message encrypted once for all members. The
// relay stores the message for every recipient that can take it, each copy
// with its own queue ID, and pushes each copy as an ordinary [Deliver]. It
// answers with a [SendMultiResult] listing the recipients it could not
// store the message for, or with an [ErrorBody] if it rejects the request
// as a whole, in which case no copy is stored. The relay learns the
// recipient list and the payload size but nothing about any group.
type SendMulti struct {
	// To lists between 1 and MaxMultiRecipients distinct recipient
	// identities, each exactly IDSize bytes. It must not contain the
	// sender.
	To [][]byte `cbor:"1,keyasint"`
	// Payload is end-to-end encrypted ciphertext, between 1 and
	// MaxMultiPayloadSize bytes. It is opaque to the relay.
	Payload []byte `cbor:"2,keyasint"`
}

func (SendMulti) frameType() FrameType { return TypeSendMulti }

func (s SendMulti) validate() error {
	if len(s.To) == 0 || len(s.To) > MaxMultiRecipients {
		return fmt.Errorf("%w: %d recipients, want 1 to %d", ErrMalformed, len(s.To), MaxMultiRecipients)
	}
	seen := make(map[[IDSize]byte]struct{}, len(s.To))
	for _, to := range s.To {
		if err := checkFixed("recipient ID", to, IDSize); err != nil {
			return err
		}
		id := [IDSize]byte(to)
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: duplicate recipient ID", ErrMalformed)
		}
		seen[id] = struct{}{}
	}
	return checkBounded("payload", s.Payload, MaxMultiPayloadSize)
}

// SendMultiResult reports the outcome of a [SendMulti] the relay accepted.
// The message is stored for every recipient of the request except those
// listed in Failed; Reasons[i] says why it was not stored for Failed[i].
// An empty Failed, encoded by omitting both lists, means every recipient
// got the message.
type SendMultiResult struct {
	// Status is the outcome of the request as a whole; it must be
	// SendAccepted, even when no recipient could take the message.
	Status SendStatus `cbor:"1,keyasint"`
	// Failed lists at most MaxMultiRecipients distinct recipient IDs, each
	// exactly IDSize bytes, for which the message was not stored. An empty
	// list is encoded by omitting the field.
	Failed [][]byte `cbor:"2,keyasint,omitempty"`
	// Reasons holds one defined error code per entry of Failed, in the same
	// order: ErrCodeNotFound for an unknown recipient and ErrCodeQueueFull
	// for one whose stored messages reached the relay's limits. It is
	// omitted exactly when Failed is.
	Reasons []ErrorCode `cbor:"3,keyasint,omitempty"`
}

func (SendMultiResult) frameType() FrameType { return TypeSendMultiResult }

func (s SendMultiResult) validate() error {
	if s.Status != SendAccepted {
		return fmt.Errorf("%w: send multi status %d, want %d", ErrMalformed, uint8(s.Status), uint8(SendAccepted))
	}
	if len(s.Failed) > MaxMultiRecipients {
		return fmt.Errorf("%w: %d failed recipients, want at most %d", ErrMalformed, len(s.Failed), MaxMultiRecipients)
	}
	if len(s.Reasons) != len(s.Failed) {
		return fmt.Errorf("%w: %d reasons for %d failed recipients", ErrMalformed, len(s.Reasons), len(s.Failed))
	}
	seen := make(map[[IDSize]byte]struct{}, len(s.Failed))
	for i, id := range s.Failed {
		if err := checkFixed("failed recipient ID", id, IDSize); err != nil {
			return err
		}
		if _, dup := seen[[IDSize]byte(id)]; dup {
			return fmt.Errorf("%w: duplicate failed recipient ID", ErrMalformed)
		}
		seen[[IDSize]byte(id)] = struct{}{}
		if !s.Reasons[i].Valid() {
			return fmt.Errorf("%w: undefined error code %d", ErrMalformed, uint16(s.Reasons[i]))
		}
	}
	return nil
}
