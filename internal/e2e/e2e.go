package e2e

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/identity"
)

// Kind is the content type of a message.
type Kind uint8

// Message kinds.
const (
	// KindText is a UTF-8 text message.
	KindText Kind = 1
)

// Format parameters and limits.
const (
	// Version is the Inner format version written by [Seal].
	Version = 1

	// MsgIDSize is the length of a message ID.
	MsgIDSize = 16

	// MaxBodySize is the largest message body in bytes (64 KiB).
	MaxBodySize = 64 << 10

	// MaxInnerSize bounds the encoded Inner structure: a maximal body plus
	// the signature and generous room for the fixed fields and CBOR
	// framing.
	MaxInnerSize = MaxBodySize + hybridsig.SignatureSize + 512

	// MaxPayloadSize is the largest sealed payload [Open] accepts. Anything
	// larger is rejected before any decryption work is done. It is well
	// below the relay's default max_message_size.
	MaxPayloadSize = MaxInnerSize + sealbox.Overhead

	// ClockSkewTolerance is how far the sender timestamp may differ from
	// the local clock before [Message.ClockSkew] is set.
	ClockSkewTolerance = 24 * time.Hour
)

// Errors returned by [Seal] and [Open]. Callers compare with [errors.Is].
// Open never returns any content together with an error.
var (
	// ErrDecrypt reports a payload that does not decrypt: modified in
	// transit, sealed to another identity, or sealed for a different
	// sender/recipient pair than the one the relay reported (the HPKE info
	// string binds both IDs).
	ErrDecrypt = errors.New("e2e: message does not decrypt")

	// ErrNotForMe reports a message that decrypts but whose signed
	// recipient is another identity.
	ErrNotForMe = errors.New("e2e: message is addressed to another identity")

	// ErrSenderMismatch reports a message that decrypts but whose signed
	// sender differs from the sender reported by the relay.
	ErrSenderMismatch = errors.New("e2e: message sender does not match the relay-reported sender")

	// ErrBadSignature reports a message whose signature does not verify
	// under the sender's signing key.
	ErrBadSignature = errors.New("e2e: message signature does not verify")

	// ErrUnknownSender reports that the sender's verified bundle could not
	// be obtained from the lookup function.
	ErrUnknownSender = errors.New("e2e: sender bundle unavailable")

	// ErrMalformed reports a payload or decrypted content that is not
	// exactly in the canonical version 1 format, or that violates a limit
	// (size, kind, UTF-8).
	ErrMalformed = errors.New("e2e: malformed message")

	// ErrInvalidMessage reports arguments to [Seal] that do not form a
	// valid message.
	ErrInvalidMessage = errors.New("e2e: invalid message")
)

// Message is a decrypted and fully verified message.
type Message struct {
	// From is the sender, equal to the relay-reported sender and to the
	// identity whose key signed the message.
	From identity.ID

	// To is the recipient, always the opening identity.
	To identity.ID

	// MsgID is the sender-chosen random message ID. Open does NOT check it
	// for replays; see [Open].
	MsgID [MsgIDSize]byte

	// Sent is the sender's claimed send time, with millisecond precision.
	Sent time.Time

	// Kind is the content type.
	Kind Kind

	// Body is the content, valid UTF-8 for [KindText]. It is not sanitised:
	// it may contain control characters and terminal escape sequences, which
	// a user interface must neutralise before display.
	Body []byte

	// ClockSkew is set when Sent differs from the local clock by more than
	// [ClockSkewTolerance]. Such messages are flagged, not dropped (the
	// clock of either side may be wrong), and Sent should not be trusted
	// for ordering.
	ClockSkew bool
}

// innerTBS holds fields 1 to 7 of Inner; its canonical encoding is what the
// sender signs.
type innerTBS struct {
	Version uint8  `cbor:"1,keyasint"`
	From    []byte `cbor:"2,keyasint"`
	To      []byte `cbor:"3,keyasint"`
	MsgID   []byte `cbor:"4,keyasint"`
	Sent    int64  `cbor:"5,keyasint"`
	Kind    uint8  `cbor:"6,keyasint"`
	Body    []byte `cbor:"7,keyasint"`
}

// inner is the complete plaintext of a sealed payload, fields 1 to 8.
type inner struct {
	Version uint8  `cbor:"1,keyasint"`
	From    []byte `cbor:"2,keyasint"`
	To      []byte `cbor:"3,keyasint"`
	MsgID   []byte `cbor:"4,keyasint"`
	Sent    int64  `cbor:"5,keyasint"`
	Kind    uint8  `cbor:"6,keyasint"`
	Body    []byte `cbor:"7,keyasint"`
	Sig     []byte `cbor:"8,keyasint"`
}

func (in *inner) tbs() innerTBS {
	return innerTBS{Version: in.Version, From: in.From, To: in.To, MsgID: in.MsgID, Sent: in.Sent, Kind: in.Kind, Body: in.Body}
}

// messageInfo returns the HPKE info string "qchat/v1/message" || From || To.
// Binding both IDs into the key schedule means a payload only decrypts for
// the exact sender/recipient pair it was sealed for, so the relay cannot
// re-attribute a payload to another sender without decryption failing.
func messageInfo(from, to identity.ID) []byte {
	info := make([]byte, 0, len(identity.ContextMessage)+2*identity.IDSize)
	info = append(info, identity.ContextMessage...)
	info = append(info, from[:]...)
	info = append(info, to[:]...)
	return info
}

// checkContent enforces the kind and body rules shared by Seal and Open.
func checkContent(kind Kind, body []byte) error {
	if kind != KindText {
		return fmt.Errorf("unknown kind %d", kind)
	}
	if len(body) == 0 || len(body) > MaxBodySize {
		return fmt.Errorf("body must be 1 to %d bytes", MaxBodySize)
	}
	if !utf8.Valid(body) {
		return errors.New("text body is not valid UTF-8")
	}
	return nil
}

// Seal builds an end-to-end message from the identity from to the identity
// of bundle to and returns the payload for a relay Send frame, together
// with the random message ID (which the caller stores, for example to match
// delivery results).
//
// The Inner structure
//
//	CBOR{1: version, 2: From, 3: To, 4: MsgID, 5: Sent (Unix ms), 6: Kind, 7: Body, 8: Sig}
//
// is signed by from under the context "qchat/v1/message" over the
// canonical encoding of fields 1 to 7 and then sealed with HPKE
// (MLKEM768-X25519) to the KEM key of to, with info
// "qchat/v1/message" || From || To. now is recorded as the send time.
//
// kind must be [KindText] and body must be 1 to [MaxBodySize] bytes of
// valid UTF-8; otherwise Seal returns [ErrInvalidMessage]. to must come from
// identity.ParseBundleForID for the ID the user means to write to.
func Seal(from *identity.Identity, to *identity.Bundle, kind Kind, body []byte, now time.Time) (payload []byte, msgID [MsgIDSize]byte, err error) {
	if from == nil || to == nil || to.KEMKey == nil || to.SigningKey == nil {
		return nil, msgID, fmt.Errorf("%w: missing sender or recipient", ErrInvalidMessage)
	}
	if err := checkContent(kind, body); err != nil {
		return nil, msgID, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	// The ID is recomputed rather than taken from to.ID: sealing to a
	// hand-assembled Bundle whose ID field names someone else would
	// otherwise produce a message signed as addressed to that someone.
	toID := identity.IDFromSigningKey(to.SigningKey)
	if toID != to.ID {
		return nil, msgID, fmt.Errorf("%w: recipient bundle ID does not match its signing key", ErrInvalidMessage)
	}
	if _, err := rand.Read(msgID[:]); err != nil {
		return nil, msgID, fmt.Errorf("e2e: reading randomness: %w", err)
	}
	fromID := from.ID()
	in := inner{
		Version: Version,
		From:    fromID[:],
		To:      toID[:],
		MsgID:   msgID[:],
		Sent:    now.UnixMilli(),
		Kind:    uint8(kind),
		Body:    body,
	}
	payload, err = sealInner(from, in, to.KEMKey, messageInfo(fromID, toID))
	if err != nil {
		return nil, [MsgIDSize]byte{}, err
	}
	return payload, msgID, nil
}

// sealInner signs in with signer and seals it under info. It performs no
// consistency checks between in, signer and info, so that tests can build
// the inconsistent messages Open must reject; production code reaches it
// only through Seal.
func sealInner(signer *identity.Identity, in inner, kem *sealbox.PublicKey, info []byte) ([]byte, error) {
	tbs, err := encMode.Marshal(in.tbs())
	if err != nil {
		return nil, fmt.Errorf("e2e: encoding message: %w", err)
	}
	if in.Sig, err = signer.SignMessage(tbs); err != nil {
		return nil, err
	}
	plaintext, err := encMode.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("e2e: encoding message: %w", err)
	}
	defer clear(plaintext)
	return sealbox.Seal(kem, info, plaintext)
}

// Open decrypts and verifies a payload received in a relay Deliver frame.
// relayFrom is the sender ID the relay reported in that frame, and lookup
// returns the verified bundle of a sender ID (from the contact store, or
// from the relay through identity.ParseBundleForID).
//
// Open performs these checks, in this order, and returns the matching
// error for the first that fails:
//
//  1. the payload is at most [MaxPayloadSize] bytes ([ErrMalformed]);
//  2. HPKE opens it with info "qchat/v1/message" || relayFrom || own ID
//     ([ErrDecrypt]);
//  3. the plaintext is the canonical encoding of a version 1 Inner with
//     fields of the right sizes, a known kind and a valid body
//     ([ErrMalformed]);
//  4. Inner.To is the opening identity ([ErrNotForMe]);
//  5. Inner.From equals relayFrom ([ErrSenderMismatch]);
//  6. lookup(From) returns a bundle whose ID, recomputed from its signing
//     key, equals From ([ErrUnknownSender]);
//  7. the signature verifies under that bundle's signing key
//     ([ErrBadSignature]).
//
// Because the info string already binds relayFrom and the own ID, a relay
// that misreports the sender or misroutes a payload makes step 2 fail;
// steps 4 and 5 catch a sender that signs one pair of IDs but seals under
// another. Content is never returned before all checks pass.
//
// Finally, Sent is compared with now and [Message.ClockSkew] set if they
// differ by more than [ClockSkewTolerance].
//
// REPLAY PROTECTION IS THE CALLER'S JOB. Open does not, and cannot, know
// which message IDs were seen before. A relay (or anyone who recorded a
// payload) can deliver the same valid payload again, and Open will accept
// it again. The caller MUST reject a message whose (From, MsgID) is already
// in its message store (clientdb.HasMessage, or rely on AppendMessage
// returning clientdb.ErrDuplicate) before showing or acting on it.
func Open(me *identity.Identity, relayFrom identity.ID, payload []byte, lookup func(identity.ID) (*identity.Bundle, error), now time.Time) (*Message, error) {
	if me == nil || lookup == nil {
		return nil, errors.New("e2e: Open needs an identity and a lookup function")
	}
	if len(payload) > MaxPayloadSize {
		return nil, fmt.Errorf("%w: payload of %d bytes exceeds %d", ErrMalformed, len(payload), MaxPayloadSize)
	}
	myID := me.ID()
	plaintext, err := me.OpenBox(messageInfo(relayFrom, myID), payload)
	if errors.Is(err, identity.ErrDestroyed) {
		return nil, err
	}
	if err != nil {
		return nil, ErrDecrypt
	}
	defer clear(plaintext)
	if len(plaintext) > MaxInnerSize {
		return nil, fmt.Errorf("%w: message too large", ErrMalformed)
	}

	var in inner
	if err := decodeCanonical(plaintext, &in); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if in.Version != Version {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrMalformed, in.Version)
	}
	if len(in.From) != identity.IDSize || len(in.To) != identity.IDSize || len(in.MsgID) != MsgIDSize ||
		len(in.Sig) != hybridsig.SignatureSize {
		return nil, fmt.Errorf("%w: field of wrong size", ErrMalformed)
	}
	if err := checkContent(Kind(in.Kind), in.Body); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	from, to := identity.ID(in.From), identity.ID(in.To)
	if to != myID {
		return nil, ErrNotForMe
	}
	if from != relayFrom {
		return nil, ErrSenderMismatch
	}

	bundle, err := lookup(from)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnknownSender, err)
	}
	// The bundle's ID is recomputed from its signing key instead of trusting
	// the ID field, so a lookup that returns the wrong bundle (or a Bundle
	// assembled by hand) can never make another key's signature count as
	// the sender's.
	if bundle == nil || bundle.SigningKey == nil || identity.IDFromSigningKey(bundle.SigningKey) != from {
		return nil, fmt.Errorf("%w: lookup did not return the sender's bundle", ErrUnknownSender)
	}
	tbs, err := encMode.Marshal(in.tbs())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := bundle.SigningKey.Verify(identity.ContextMessage, tbs, in.Sig); err != nil {
		return nil, ErrBadSignature
	}

	sent := time.UnixMilli(in.Sent)
	skew := now.Sub(sent)
	msg := &Message{
		From:      from,
		To:        to,
		Sent:      sent,
		Kind:      Kind(in.Kind),
		Body:      append([]byte(nil), in.Body...),
		ClockSkew: skew > ClockSkewTolerance || skew < -ClockSkewTolerance,
	}
	copy(msg.MsgID[:], in.MsgID)
	return msg, nil
}
