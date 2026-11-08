package e2e

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/craguS/qchat/internal/handshake"
	"github.com/craguS/qchat/internal/padding"
)

// Kind is the content type of a message.
type Kind uint8

// Message kinds. Kinds 1 to 3 and 8 travel over pairwise ratchet sessions
// inside an [Envelope]; kind 4 is only ever encrypted with a group sender
// key (package senderkey) and must be rejected when it arrives pairwise,
// just as the pairwise kinds must be rejected inside a group envelope.
// Kinds 5 to 7 are reserved and rejected.
const (
	// KindText is a UTF-8 text message.
	KindText Kind = 1
	// KindGroupControl carries a signed group control message (package
	// group) as its body. The body is binary.
	KindGroupControl Kind = 2
	// KindSenderKey carries a sender key distribution message (package
	// senderkey) as its body. The body is binary.
	KindSenderKey Kind = 3
	// KindGroupText is a UTF-8 text message to a group, encrypted with the
	// sender's group sender key.
	KindGroupText Kind = 4
	// KindAccessKey carries the sender's sealed sender access key (package
	// sealed, docs/design/phase-5-metadata.md) as its body: the secret that
	// lets the recipient send sealed messages to the sender. The body is
	// binary; its exact format is checked by the application.
	KindAccessKey Kind = 8
)

// known reports whether k is a kind this package encodes and parses.
func (k Kind) known() bool {
	return (k >= KindText && k <= KindGroupText) || k == KindAccessKey
}

// IsText reports whether k is a kind whose body is UTF-8 text shown to the
// user.
func (k Kind) IsText() bool { return k == KindText || k == KindGroupText }

// Format parameters and limits.
const (
	// Version is the envelope format version. Version 3 differs from
	// version 2 only in that the ciphertext seals a padded plaintext
	// ([MarshalPaddedPlaintext]); envelopes of other versions are rejected.
	Version = 3

	// MsgIDSize is the length of a message ID.
	MsgIDSize = 16

	// MaxBodySize is the largest message body in bytes (64 KiB).
	MaxBodySize = 64 << 10

	// MaxPlaintextSize bounds an encoded Plaintext: a maximal body plus
	// generous room for the message ID, time, kind and CBOR framing.
	MaxPlaintextSize = MaxBodySize + 64

	// MaxPaddedPlaintextSize is the padded size of a maximal encoded
	// Plaintext: the padding bucket of MaxPlaintextSize bytes, 128 KiB.
	MaxPaddedPlaintextSize = 128 << 10

	// MaxCiphertextSize bounds Envelope.Ciphertext: an encrypted maximal
	// padded Plaintext with its 16-byte authentication tag.
	MaxCiphertextSize = MaxPaddedPlaintextSize + 16

	// MaxHeaderSize bounds Envelope.Header, the encoded ratchet header
	// (ratchet public key, KEM ciphertext, target and counters). It equals
	// the bound package ratchet applies when parsing a header.
	MaxHeaderSize = 4096

	// MaxInitSize bounds Envelope.Init; it is handshake.MaxInitSize.
	MaxInitSize = handshake.MaxInitSize

	// MaxEnvelopeSize is the largest relay payload [ParseEnvelope] accepts:
	// every field at its maximum plus room for the CBOR framing. Anything
	// larger is rejected before it is decoded. It is below the relay's
	// default max_message_size of 256 KiB.
	MaxEnvelopeSize = MaxInitSize + MaxHeaderSize + MaxCiphertextSize + 64

	// ClockSkewTolerance is how far a sender timestamp may differ from the
	// local clock before [ClockSkewed] reports it.
	ClockSkewTolerance = 24 * time.Hour
)

// Errors returned by this package. Callers compare with [errors.Is].
var (
	// ErrMalformed reports input that is not exactly in the canonical
	// format, or that violates a limit (size, version, kind, UTF-8).
	ErrMalformed = errors.New("e2e: malformed message")

	// ErrInvalidMessage reports arguments that do not form a valid
	// envelope or plaintext.
	ErrInvalidMessage = errors.New("e2e: invalid message")
)

// Envelope is the relay payload of a message.
type Envelope struct {
	// Init is the encoded handshake Init header, or nil when none is
	// attached.
	Init []byte
	// Header is the encoded ratchet header.
	Header []byte
	// Ciphertext is the ratchet ciphertext of an encoded Plaintext.
	Ciphertext []byte
}

// envelopeWire is the encoding of Envelope.
type envelopeWire struct {
	Version    uint8  `cbor:"1,keyasint"`
	Init       []byte `cbor:"2,keyasint,omitempty"`
	Header     []byte `cbor:"3,keyasint"`
	Ciphertext []byte `cbor:"4,keyasint"`
}

func (e Envelope) check() error {
	if e.Init != nil && (len(e.Init) == 0 || len(e.Init) > MaxInitSize) {
		return fmt.Errorf("Init must be absent or 1 to %d bytes", MaxInitSize)
	}
	if len(e.Header) == 0 || len(e.Header) > MaxHeaderSize {
		return fmt.Errorf("header must be 1 to %d bytes", MaxHeaderSize)
	}
	if len(e.Ciphertext) == 0 || len(e.Ciphertext) > MaxCiphertextSize {
		return fmt.Errorf("ciphertext must be 1 to %d bytes", MaxCiphertextSize)
	}
	return nil
}

// MarshalEnvelope returns the canonical encoding of e. It returns
// [ErrInvalidMessage] if a field is empty (other than an absent Init) or
// above its limit.
func MarshalEnvelope(e Envelope) ([]byte, error) {
	if err := e.check(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	b, err := encMode.Marshal(envelopeWire{Version: Version, Init: e.Init, Header: e.Header, Ciphertext: e.Ciphertext})
	if err != nil {
		return nil, fmt.Errorf("e2e: encoding envelope: %w", err)
	}
	return b, nil
}

// ParseEnvelope decodes a relay payload. It accepts only the canonical
// encoding of a version [Version] envelope whose fields are within their limits,
// and returns [ErrMalformed] otherwise. The returned slices do not alias b.
func ParseEnvelope(b []byte) (Envelope, error) {
	if len(b) > MaxEnvelopeSize {
		return Envelope{}, fmt.Errorf("%w: envelope of %d bytes exceeds %d", ErrMalformed, len(b), MaxEnvelopeSize)
	}
	var w envelopeWire
	if err := decodeCanonical(b, &w); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if w.Version != Version {
		return Envelope{}, fmt.Errorf("%w: unsupported version %d", ErrMalformed, w.Version)
	}
	e := Envelope{Init: w.Init, Header: w.Header, Ciphertext: w.Ciphertext}
	if err := e.check(); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return e, nil
}

// Plaintext is the content of a message, encrypted by the ratchet.
type Plaintext struct {
	// MsgID is the sender-chosen random message ID.
	MsgID [MsgIDSize]byte
	// Sent is the sender's claimed send time, with millisecond precision.
	Sent time.Time
	// Kind is the content type.
	Kind Kind
	// Body is the content, valid UTF-8 for [KindText] and [KindGroupText]
	// and opaque bytes for the other kinds. Text is not
	// sanitised: it may contain control characters and terminal escape
	// sequences, which a user interface must neutralise before display.
	Body []byte
}

// plaintextWire is the encoding of Plaintext.
type plaintextWire struct {
	MsgID []byte `cbor:"1,keyasint"`
	Sent  int64  `cbor:"2,keyasint"`
	Kind  uint8  `cbor:"3,keyasint"`
	Body  []byte `cbor:"4,keyasint"`
}

// checkContent enforces the kind and body rules.
func checkContent(kind Kind, body []byte) error {
	if !kind.known() {
		return fmt.Errorf("unknown kind %d", kind)
	}
	if len(body) == 0 || len(body) > MaxBodySize {
		return fmt.Errorf("body must be 1 to %d bytes", MaxBodySize)
	}
	if kind.IsText() && !utf8.Valid(body) {
		return errors.New("text body is not valid UTF-8")
	}
	return nil
}

// NewPlaintext returns a plaintext of the given kind and body with a fresh
// random message ID, sent at now. It returns [ErrInvalidMessage] unless
// kind is known and body is 1 to [MaxBodySize] bytes, valid UTF-8 for the
// text kinds.
// body is not copied.
func NewPlaintext(kind Kind, body []byte, now time.Time) (Plaintext, error) {
	if err := checkContent(kind, body); err != nil {
		return Plaintext{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	p := Plaintext{Sent: time.UnixMilli(now.UnixMilli()), Kind: kind, Body: body}
	if _, err := rand.Read(p.MsgID[:]); err != nil {
		return Plaintext{}, fmt.Errorf("e2e: reading randomness: %w", err)
	}
	return p, nil
}

// MarshalPlaintext returns the canonical encoding of p. It returns
// [ErrInvalidMessage] for content NewPlaintext would refuse. The result
// contains the message body; the caller should clear it after encryption.
func MarshalPlaintext(p Plaintext) ([]byte, error) {
	if err := checkContent(p.Kind, p.Body); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	b, err := encMode.Marshal(plaintextWire{MsgID: p.MsgID[:], Sent: p.Sent.UnixMilli(), Kind: uint8(p.Kind), Body: p.Body})
	if err != nil {
		return nil, fmt.Errorf("e2e: encoding plaintext: %w", err)
	}
	return b, nil
}

// ParsePlaintext decodes a decrypted plaintext. It accepts only the
// canonical encoding with a 16-byte message ID, a known kind and a valid
// body, and returns [ErrMalformed] otherwise. The returned body does not
// alias b, so the caller may clear b.
func ParsePlaintext(b []byte) (Plaintext, error) {
	if len(b) > MaxPlaintextSize {
		return Plaintext{}, fmt.Errorf("%w: plaintext of %d bytes exceeds %d", ErrMalformed, len(b), MaxPlaintextSize)
	}
	var w plaintextWire
	if err := decodeCanonical(b, &w); err != nil {
		return Plaintext{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(w.MsgID) != MsgIDSize {
		return Plaintext{}, fmt.Errorf("%w: message ID of wrong size", ErrMalformed)
	}
	if err := checkContent(Kind(w.Kind), w.Body); err != nil {
		return Plaintext{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return Plaintext{MsgID: [MsgIDSize]byte(w.MsgID), Sent: time.UnixMilli(w.Sent), Kind: Kind(w.Kind), Body: w.Body}, nil
}

// MarshalPaddedPlaintext returns the canonical encoding of p padded with
// [padding.Pad] to its size bucket. This is what the ratchet encrypts: the
// padding sits inside the AEAD, so the ciphertext length reveals only the
// bucket. It returns [ErrInvalidMessage] for content NewPlaintext would
// refuse. The result contains the message body; the caller should clear it
// after encryption.
func MarshalPaddedPlaintext(p Plaintext) ([]byte, error) {
	b, err := MarshalPlaintext(p)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	padded, err := padding.Pad(b)
	if err != nil {
		return nil, fmt.Errorf("e2e: padding plaintext: %w", err)
	}
	return padded, nil
}

// ParsePaddedPlaintext strips the padding of a decrypted plaintext with
// [padding.Unpad], which accepts only a bucket-sized input ending in the
// padding marker and zero bytes, and then decodes the rest like
// [ParsePlaintext]. It returns [ErrMalformed] for input above
// [MaxPaddedPlaintextSize], for invalid padding and for an invalid
// plaintext. The returned body does not alias b.
func ParsePaddedPlaintext(b []byte) (Plaintext, error) {
	if len(b) > MaxPaddedPlaintextSize {
		return Plaintext{}, fmt.Errorf("%w: padded plaintext of %d bytes exceeds %d", ErrMalformed, len(b), MaxPaddedPlaintextSize)
	}
	unpadded, err := padding.Unpad(b)
	if err != nil {
		return Plaintext{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return ParsePlaintext(unpadded)
}

// ClockSkewed reports whether a sender's claimed send time differs from
// the local clock now by more than [ClockSkewTolerance]. Such messages
// should be flagged, not dropped: either clock may be wrong.
func ClockSkewed(sent, now time.Time) bool {
	skew := now.Sub(sent)
	return skew > ClockSkewTolerance || skew < -ClockSkewTolerance
}
