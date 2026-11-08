package sealed

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
)

// Version is the envelope version this package produces and accepts.
const Version = 1

// Size limits of envelopes, in bytes.
const (
	// MaxEnvelopeSize is the largest envelope Open accepts: the largest
	// payload the relay protocol carries.
	MaxEnvelopeSize = protocol.MaxPayloadSize
	// MaxOverhead bounds how many bytes Seal adds to the inner payload: the
	// HPKE encapsulation and tag, the sender ID and the CBOR framing of
	// both layers.
	MaxOverhead = sealbox.Overhead + 51
	// MaxInnerSize is the largest inner payload Seal accepts, so that every
	// envelope fits in MaxEnvelopeSize.
	MaxInnerSize = MaxEnvelopeSize - MaxOverhead
)

// infoLabel starts the HPKE info string; the recipient ID follows it.
const infoLabel = "qchat/v1/sealed"

// envelopePrefix is how every envelope starts: a map of two pairs (0xa2)
// whose key 1 holds Version and whose key 2 starts the box. It differs
// from the first bytes of pairwise (version 3, three or four pairs) and
// group (five pairs) envelopes.
var envelopePrefix = []byte{0xa2, 0x01, Version, 0x02}

// Errors returned by this package. Callers compare them with errors.Is.
var (
	// ErrMalformed reports an envelope or content that is not a valid,
	// canonical encoding, or field values out of range.
	ErrMalformed = errors.New("sealed: malformed envelope")
	// ErrUnsupportedVersion reports an envelope of another version.
	ErrUnsupportedVersion = errors.New("sealed: unsupported envelope version")
	// ErrDecrypt reports a box that does not open: modified, truncated,
	// sealed to another recipient or under another info string. The cases
	// are deliberately not distinguished.
	ErrDecrypt = errors.New("sealed: envelope does not open")
	// ErrInvalidArgument reports an argument of Seal outside its range.
	ErrInvalidArgument = errors.New("sealed: invalid argument")
)

// envelope is the outer, plaintext structure.
type envelope struct {
	Version uint8  `cbor:"1,keyasint"`
	Box     []byte `cbor:"2,keyasint"`
}

// content is the structure inside the box.
type content struct {
	Sender []byte `cbor:"1,keyasint"`
	Inner  []byte `cbor:"2,keyasint"`
}

// Recipient is the private side Open needs: the recipient's ID and the
// ability to open HPKE boxes sealed to its KEM key.
// *identity.Identity implements it.
type Recipient interface {
	ID() identity.ID
	OpenBox(info, box []byte) ([]byte, error)
}

// Opened is the result of [Open].
type Opened struct {
	// ClaimedSender is the sender ID found inside the envelope. It is not
	// authenticated: the caller must verify it by opening Inner with that
	// sender's session before trusting it.
	ClaimedSender identity.ID
	// Inner is the payload the sender sealed.
	Inner []byte
}

// info returns the HPKE info string binding a box to recipient.
func info(recipient identity.ID) []byte {
	return append([]byte(infoLabel), recipient[:]...)
}

// Seal wraps inner, sent by sender, for the identity of the verified bundle
// recipient. inner must hold between 1 and MaxInnerSize bytes and sender
// must not be the zero ID. The result is at most len(inner)+MaxOverhead
// bytes long.
func Seal(sender identity.ID, recipient *identity.Bundle, inner []byte) ([]byte, error) {
	if recipient == nil || recipient.KEMKey == nil {
		return nil, fmt.Errorf("%w: no recipient bundle", ErrInvalidArgument)
	}
	if sender.IsZero() {
		return nil, fmt.Errorf("%w: zero sender ID", ErrInvalidArgument)
	}
	if len(inner) == 0 || len(inner) > MaxInnerSize {
		return nil, fmt.Errorf("%w: inner payload is %d bytes, want 1 to %d", ErrInvalidArgument, len(inner), MaxInnerSize)
	}
	plaintext, err := encMode.Marshal(content{Sender: sender[:], Inner: inner})
	if err != nil {
		return nil, fmt.Errorf("sealed: encode content: %w", err)
	}
	defer clear(plaintext)
	box, err := sealbox.Seal(recipient.KEMKey, info(recipient.ID), plaintext)
	if err != nil {
		return nil, fmt.Errorf("sealed: %w", err)
	}
	out, err := encMode.Marshal(envelope{Version: Version, Box: box})
	if err != nil {
		return nil, fmt.Errorf("sealed: encode envelope: %w", err)
	}
	return out, nil
}

// Open decrypts an envelope sealed to recipient and returns the claimed
// sender and the inner payload. It fails with ErrMalformed,
// ErrUnsupportedVersion or ErrDecrypt, or with the recipient's own error if
// it can no longer open boxes (identity.ErrDestroyed).
//
// The claimed sender is not authenticated; see the package documentation.
func Open(recipient Recipient, sealed []byte) (Opened, error) {
	if recipient == nil {
		return Opened{}, fmt.Errorf("%w: no recipient", ErrInvalidArgument)
	}
	if len(sealed) == 0 || len(sealed) > MaxEnvelopeSize {
		return Opened{}, fmt.Errorf("%w: envelope is %d bytes, want 1 to %d", ErrMalformed, len(sealed), MaxEnvelopeSize)
	}
	var outer envelope
	if err := decodeCanonical(sealed, &outer); err != nil {
		if version, ok := peekVersion(sealed); ok && version != Version {
			return Opened{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
		}
		return Opened{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if outer.Version != Version {
		return Opened{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, outer.Version)
	}
	if len(outer.Box) < sealbox.Overhead {
		return Opened{}, ErrDecrypt
	}
	plaintext, err := recipient.OpenBox(info(recipient.ID()), outer.Box)
	if errors.Is(err, identity.ErrDestroyed) {
		return Opened{}, err
	}
	if err != nil {
		return Opened{}, ErrDecrypt
	}
	var inside content
	if err := decodeCanonical(plaintext, &inside); err != nil {
		clear(plaintext)
		return Opened{}, fmt.Errorf("%w: content: %w", ErrMalformed, err)
	}
	if len(inside.Sender) != identity.IDSize {
		clear(plaintext)
		return Opened{}, fmt.Errorf("%w: sender ID is %d bytes", ErrMalformed, len(inside.Sender))
	}
	sender := identity.ID(inside.Sender)
	if sender.IsZero() {
		clear(plaintext)
		return Opened{}, fmt.Errorf("%w: zero sender ID", ErrMalformed)
	}
	if len(inside.Inner) == 0 {
		clear(plaintext)
		return Opened{}, fmt.Errorf("%w: empty inner payload", ErrMalformed)
	}
	return Opened{ClaimedSender: sender, Inner: inside.Inner}, nil
}

// IsEnvelope reports whether b has the shape of a sealed envelope of this
// version, as opposed to a pairwise or group envelope. It inspects only the
// first bytes, which are identical for every envelope, and is meant for
// routing; a true result does not mean that b is well-formed.
func IsEnvelope(b []byte) bool {
	return bytes.HasPrefix(b, envelopePrefix)
}
