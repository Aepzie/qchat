package sealed

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/padding"
	"github.com/craguS/qchat/internal/protocol"
)

// Version is the envelope version this package produces and accepts.
// Version 1 carried the content unpadded and is rejected.
const Version = 2

// Size limits of envelopes, in bytes.
//
// The content inside the box is padded with package padding to one of the
// buckets from MinPaddedSize to MaxPaddedSize: 32, 64, 128 or 256 KiB. The
// floor of 32 KiB is larger than the session Init (about 13 KiB for a
// typical bundle, at most handshake.MaxInitSize) plus the ratchet header
// and a small padded body, so the relay cannot tell a first message,
// which carries an Init, from a later one, nor read the CBOR width of the
// header counters or the one-time prekey ID. An envelope is therefore
// exactly one of four sizes: the bucket plus MaxOverhead, minus two bytes
// for the 32 KiB bucket, whose box length needs a shorter CBOR header.
const (
	// MinPaddedSize is the smallest padded content.
	MinPaddedSize = 32 << 10
	// MaxPaddedSize is the largest padded content.
	MaxPaddedSize = 256 << 10
	// MaxOverhead is how many bytes the envelope adds to the padded
	// content at most: the HPKE encapsulation and tag and the CBOR framing
	// of the outer map.
	MaxOverhead = sealbox.Overhead + 9
	// MaxEnvelopeSize is the largest envelope Seal produces and Open
	// accepts. It is below protocol.MaxPayloadSize; relays must allow
	// messages of this size (the default limits.max_message_size does).
	MaxEnvelopeSize = MaxPaddedSize + MaxOverhead
	// contentOverhead is the CBOR framing of a content whose inner payload
	// is at least 64 KiB: map header, two keys, the 32-byte sender ID with
	// its header and the five-byte header of the inner payload.
	contentOverhead = 1 + 1 + 2 + identity.IDSize + 1 + 5
	// MaxInnerSize is the largest inner payload Seal accepts: its content
	// and the padding marker must fit in MaxPaddedSize.
	MaxInnerSize = MaxPaddedSize - 1 - contentOverhead
)

// The envelope must fit in every relay payload.
var _ [protocol.MaxPayloadSize - MaxEnvelopeSize]struct{}

// infoLabel starts the HPKE info string; the recipient ID follows it.
const infoLabel = "qchat/v1/sealed"

// envelopePrefix is how every envelope starts: a map of two pairs (0xa2)
// whose key 1 holds Version and whose key 2 starts the box. It differs
// from the first bytes of pairwise (version 3, three or four pairs) and
// group (five pairs) envelopes, and from version 1 sealed envelopes.
var envelopePrefix = []byte{0xa2, 0x01, Version, 0x02}

// Errors returned by this package. Callers compare them with errors.Is.
var (
	// ErrMalformed reports an envelope or content that is not a valid,
	// canonical encoding, content that is not padded to one of the sealed
	// buckets, or field values out of range.
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
// must not be the zero ID. The content is padded to the smallest bucket
// between MinPaddedSize and MaxPaddedSize that holds it, so the result
// is at most MaxEnvelopeSize bytes long and reveals only that bucket.
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
	encoded, err := encMode.Marshal(content{Sender: sender[:], Inner: inner})
	if err != nil {
		return nil, fmt.Errorf("sealed: encode content: %w", err)
	}
	plaintext, err := padContent(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
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
	unpadded, err := unpadContent(plaintext)
	if err != nil {
		clear(plaintext)
		return Opened{}, fmt.Errorf("%w: content: %w", ErrMalformed, err)
	}
	var inside content
	if err := decodeCanonical(unpadded, &inside); err != nil {
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

// padContent pads encoded content with the scheme of package padding (a
// 0x80 marker, then zero bytes) to the smallest bucket of at least
// MinPaddedSize bytes that holds it and the marker. padding.Unpad strips
// it.
func padContent(encoded []byte) ([]byte, error) {
	size, err := padding.BucketFor(len(encoded))
	if err != nil || size > MaxPaddedSize {
		return nil, fmt.Errorf("%w: content of %d bytes does not fit", ErrInvalidArgument, len(encoded))
	}
	padded := make([]byte, max(size, MinPaddedSize))
	copy(padded, encoded)
	padded[len(encoded)] = paddingMarker
	return padded, nil
}

// paddingMarker is the first padding byte of package padding.
const paddingMarker = 0x80

// unpadContent strips the padding of a decrypted content. It accepts only
// a bucket between MinPaddedSize and MaxPaddedSize ending in valid
// padding.
func unpadContent(plaintext []byte) ([]byte, error) {
	if len(plaintext) < MinPaddedSize || len(plaintext) > MaxPaddedSize {
		return nil, fmt.Errorf("padded content is %d bytes, want %d to %d", len(plaintext), MinPaddedSize, MaxPaddedSize)
	}
	return padding.Unpad(plaintext)
}

// IsEnvelope reports whether b has the shape of a sealed envelope of this
// version, as opposed to a pairwise or group envelope. It inspects only the
// first bytes, which are identical for every envelope, and is meant for
// routing; a true result does not mean that b is well-formed.
func IsEnvelope(b []byte) bool {
	return bytes.HasPrefix(b, envelopePrefix)
}
