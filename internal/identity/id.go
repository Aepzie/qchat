package identity

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"

	"github.com/Aepzie/qchat/internal/crypto/hybridsig"
	"github.com/Aepzie/qchat/internal/protocol"
)

// Parameters of the textual ID format.
const (
	// IDSize is the length of an ID in bytes.
	IDSize = protocol.IDSize

	// IDPrefix starts the single-string form of an ID. The "1" is the format
	// version; it can never be confused with ID characters because the
	// base32 alphabet has no digit 1.
	IDPrefix = "qc1-"

	// idChars is the number of base32 characters of an ID: 256 bits in
	// 5-bit characters, rounded up. The last character carries 4 padding
	// bits, which must be zero.
	idChars = 52

	// idGroupSize is the number of characters per displayed group.
	idGroupSize = 4

	// shortGroups is the number of groups shown by [ID.ShortString].
	shortGroups = 3

	// maxIDInput bounds the input accepted by [ParseID], so that hostile
	// input cannot make it do unbounded work.
	maxIDInput = 256
)

// idDomain prefixes the hash input of every ID. It ties IDs to this
// construction and version, so the hash of a signing key computed for any
// other purpose can never collide with an ID by construction.
const idDomain = "qchat-identity-v1"

// ErrInvalidID reports a string that is not a well-formed ID.
var ErrInvalidID = errors.New("identity: invalid ID")

// idEncoding is RFC 4648 base32 without padding, lowercased on output.
var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ID names an identity. It is the SHA-256 hash of the identity's hybrid
// signing public key (see [IDFromSigningKey]), so it commits to the signing
// keys: nobody, the relay included, can present a different signing key for
// an ID without breaking SHA-256 second-preimage resistance.
//
// The zero ID is never the ID of a real identity and is used as "no ID".
type ID [IDSize]byte

// IDFromSigningKey computes the ID of the identity whose hybrid signing
// public key is pub:
//
//	ID = SHA-256("qchat-identity-v1" || pub.Bytes())
//
// It panics if pub is nil.
func IDFromSigningKey(pub *hybridsig.PublicKey) ID {
	h := sha256.New()
	h.Write([]byte(idDomain))
	h.Write(pub.Bytes())
	var id ID
	h.Sum(id[:0])
	return id
}

// IsZero reports whether id is the zero ID.
func (id ID) IsZero() bool {
	return id == ID{}
}

// String returns the canonical textual form of id: [IDPrefix] followed by
// the 52 lowercase base32 characters (RFC 4648 alphabet, no padding) in
// groups of four separated by "-", for example
// "qc1-abcd-efgh-...-wxy2". [ParseID] accepts this form.
func (id ID) String() string {
	return IDPrefix + grouped(compact(id))
}

// ShortString returns [IDPrefix] and the first three groups of the textual
// form (60 bits), for example "qc1-abcd-efgh-ijkl". It is a display hint to
// tell contacts apart in a user interface. It is far too short to identify
// anybody securely: never use it to look up, compare or verify identities;
// use the full ID or the safety number for that.
func (id ID) ShortString() string {
	return IDPrefix + grouped(compact(id)[:shortGroups*idGroupSize])
}

// compact returns the 52 lowercase base32 characters of id.
func compact(id ID) string {
	return strings.ToLower(idEncoding.EncodeToString(id[:]))
}

// grouped inserts "-" after every idGroupSize characters of s.
func grouped(s string) string {
	var sb strings.Builder
	sb.Grow(len(s) + len(s)/idGroupSize)
	for i := 0; i < len(s); i += idGroupSize {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(s[i:min(i+idGroupSize, len(s))])
	}
	return sb.String()
}

// ParseID parses the textual form of an ID as produced by [ID.String]. It is
// lenient about presentation and strict about content:
//
//   - the "qc1" prefix is optional and may be in any case;
//   - letters may be in any case;
//   - "-", spaces, tabs and line breaks anywhere are ignored, so IDs
//     copied from a grouped display, split across lines or typed without
//     separators are all accepted;
//   - after removing those, exactly 52 characters of the base32 alphabet
//     (a-z, 2-7) must remain, and the 4 unused bits of the last character
//     must be zero.
//
// The last rule makes the textual form canonical: every ID has exactly one
// compact spelling, so two different strings that both parse can never name
// different IDs by accident of encoding. Any non-ASCII character is
// rejected; in particular, Unicode characters whose lowercase form is an
// ASCII letter (such as KELVIN SIGN, U+212A) are not folded, so look-alike
// spellings cannot be smuggled in.
//
// ParseID returns [ErrInvalidID] for anything else.
func ParseID(s string) (ID, error) {
	if len(s) > maxIDInput {
		return ID{}, ErrInvalidID
	}
	normalized := make([]byte, 0, idChars+len("qc1"))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n':
			continue
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case c >= 0x80:
			return ID{}, ErrInvalidID
		}
		normalized = append(normalized, c)
	}
	body, _ := strings.CutPrefix(string(normalized), "qc1")
	if len(body) != idChars {
		return ID{}, ErrInvalidID
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return ID{}, ErrInvalidID
		}
	}

	// The alphabet check above matters: encoding/base32 silently skips
	// '\r' and '\n', so it must never see anything but alphabet characters.
	raw, err := idEncoding.DecodeString(strings.ToUpper(body))
	if err != nil || len(raw) != IDSize {
		return ID{}, ErrInvalidID
	}
	var id ID
	copy(id[:], raw)

	// Re-encoding rejects non-zero padding bits, which the decoder ignores
	// and which would otherwise give every ID 16 different spellings.
	if compact(id) != body {
		return ID{}, ErrInvalidID
	}
	return id, nil
}
