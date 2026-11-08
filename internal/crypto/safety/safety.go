package safety

import (
	"bytes"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// Parameters of the safety number format.
const (
	// IDSize is the size of a qchat identity ID.
	IDSize = 32

	// FingerprintSize is the number of hash bytes kept per party.
	FingerprintSize = 30

	// Iterations is the number of SHA-512 rounds per fingerprint.
	Iterations = 5200

	// Digits is the length of a safety number.
	Digits = 60

	// GroupSize is the number of digits per displayed group.
	GroupSize = 5

	// Groups is the number of displayed groups in a safety number.
	Groups = Digits / GroupSize

	// QRPrefix starts every QR payload; the "1" is the payload version.
	QRPrefix = "qchat-verify:1:"
)

// fingerprintVersion is the 16-bit version prefix of the hash input. Signal
// uses 0 for its displayable fingerprints and so does the qchat spec.
const fingerprintVersion = 0

// ErrInvalidQRPayload reports a QR payload that is not in the canonical
// format produced by [QRPayload].
var ErrInvalidQRPayload = errors.New("safety: invalid QR payload")

// Fingerprint returns the 30-byte fingerprint of one party: the first
// [FingerprintSize] bytes of SHA-512 iterated [Iterations] times as described
// in the package documentation. publicKey is the party's hybrid signature
// public key encoding.
func Fingerprint(id [IDSize]byte, publicKey []byte) [FingerprintSize]byte {
	return iteratedFingerprint(publicKey, id[:])
}

// iteratedFingerprint implements Signal's NumericFingerprintGenerator hash
// for one party. The initial buffer is the version, key and identifier
// concatenated (not yet hashed); every round then hashes the previous buffer
// followed by the public key again. Re-feeding the key in every round is part
// of Signal's design and keeps every iteration bound to the key.
func iteratedFingerprint(publicKey, identifier []byte) [FingerprintSize]byte {
	buf := make([]byte, 0, 2+len(publicKey)+len(identifier))
	buf = binary.BigEndian.AppendUint16(buf, fingerprintVersion)
	buf = append(buf, publicKey...)
	buf = append(buf, identifier...)

	h := sha512.New()
	for range Iterations {
		h.Reset()
		h.Write(buf)
		h.Write(publicKey)
		buf = h.Sum(buf[:0])
	}

	var out [FingerprintSize]byte
	copy(out[:], buf)
	return out
}

// digits renders a fingerprint as 30 decimal digits: six 5-byte big-endian
// chunks, each reduced modulo 100000 and zero-padded to 5 digits. The modular
// reduction of a 40-bit value has a negligible bias (2^40 is about
// 11 million times 100000).
func digits(fp [FingerprintSize]byte) string {
	var sb strings.Builder
	sb.Grow(FingerprintSize)
	for chunk := 0; chunk < FingerprintSize; chunk += 5 {
		var v uint64
		for _, b := range fp[chunk : chunk+5] {
			v = v<<8 | uint64(b)
		}
		v %= 100000
		var group [GroupSize]byte
		for i := GroupSize - 1; i >= 0; i-- {
			group[i] = byte('0' + v%10)
			v /= 10
		}
		sb.Write(group[:])
	}
	return sb.String()
}

// Number returns the 60-digit safety number of the conversation between two
// parties, without separators. The arguments may be given in either order:
// the half belonging to the lexicographically smaller ID always comes first,
// so both participants obtain the same string. Use [Grouped] for display.
func Number(idA [IDSize]byte, pubA []byte, idB [IDSize]byte, pubB []byte) string {
	first, second := canonicalHalves(idA, pubA, idB, pubB)
	return first + second
}

// canonicalHalves returns the two 30-digit halves in canonical order. When
// both IDs are equal (which happens only if a client compares an identity
// with itself) the halves are ordered by their digits, so the result is
// still independent of argument order.
func canonicalHalves(idA [IDSize]byte, pubA []byte, idB [IDSize]byte, pubB []byte) (string, string) {
	a := digits(Fingerprint(idA, pubA))
	b := digits(Fingerprint(idB, pubB))
	switch c := bytes.Compare(idA[:], idB[:]); {
	case c < 0:
		return a, b
	case c > 0:
		return b, a
	case a <= b:
		return a, b
	default:
		return b, a
	}
}

// Grouped formats a safety number for display as groups of [GroupSize]
// digits separated by single spaces ("12345 67890 ..."). Whitespace already
// present in the input is removed first, so Grouped is idempotent. It only
// formats; it does not validate the input.
func Grouped(number string) string {
	compact := stripSpace(number)
	var sb strings.Builder
	sb.Grow(len(compact) + len(compact)/GroupSize)
	for i := 0; i < len(compact); i += GroupSize {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(compact[i:min(i+GroupSize, len(compact))])
	}
	return sb.String()
}

// EqualNumbers reports whether two safety numbers are the same, ignoring
// spaces, tabs and line breaks (so a grouped number equals its compact form).
// Both inputs must contain exactly [Digits] decimal digits after removing
// whitespace; anything else compares unequal. The digit comparison runs in
// constant time.
func EqualNumbers(a, b string) bool {
	na, nb := stripSpace(a), stripSpace(b)
	if !isNumber(na) || !isNumber(nb) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(na), []byte(nb)) == 1
}

// QRPayload returns the string to encode in the verification QR code:
// "qchat-verify:1:<smaller ID hex>:<larger ID hex>:<60 digits>". Like
// [Number] it is independent of argument order.
func QRPayload(idA [IDSize]byte, pubA []byte, idB [IDSize]byte, pubB []byte) string {
	first, second := idA, idB
	if bytes.Compare(idA[:], idB[:]) > 0 {
		first, second = idB, idA
	}
	return QRPrefix + hex.EncodeToString(first[:]) + ":" + hex.EncodeToString(second[:]) + ":" +
		Number(idA, pubA, idB, pubB)
}

// VerifyQRPayload reports whether a scanned QR payload is exactly the payload
// expected for these two parties (in either argument order). The comparison
// runs in constant time.
func VerifyQRPayload(scanned string, idA [IDSize]byte, pubA []byte, idB [IDSize]byte, pubB []byte) bool {
	expected := QRPayload(idA, pubA, idB, pubB)
	return subtle.ConstantTimeCompare([]byte(scanned), []byte(expected)) == 1
}

// ParseQRPayload splits a scanned payload into its two IDs (in canonical
// order) and the 60-digit number. It accepts only the exact canonical form
// produced by [QRPayload]: lowercase hex, the smaller ID first, no extra
// characters. It lets a client explain a mismatch (for example "this code is
// for a different contact"); to decide whether a contact is verified, use
// [VerifyQRPayload].
func ParseQRPayload(payload string) (first, second [IDSize]byte, number string, err error) {
	rest, ok := strings.CutPrefix(payload, QRPrefix)
	if !ok {
		return first, second, "", ErrInvalidQRPayload
	}
	parts := strings.SplitN(rest, ":", 4)
	if len(parts) != 3 || !decodeID(parts[0], &first) || !decodeID(parts[1], &second) || !isNumber(parts[2]) {
		return [IDSize]byte{}, [IDSize]byte{}, "", ErrInvalidQRPayload
	}
	if bytes.Compare(first[:], second[:]) > 0 {
		return [IDSize]byte{}, [IDSize]byte{}, "", ErrInvalidQRPayload
	}
	return first, second, parts[2], nil
}

func decodeID(s string, id *[IDSize]byte) bool {
	if len(s) != 2*IDSize || strings.ToLower(s) != s {
		return false
	}
	n, err := hex.Decode(id[:], []byte(s))
	return err == nil && n == IDSize
}

func isNumber(s string) bool {
	if len(s) != Digits {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
}
