package transport

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Fingerprint is the SHA-256 hash of a certificate's DER-encoded
// SubjectPublicKeyInfo (an "SPKI pin").
//
// Pinning the public key rather than the whole certificate means the server
// can re-issue its certificate (new validity dates, new hostnames) without
// breaking clients, as long as it keeps the same key pair.
type Fingerprint [32]byte

// fingerprintPrefix names the hash algorithm in the textual form so the
// format can be extended later without ambiguity.
const fingerprintPrefix = "sha256:"

// maxFingerprintInput bounds the input accepted by ParseFingerprint. The
// longest legitimate form (prefix plus 32 colon-separated byte pairs, with
// some surrounding whitespace) is far below this limit.
const maxFingerprintInput = 512

// errInvalidFingerprint is wrapped by every ParseFingerprint error.
var errInvalidFingerprint = errors.New("transport: invalid fingerprint")

// FingerprintOf returns the SPKI fingerprint of cert. A nil certificate
// yields the zero Fingerprint, which is never accepted as a pin.
func FingerprintOf(cert *x509.Certificate) Fingerprint {
	if cert == nil {
		return Fingerprint{}
	}
	return Fingerprint(sha256.Sum256(cert.RawSubjectPublicKeyInfo))
}

// FingerprintOfTLS returns the SPKI fingerprint of the leaf certificate of a
// tls.Certificate. If cert.Leaf is nil, the first DER certificate in the
// chain is parsed.
func FingerprintOfTLS(cert tls.Certificate) (Fingerprint, error) {
	if cert.Leaf != nil {
		return FingerprintOf(cert.Leaf), nil
	}
	if len(cert.Certificate) == 0 {
		return Fingerprint{}, errors.New("transport: certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return Fingerprint{}, fmt.Errorf("transport: parse leaf certificate: %w", err)
	}
	return FingerprintOf(leaf), nil
}

// String returns the canonical form: "sha256:" followed by 64 lowercase hex
// digits. This is the form to store in configuration files.
func (f Fingerprint) String() string {
	return fingerprintPrefix + hex.EncodeToString(f[:])
}

// Grouped returns the fingerprint as 16 groups of 4 lowercase hex digits
// separated by single spaces. It is meant for humans comparing a fingerprint
// over a separate channel (in person, by phone, on a printed card).
// ParseFingerprint accepts this form.
func (f Fingerprint) Grouped() string {
	digits := hex.EncodeToString(f[:])
	var b strings.Builder
	b.Grow(len(digits) + len(digits)/4)
	for i := 0; i < len(digits); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(digits[i : i+4])
	}
	return b.String()
}

// Equal reports whether f and o are identical. The comparison runs in
// constant time so that timing does not reveal how many leading bytes of a
// candidate fingerprint matched.
func (f Fingerprint) Equal(o Fingerprint) bool {
	return subtle.ConstantTimeCompare(f[:], o[:]) == 1
}

// IsZero reports whether f is the zero value, meaning "no pin configured".
// A zero fingerprint is never accepted as a trust anchor.
func (f Fingerprint) IsZero() bool {
	return f.Equal(Fingerprint{})
}

// ParseFingerprint parses a fingerprint written by String or Grouped, or in
// the common colon-separated style ("AB:CD:..."). Parsing is lenient about
// presentation but strict about content:
//
//   - the "sha256:" prefix is optional and matched case-insensitively;
//   - hex digits may be upper or lower case;
//   - spaces, tabs, line breaks and ':' separators are ignored;
//   - exactly 64 hex digits (32 bytes) must remain, and nothing else;
//   - the all-zero value is rejected because it means "no pin".
func ParseFingerprint(s string) (Fingerprint, error) {
	if len(s) > maxFingerprintInput {
		return Fingerprint{}, fmt.Errorf("%w: input longer than %d bytes", errInvalidFingerprint, maxFingerprintInput)
	}
	s = strings.TrimSpace(s)
	if hasASCIIPrefixFold(s, fingerprintPrefix) {
		s = s[len(fingerprintPrefix):]
	}

	var digits [2 * len(Fingerprint{})]byte
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isFingerprintSeparator(c) {
			continue
		}
		if !isHexDigit(c) {
			return Fingerprint{}, fmt.Errorf("%w: unexpected character at offset %d", errInvalidFingerprint, i)
		}
		if n == len(digits) {
			return Fingerprint{}, fmt.Errorf("%w: more than %d hex digits", errInvalidFingerprint, len(digits))
		}
		digits[n] = c
		n++
	}
	if n != len(digits) {
		return Fingerprint{}, fmt.Errorf("%w: got %d hex digits, want %d", errInvalidFingerprint, n, len(digits))
	}

	var f Fingerprint
	if _, err := hex.Decode(f[:], digits[:]); err != nil {
		return Fingerprint{}, fmt.Errorf("%w: %v", errInvalidFingerprint, err)
	}
	if f.IsZero() {
		return Fingerprint{}, fmt.Errorf("%w: all-zero fingerprint", errInvalidFingerprint)
	}
	return f, nil
}

// hasASCIIPrefixFold reports whether s starts with prefix, ignoring ASCII
// case only. Unicode case folding is deliberately not applied so that
// look-alike characters cannot be mistaken for the prefix.
func hasASCIIPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if asciiLower(s[i]) != asciiLower(prefix[i]) {
			return false
		}
	}
	return true
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isFingerprintSeparator(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', ':':
		return true
	}
	return false
}
