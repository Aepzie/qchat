package sealed

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// Sizes of access keys and verifiers, in bytes.
const (
	// AccessKeySize is the size of an [AccessKey].
	AccessKeySize = 16
	// VerifierSize is the size of an access verifier, and of the access
	// proof a sealed sender presents. It equals
	// protocol.AccessVerifierSize.
	VerifierSize = sha256.Size
)

// verifierLabel is the HMAC message that derives a verifier from an access
// key.
const verifierLabel = "qchat/v1/access-verifier"

// AccessKey is a user's secret for unidentified delivery. Whoever knows it
// can send sealed messages to the user through the relay. The zero value
// is not a valid key.
type AccessKey [AccessKeySize]byte

// NewAccessKey returns a fresh random access key.
func NewAccessKey() (AccessKey, error) {
	var key AccessKey
	if _, err := rand.Read(key[:]); err != nil {
		return AccessKey{}, fmt.Errorf("sealed: generate access key: %w", err)
	}
	return key, nil
}

// ParseAccessKey returns the access key encoded in b, which must be exactly
// AccessKeySize bytes and not all zero.
func ParseAccessKey(b []byte) (AccessKey, error) {
	if len(b) != AccessKeySize {
		return AccessKey{}, fmt.Errorf("%w: access key is %d bytes, want %d", ErrMalformed, len(b), AccessKeySize)
	}
	key := AccessKey(b)
	if key.IsZero() {
		return AccessKey{}, fmt.Errorf("%w: access key is zero", ErrMalformed)
	}
	return key, nil
}

// IsZero reports whether k is the zero value, in constant time.
func (k AccessKey) IsZero() bool {
	return subtle.ConstantTimeCompare(k[:], make([]byte, AccessKeySize)) == 1
}

// Verifier returns HMAC-SHA256(k, "qchat/v1/access-verifier"). The owner of
// k uploads it to the relay with protocol.SetAccessKey, and senders who
// know k present it as the access proof of their sealed sends.
func (k AccessKey) Verifier() [VerifierSize]byte {
	mac := hmac.New(sha256.New, k[:])
	mac.Write([]byte(verifierLabel))
	return [VerifierSize]byte(mac.Sum(nil))
}
