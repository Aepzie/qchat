package sealbox

import (
	"crypto/hpke"
	"crypto/subtle"
	"errors"
	"fmt"
)

// Sizes of the encodings handled by this package, in bytes.
const (
	// PublicKeySize is the size of a serialised MLKEM768-X25519 public key:
	// the ML-KEM-768 encapsulation key (1184) followed by the X25519 public
	// key (32).
	PublicKeySize = 1216

	// PrivateKeySize is the size of a serialised private key. For X-Wing,
	// SerializePrivateKey outputs the 32-byte seed from which both component
	// keys are expanded.
	PrivateKeySize = 32

	// EncapsulatedKeySize is the size of the KEM encapsulation at the start
	// of every sealed box: the ML-KEM-768 ciphertext (1088) followed by the
	// ephemeral X25519 public key (32).
	EncapsulatedKeySize = 1120

	// TagSize is the size of the ChaCha20-Poly1305 authentication tag.
	TagSize = 16

	// Overhead is how many bytes [Seal] adds to the plaintext.
	Overhead = EncapsulatedKeySize + TagSize
)

// HPKE algorithm identifiers of the fixed suite (RFC 9180 registry values).
const (
	KEMID  uint16 = 0x647a
	KDFID  uint16 = 0x0001
	AEADID uint16 = 0x0003
)

// Errors returned by this package. Callers should compare with [errors.Is].
var (
	// ErrInvalidInfo reports an empty info string. An empty info string would
	// mean the box is not bound to any context, so it is always refused.
	ErrInvalidInfo = errors.New("sealbox: info must not be empty")

	// ErrInvalidPublicKey reports a public key of the wrong length or one the
	// KEM rejects.
	ErrInvalidPublicKey = errors.New("sealbox: invalid public key")

	// ErrInvalidPrivateKey reports a private key of the wrong length or one
	// the KEM rejects, or use of a key after [PrivateKey.Destroy].
	ErrInvalidPrivateKey = errors.New("sealbox: invalid private key")

	// ErrDecrypt reports that a box could not be opened: it was truncated or
	// modified, sealed to another key, or sealed under a different info
	// string. These cases are deliberately not distinguished.
	ErrDecrypt = errors.New("sealbox: message authentication failed")
)

var (
	kem  = hpke.MLKEM768X25519()
	kdf  = hpke.HKDFSHA256()
	aead = hpke.ChaCha20Poly1305()
)

// PrivateKey is an MLKEM768-X25519 decryption key.
//
// A PrivateKey is safe for concurrent use by multiple goroutines, except that
// [PrivateKey.Destroy] must not run concurrently with any other method.
type PrivateKey struct {
	seed   [PrivateKeySize]byte
	key    hpke.PrivateKey
	public *PublicKey
}

// PublicKey is an MLKEM768-X25519 encryption key. It is immutable and safe
// for concurrent use.
type PublicKey struct {
	encoding []byte
	key      hpke.PublicKey
}

// GenerateKey returns a new random private key.
func GenerateKey() (*PrivateKey, error) {
	key, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("sealbox: generating key: %w", err)
	}
	seed, err := key.Bytes()
	if err != nil {
		return nil, fmt.Errorf("sealbox: serialising key: %w", err)
	}
	defer clear(seed)
	return NewPrivateKey(seed)
}

// NewPrivateKey deserialises a private key produced by [PrivateKey.Bytes]
// (RFC 9180 DeserializePrivateKey). The input must be exactly
// [PrivateKeySize] bytes and is copied.
//
// This is the persistence path: NewPrivateKey(k.Bytes()) yields the same key
// as k. It must not be confused with HPKE DeriveKeyPair, which treats its
// input as keying material to be hashed and would yield a different key.
func NewPrivateKey(encoding []byte) (*PrivateKey, error) {
	if len(encoding) != PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	key, err := kem.NewPrivateKey(encoding)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	public, err := newPublicKey(key.PublicKey())
	if err != nil {
		return nil, err
	}
	priv := &PrivateKey{key: key, public: public}
	copy(priv.seed[:], encoding)
	return priv, nil
}

// Bytes returns the [PrivateKeySize]-byte serialisation of k (RFC 9180
// SerializePrivateKey). This is the complete private key; store it only in
// encrypted form and clear the returned copy after use. Bytes returns nil
// after [PrivateKey.Destroy].
func (k *PrivateKey) Bytes() []byte {
	if k.key == nil {
		return nil
	}
	return append([]byte(nil), k.seed[:]...)
}

// Public returns the public key corresponding to k. It remains usable after
// [PrivateKey.Destroy].
func (k *PrivateKey) Public() *PublicKey {
	return k.public
}

// Destroy clears the serialised seed held by k and makes every later [Open]
// with k fail. This is best effort: the expanded key inside crypto/hpke is
// only dropped for the garbage collector, and the Go runtime may hold other
// copies. Destroy must not run concurrently with other uses of k.
func (k *PrivateKey) Destroy() {
	clear(k.seed[:])
	k.key = nil
}

// ParsePublicKey deserialises a public key produced by [PublicKey.Bytes]
// (RFC 9180 DeserializePublicKey). The input must be exactly [PublicKeySize]
// bytes and is copied.
func ParsePublicKey(encoding []byte) (*PublicKey, error) {
	if len(encoding) != PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	key, err := kem.NewPublicKey(encoding)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	return newPublicKey(key)
}

func newPublicKey(key hpke.PublicKey) (*PublicKey, error) {
	encoding := key.Bytes()
	if len(encoding) != PublicKeySize || key.KEM().ID() != KEMID {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKey{encoding: append([]byte(nil), encoding...), key: key}, nil
}

// Bytes returns the [PublicKeySize]-byte serialisation of p. The returned
// slice is a copy.
func (p *PublicKey) Bytes() []byte {
	return append([]byte(nil), p.encoding...)
}

// Equal reports whether p and other have the same encoding. A nil key equals
// only another nil key.
func (p *PublicKey) Equal(other *PublicKey) bool {
	if p == nil || other == nil {
		return p == other
	}
	return subtle.ConstantTimeCompare(p.encoding, other.encoding) == 1
}

// Seal encrypts plaintext to pub. The info string binds the box to its
// purpose and participants (Phase 2 uses "qchat/v1/message" || From || To)
// and must be passed unchanged to [Open]. info must not be empty.
//
// The result is [Overhead] bytes longer than plaintext.
func Seal(pub *PublicKey, info, plaintext []byte) ([]byte, error) {
	if pub == nil {
		return nil, ErrInvalidPublicKey
	}
	if len(info) == 0 {
		return nil, ErrInvalidInfo
	}
	box, err := hpke.Seal(pub.key, kdf, aead, info, plaintext)
	if err != nil {
		return nil, fmt.Errorf("sealbox: sealing: %w", err)
	}
	return box, nil
}

// Open decrypts a box produced by [Seal] for the public key of priv under the
// same info string. On any failure it returns nil and an error, never partial
// plaintext; authentication failures are all reported as [ErrDecrypt].
func Open(priv *PrivateKey, info, box []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, ErrInvalidPrivateKey
	}
	if len(info) == 0 {
		return nil, ErrInvalidInfo
	}
	if len(box) < Overhead {
		return nil, ErrDecrypt
	}
	plaintext, err := hpke.Open(priv.key, kdf, aead, info, box)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
