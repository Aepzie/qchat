package hybridsig

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
)

// Sizes of the encodings handled by this package, in bytes.
const (
	// SeedSize is the size of each of the two component seeds that make up a
	// private key: the Ed25519 seed (RFC 8032) and the ML-DSA-65 seed ξ
	// (FIPS 204). The complete private key is therefore 2*SeedSize bytes.
	SeedSize = 32

	// PublicKeySize is the size of an encoded hybrid public key: the Ed25519
	// public key followed by the ML-DSA-65 public key.
	PublicKeySize = ed25519.PublicKeySize + mldsa.MLDSA65PublicKeySize

	// SignatureSize is the size of an encoded hybrid signature: the Ed25519
	// signature followed by the ML-DSA-65 signature.
	SignatureSize = ed25519.SignatureSize + mldsa.MLDSA65SignatureSize

	// MaxContextSize is the longest context label accepted. It is the limit
	// imposed by both the one-byte length prefix in M' and the FIPS 204
	// context string.
	MaxContextSize = 255
)

// domainPrefix starts every message signed by this package. It pins the
// scheme and its version, so signatures produced here can never be confused
// with signatures of any other construction using the same keys.
const domainPrefix = "qchat-hybridsig-v1"

// Errors returned by this package. Callers should compare with [errors.Is].
var (
	// ErrInvalidContext reports a context label that is empty, longer than
	// [MaxContextSize] bytes or contains characters other than printable
	// ASCII.
	ErrInvalidContext = errors.New("hybridsig: invalid context label")

	// ErrInvalidPublicKey reports a public key encoding of the wrong length or
	// one that the ML-DSA-65 decoder rejects.
	ErrInvalidPublicKey = errors.New("hybridsig: invalid public key")

	// ErrInvalidSeed reports a seed of the wrong length.
	ErrInvalidSeed = errors.New("hybridsig: invalid seed")

	// ErrInvalidSignature reports a signature that has the wrong length or for
	// which at least one component fails to verify. Which component failed is
	// deliberately not revealed.
	ErrInvalidSignature = errors.New("hybridsig: invalid signature")

	// ErrDestroyed reports use of a private key after [PrivateKey.Destroy].
	ErrDestroyed = errors.New("hybridsig: private key has been destroyed")
)

// PrivateKey is a hybrid signing key: an Ed25519 key and an ML-DSA-65 key,
// both expanded from 32-byte seeds.
//
// A PrivateKey is safe for concurrent use by multiple goroutines, except that
// [PrivateKey.Destroy] must not run concurrently with any other method.
type PrivateKey struct {
	edSeed    [SeedSize]byte
	mldsaSeed [SeedSize]byte
	ed        ed25519.PrivateKey
	mldsa     *mldsa.PrivateKey
	public    *PublicKey
	destroyed bool
}

// PublicKey is a hybrid verification key. It is immutable and safe for
// concurrent use.
type PublicKey struct {
	encoding []byte
	ed       ed25519.PublicKey
	mldsa    *mldsa.PublicKey
}

// GenerateKey returns a new private key whose two seeds are drawn
// independently from crypto/rand.
func GenerateKey() (*PrivateKey, error) {
	var edSeed, mldsaSeed [SeedSize]byte
	defer clear(edSeed[:])
	defer clear(mldsaSeed[:])
	if _, err := rand.Read(edSeed[:]); err != nil {
		return nil, fmt.Errorf("hybridsig: reading randomness: %w", err)
	}
	if _, err := rand.Read(mldsaSeed[:]); err != nil {
		return nil, fmt.Errorf("hybridsig: reading randomness: %w", err)
	}
	return NewPrivateKeyFromSeeds(edSeed[:], mldsaSeed[:])
}

// NewPrivateKeyFromSeeds reconstructs a private key from the two seeds
// returned by [PrivateKey.Seeds]. Both seeds must be exactly [SeedSize] bytes.
// Key expansion is deterministic, so the same seeds always yield the same
// public key. The seeds are copied; the caller may erase its own copies
// afterwards.
//
// The seeds must come from a cryptographically secure random source (as in
// [GenerateKey]) and must be independent of each other; deriving one from the
// other would couple the security of the two components.
func NewPrivateKeyFromSeeds(edSeed, mldsaSeed []byte) (*PrivateKey, error) {
	if len(edSeed) != SeedSize || len(mldsaSeed) != SeedSize {
		return nil, ErrInvalidSeed
	}
	mlKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), mldsaSeed)
	if err != nil {
		return nil, fmt.Errorf("hybridsig: expanding ML-DSA-65 seed: %w", err)
	}
	edKey := ed25519.NewKeyFromSeed(edSeed)

	edPublic, ok := edKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("hybridsig: unexpected Ed25519 public key type")
	}
	public, err := newPublicKey(edPublic, mlKey.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}

	priv := &PrivateKey{ed: edKey, mldsa: mlKey, public: public}
	copy(priv.edSeed[:], edSeed)
	copy(priv.mldsaSeed[:], mldsaSeed)
	return priv, nil
}

// Seeds returns fresh copies of the Ed25519 seed and the ML-DSA-65 seed. They
// are the complete private key and must be stored only in encrypted form (see
// package internal/crypto/vault). The caller owns the returned slices and
// should clear them once they are no longer needed. Seeds returns nil slices
// after [PrivateKey.Destroy].
func (k *PrivateKey) Seeds() (edSeed, mldsaSeed []byte) {
	if k.destroyed {
		return nil, nil
	}
	return append([]byte(nil), k.edSeed[:]...), append([]byte(nil), k.mldsaSeed[:]...)
}

// Public returns the public key corresponding to k. It remains usable after
// [PrivateKey.Destroy], because it contains no secret material.
func (k *PrivateKey) Public() *PublicKey {
	return k.public
}

// Sign returns a hybrid signature of msg under the context label ctx.
//
// ctx names the purpose of the signature, for example "qchat/v1/bundle". It
// must be 1 to [MaxContextSize] bytes of printable ASCII and must be fixed per
// protocol use: the verifier passes the same label, and a signature made under
// one label never verifies under another.
//
// The ML-DSA-65 half is produced with hedged signing, which mixes fresh
// randomness into the per-signature nonce, so repeated calls return different
// signatures that all verify.
func (k *PrivateKey) Sign(ctx string, msg []byte) ([]byte, error) {
	if k.destroyed {
		return nil, ErrDestroyed
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	signed := signedMessage(ctx, msg)

	mlSig, err := k.mldsa.Sign(nil, signed, &mldsa.Options{Context: ctx})
	if err != nil {
		return nil, fmt.Errorf("hybridsig: ML-DSA-65 signing: %w", err)
	}
	if len(mlSig) != mldsa.MLDSA65SignatureSize {
		return nil, errors.New("hybridsig: unexpected ML-DSA-65 signature length")
	}

	sig := make([]byte, 0, SignatureSize)
	sig = append(sig, ed25519.Sign(k.ed, signed)...)
	sig = append(sig, mlSig...)
	return sig, nil
}

// Destroy overwrites the seeds and the expanded Ed25519 key held by k and
// makes every later [PrivateKey.Sign] fail with [ErrDestroyed].
//
// This is best effort only. The expanded ML-DSA-65 key lives inside
// crypto/mldsa and cannot be erased from here; it is merely dropped for the
// garbage collector. The Go runtime may also have left copies of any of the
// key material elsewhere in memory. Destroy reduces the window in which keys
// are exposed (for example to a later memory dump), it does not guarantee
// erasure. Destroy must not be called concurrently with other methods of k.
func (k *PrivateKey) Destroy() {
	clear(k.edSeed[:])
	clear(k.mldsaSeed[:])
	clear(k.ed)
	k.ed = nil
	k.mldsa = nil
	k.destroyed = true
}

// ParsePublicKey decodes a public key produced by [PublicKey.Bytes]. The
// input must be exactly [PublicKeySize] bytes; it is copied, so the caller may
// reuse the slice.
//
// Parsing performs only structural checks. A syntactically valid key whose
// Ed25519 half is not a valid curve point is accepted here and simply never
// verifies any signature.
func ParsePublicKey(encoding []byte) (*PublicKey, error) {
	if len(encoding) != PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	return newPublicKey(encoding[:ed25519.PublicKeySize], encoding[ed25519.PublicKeySize:])
}

func newPublicKey(edPublic, mldsaPublic []byte) (*PublicKey, error) {
	if len(edPublic) != ed25519.PublicKeySize || len(mldsaPublic) != mldsa.MLDSA65PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	mlKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), mldsaPublic)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	encoding := make([]byte, 0, PublicKeySize)
	encoding = append(encoding, edPublic...)
	encoding = append(encoding, mldsaPublic...)
	return &PublicKey{
		encoding: encoding,
		ed:       ed25519.PublicKey(encoding[:ed25519.PublicKeySize:ed25519.PublicKeySize]),
		mldsa:    mlKey,
	}, nil
}

// Bytes returns the [PublicKeySize]-byte encoding of p: the Ed25519 public
// key followed by the ML-DSA-65 public key. The returned slice is a copy.
func (p *PublicKey) Bytes() []byte {
	return append([]byte(nil), p.encoding...)
}

// Equal reports whether p and other are the same key, comparing their full
// encodings in constant time. A nil key equals only another nil key.
func (p *PublicKey) Equal(other *PublicKey) bool {
	if p == nil || other == nil {
		return p == other
	}
	return subtle.ConstantTimeCompare(p.encoding, other.encoding) == 1
}

// Verify checks that sig is a valid hybrid signature of msg under the context
// label ctx. It returns nil only if sig has exactly [SignatureSize] bytes and
// both the Ed25519 and the ML-DSA-65 component verify; otherwise it returns
// [ErrInvalidSignature] (or [ErrInvalidContext] for a malformed label).
func (p *PublicKey) Verify(ctx string, msg, sig []byte) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if len(sig) != SignatureSize {
		return ErrInvalidSignature
	}
	signed := signedMessage(ctx, msg)

	// Both components must verify; accepting either one alone would reduce
	// the hybrid to its weaker half. Both are always evaluated so the rule is
	// a plain AND. Verification handles only public data, so the timing of
	// these checks reveals nothing secret.
	edOK := ed25519.Verify(p.ed, signed, sig[:ed25519.SignatureSize])
	mlOK := mldsa.Verify(p.mldsa, signed, sig[ed25519.SignatureSize:], &mldsa.Options{Context: ctx}) == nil
	if !edOK || !mlOK {
		return ErrInvalidSignature
	}
	return nil
}

// signedMessage builds M' = prefix || u8(len(ctx)) || ctx || msg. The length
// byte makes the boundary between ctx and msg unambiguous; checkContext has
// already guaranteed that len(ctx) fits in it.
func signedMessage(ctx string, msg []byte) []byte {
	out := make([]byte, 0, len(domainPrefix)+1+len(ctx)+len(msg))
	out = append(out, domainPrefix...)
	out = append(out, byte(len(ctx))) // #nosec G115 -- checkContext limits ctx to 255 bytes
	out = append(out, ctx...)
	out = append(out, msg...)
	return out
}

// checkContext enforces the rules for context labels. The spec calls for
// short ASCII labels; rejecting control characters, non-ASCII bytes and the
// empty label prevents accidental use of attacker-influenced or missing
// labels, which would defeat domain separation.
func checkContext(ctx string) error {
	if len(ctx) == 0 || len(ctx) > MaxContextSize {
		return ErrInvalidContext
	}
	for i := 0; i < len(ctx); i++ {
		if ctx[i] < 0x20 || ctx[i] > 0x7e {
			return ErrInvalidContext
		}
	}
	return nil
}
