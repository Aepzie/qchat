package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Format constants.
const (
	// Version is the blob format version written by [Seal].
	Version = 1

	// KDFArgon2id identifies Argon2id (version 0x13) in the header.
	KDFArgon2id = 1

	// SaltSize is the length of the random Argon2 salt.
	SaltSize = 16

	// NonceSize is the length of the random XChaCha20-Poly1305 nonce.
	NonceSize = chacha20poly1305.NonceSizeX

	// KeySize is the length of the key derived from the passphrase and of
	// the keys returned by [RandomKey].
	KeySize = chacha20poly1305.KeySize

	// TagSize is the length of the Poly1305 authentication tag.
	TagSize = chacha20poly1305.Overhead
)

// Upper bounds on Argon2 parameters accepted by [Seal] and [Open]. They are
// checked before any key derivation so that a crafted blob cannot exhaust
// the memory or CPU of the client. The worst accepted case (1 GiB, 10 passes)
// is expensive but finite.
const (
	MaxTime      = 10
	MaxMemoryKiB = 1 << 20
	MaxThreads   = 16
)

// Lower bounds for production use: half of [DefaultParams]. The memory floor
// keeps GPU and ASIC attacks memory-bound, and the cost floor (passes times
// memory) keeps the total work per guess at least half the default, so
// trading passes for memory is allowed but weakening both is not.
const (
	MinMemoryKiB = 32 * 1024
	minCost      = 3 * 64 * 1024 / 2
)

// Errors returned by this package. Callers should compare with [errors.Is].
var (
	// ErrWrongPassphrase reports that the blob did not authenticate. This is
	// the result of a wrong passphrase and equally of a modified blob; the
	// two cannot be told apart, by design.
	ErrWrongPassphrase = errors.New("vault: wrong passphrase or corrupted vault")

	// ErrMalformed reports a blob that is not a structurally valid vault.
	ErrMalformed = errors.New("vault: malformed vault")

	// ErrUnsupportedVersion reports a blob written by a newer format version
	// or using an unknown KDF.
	ErrUnsupportedVersion = errors.New("vault: unsupported vault version")

	// ErrUnsafeParams reports Argon2 parameters outside the accepted bounds,
	// either too expensive (a possible denial-of-service attempt) or too
	// weak (cheap to brute force).
	ErrUnsafeParams = errors.New("vault: unsafe key derivation parameters")

	// ErrEmptyPassphrase reports an empty passphrase, which [Seal] refuses.
	ErrEmptyPassphrase = errors.New("vault: empty passphrase")
)

// Params are the Argon2id cost parameters of a vault. Salt length and key
// length are fixed by the format ([SaltSize], [KeySize]).
type Params struct {
	// Time is the number of passes over memory.
	Time uint32

	// MemoryKiB is the memory cost in KiB.
	MemoryKiB uint32

	// Threads is the degree of parallelism.
	Threads uint8

	// insecure marks parameters from TestParams, which Seal accepts below
	// the production floor only inside test binaries.
	insecure bool
}

// DefaultParams returns the RFC 9106 second recommended profile: Argon2id
// with 3 passes, 64 MiB of memory and 4 lanes. On a typical desktop this
// takes a fraction of a second, once per unlock.
func DefaultParams() Params {
	return Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}
}

// TestParams returns tiny Argon2 parameters (1 pass, 64 KiB, 1 lane) so that
// unit tests in other packages can create and open vaults quickly.
//
// INSECURE, TESTS ONLY. A passphrase protected with these parameters can be
// brute forced orders of magnitude faster than with [DefaultParams]. They are
// accepted only while running inside a "go test" binary (see
// [testing.Testing]); in any other program [Seal] and [Open] reject them with
// [ErrUnsafeParams], so calling TestParams from production code fails loudly
// instead of weakening real vaults.
func TestParams() Params {
	return Params{Time: 1, MemoryKiB: 64, Threads: 1, insecure: true}
}

// insecureParamsAllowed reports whether weak parameters may be used. It is a
// variable so that this package's own tests can exercise the production
// rules.
var insecureParamsAllowed = testing.Testing

// check enforces the parameter bounds. allowWeak lifts the production floor
// but never the ceiling and never the Argon2 structural minimums.
func (p Params) check(allowWeak bool) error {
	if p.Time < 1 || p.Threads < 1 || p.MemoryKiB < 8*uint32(p.Threads) {
		return ErrUnsafeParams
	}
	if p.Time > MaxTime || p.MemoryKiB > MaxMemoryKiB || p.Threads > MaxThreads {
		return ErrUnsafeParams
	}
	if allowWeak {
		return nil
	}
	if p.MemoryKiB < MinMemoryKiB || uint64(p.Time)*uint64(p.MemoryKiB) < minCost {
		return ErrUnsafeParams
	}
	return nil
}

// header is the CBOR header of a blob. Every field is always encoded.
type header struct {
	Version   uint8  `cbor:"1,keyasint"`
	KDF       uint8  `cbor:"2,keyasint"`
	Time      uint32 `cbor:"3,keyasint"`
	MemoryKiB uint32 `cbor:"4,keyasint"`
	Threads   uint8  `cbor:"5,keyasint"`
	Salt      []byte `cbor:"6,keyasint"`
	Nonce     []byte `cbor:"7,keyasint"`
}

// versionPeek reads only the version, tolerating unknown fields, so that a
// blob from a newer format is reported as ErrUnsupportedVersion rather than
// ErrMalformed.
type versionPeek struct {
	Version uint64 `cbor:"1,keyasint"`
}

var (
	encMode  cbor.EncMode
	decMode  cbor.DecMode
	peekMode cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.IndefLength = cbor.IndefLengthForbidden
	encOpts.TagsMd = cbor.TagsForbidden
	var err error
	if encMode, err = encOpts.EncMode(); err != nil {
		panic("vault: invalid CBOR encoding options: " + err.Error())
	}

	decOpts := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		BignumTag:         cbor.BignumTagForbidden,
		NaN:               cbor.NaNDecodeForbidden,
		Inf:               cbor.InfDecodeForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		MaxNestedLevels:   4,
		MaxArrayElements:  16,
		MaxMapPairs:       16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}
	if decMode, err = decOpts.DecMode(); err != nil {
		panic("vault: invalid CBOR decoding options: " + err.Error())
	}
	decOpts.ExtraReturnErrors = cbor.ExtraDecErrorNone
	if peekMode, err = decOpts.DecMode(); err != nil {
		panic("vault: invalid CBOR peek options: " + err.Error())
	}
}

// RandomKey returns a fresh uniformly random [KeySize]-byte key from
// crypto/rand, for example the local database key stored inside a vault.
func RandomKey() ([KeySize]byte, error) {
	var key [KeySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return [KeySize]byte{}, fmt.Errorf("vault: reading randomness: %w", err)
	}
	return key, nil
}

// Seal encrypts secret under passphrase and returns the blob. params must be
// within the accepted bounds; use [DefaultParams] unless there is a measured
// reason to deviate. The passphrase must not be empty. Each call draws a new
// salt and nonce, so sealing the same secret twice yields unrelated blobs.
func Seal(passphrase, secret []byte, params Params) ([]byte, error) {
	var salt [SaltSize]byte
	var nonce [NonceSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, fmt.Errorf("vault: reading randomness: %w", err)
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("vault: reading randomness: %w", err)
	}
	return sealWith(passphrase, secret, params, salt[:], nonce[:])
}

// sealWith is Seal with caller-chosen salt and nonce. It exists so tests can
// produce known-answer blobs; production code always goes through Seal,
// because reusing a salt and nonce under the same passphrase would reuse the
// AEAD key and nonce and destroy confidentiality.
func sealWith(passphrase, secret []byte, params Params, salt, nonce []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	if err := params.check(params.insecure && insecureParamsAllowed()); err != nil {
		return nil, err
	}
	if len(salt) != SaltSize || len(nonce) != NonceSize {
		return nil, errors.New("vault: invalid salt or nonce length")
	}

	hdr := header{
		Version:   Version,
		KDF:       KDFArgon2id,
		Time:      params.Time,
		MemoryKiB: params.MemoryKiB,
		Threads:   params.Threads,
		Salt:      salt,
		Nonce:     nonce,
	}
	headerBytes, err := encMode.Marshal(hdr)
	if err != nil {
		return nil, fmt.Errorf("vault: encoding header: %w", err)
	}

	key := deriveKey(passphrase, &hdr)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("vault: initialising cipher: %w", err)
	}

	blob := make([]byte, 0, len(headerBytes)+len(secret)+TagSize)
	blob = append(blob, headerBytes...)
	return aead.Seal(blob, nonce, secret, headerBytes), nil
}

// Open decrypts a blob produced by [Seal] and returns the secret. The caller
// owns the returned slice and should clear it after use.
//
// The header is fully validated, including the Argon2 parameter bounds,
// before the key derivation runs. Errors are [ErrMalformed],
// [ErrUnsupportedVersion], [ErrUnsafeParams] or [ErrWrongPassphrase]; on any
// error no part of the secret is returned.
func Open(passphrase, blob []byte) ([]byte, error) {
	hdr, headerBytes, ciphertext, err := parse(blob)
	if err != nil {
		return nil, err
	}
	key := deriveKey(passphrase, hdr)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("vault: initialising cipher: %w", err)
	}
	secret, err := aead.Open(nil, hdr.Nonce, ciphertext, headerBytes)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return secret, nil
}

// parse splits a blob into its validated header, the exact header bytes (the
// AEAD associated data) and the ciphertext. It does no cryptographic work, so
// it is cheap on any input.
func parse(blob []byte) (*header, []byte, []byte, error) {
	var hdr header
	rest, err := decMode.UnmarshalFirst(blob, &hdr)
	if err != nil {
		var peek versionPeek
		if _, perr := peekMode.UnmarshalFirst(blob, &peek); perr == nil && peek.Version != Version {
			return nil, nil, nil, ErrUnsupportedVersion
		}
		return nil, nil, nil, ErrMalformed
	}
	headerBytes := blob[:len(blob)-len(rest)]

	if hdr.Version != Version {
		return nil, nil, nil, ErrUnsupportedVersion
	}
	if hdr.KDF != KDFArgon2id {
		return nil, nil, nil, ErrUnsupportedVersion
	}
	if len(hdr.Salt) != SaltSize || len(hdr.Nonce) != NonceSize || len(rest) < TagSize {
		return nil, nil, nil, ErrMalformed
	}

	// Accept only the canonical encoding: the header is authenticated byte
	// for byte, and a single valid encoding per header removes any room for
	// parser differentials (alternative integer widths, other key orders).
	canonical, err := encMode.Marshal(hdr)
	if err != nil || !bytes.Equal(canonical, headerBytes) {
		return nil, nil, nil, ErrMalformed
	}

	params := Params{Time: hdr.Time, MemoryKiB: hdr.MemoryKiB, Threads: hdr.Threads}
	if err := params.check(insecureParamsAllowed()); err != nil {
		return nil, nil, nil, err
	}
	return &hdr, headerBytes, rest, nil
}

// deriveKey runs Argon2id over the passphrase with the header's salt and
// cost. The parameters must already have been validated.
func deriveKey(passphrase []byte, hdr *header) []byte {
	return argon2.IDKey(passphrase, hdr.Salt, hdr.Time, hdr.MemoryKiB, hdr.Threads, KeySize)
}
