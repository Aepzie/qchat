package identity

import (
	"errors"
	"fmt"
	"sync"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/crypto/sealbox"
)

// Signature context labels. Each signed structure of the protocol has its
// own label, so a signature made for one purpose can never be accepted for
// another (see package hybridsig on domain separation).
const (
	// ContextBundle labels the self-signature of an identity bundle.
	ContextBundle = "qchat/v1/bundle"

	// ContextMessage labels the sender signature inside an end-to-end
	// message. It is also the prefix of the HPKE info string of a message.
	ContextMessage = "qchat/v1/message"

	// ContextAuth labels the relay authentication proof.
	ContextAuth = "qchat/v1/auth-tls"

	// ContextSignedPrekey labels the signature on a signed prekey.
	ContextSignedPrekey = "qchat/v1/signed-prekey"

	// ContextOneTimePrekey labels the signature on a one-time prekey.
	ContextOneTimePrekey = "qchat/v1/one-time-prekey"

	// ContextSessionInit labels the signature on a session Init header.
	ContextSessionInit = "qchat/v1/session-init"
)

// SecretVersion is the format version of the record produced by
// [Identity.MarshalSecret].
const SecretVersion = 1

// Errors returned by this package for private identities. Callers compare
// with [errors.Is].
var (
	// ErrDestroyed reports use of an Identity after [Identity.Destroy].
	ErrDestroyed = errors.New("identity: identity has been destroyed")

	// ErrMalformedSecret reports a secret-key record that is not exactly in
	// the format written by [Identity.MarshalSecret].
	ErrMalformedSecret = errors.New("identity: malformed secret key record")

	// ErrUnsupportedVersion reports a secret-key record or bundle written by
	// a newer format version.
	ErrUnsupportedVersion = errors.New("identity: unsupported format version")

	// ErrInvalidArgument reports an argument outside its documented range.
	ErrInvalidArgument = errors.New("identity: invalid argument")
)

// Identity is a private qchat identity: a hybrid signing key (Ed25519 and
// ML-DSA-65) and an HPKE decryption key (MLKEM768-X25519). Its [ID] is
// derived from the signing public key.
//
// An Identity is safe for concurrent use. [Identity.Destroy] may be called
// at any time, also concurrently with other methods; it waits for
// operations in progress, and every later operation that needs private key
// material fails with [ErrDestroyed].
type Identity struct {
	mu        sync.RWMutex
	signing   *hybridsig.PrivateKey
	kem       *sealbox.PrivateKey
	id        ID
	destroyed bool
}

// secretRecord is the CBOR form of the private keys. All three values are
// seeds from which the full keys are expanded deterministically, so the
// record is small and has a single valid encoding.
type secretRecord struct {
	Version   uint8  `cbor:"1,keyasint"`
	EdSeed    []byte `cbor:"2,keyasint"`
	MLDSASeed []byte `cbor:"3,keyasint"`
	KEMKey    []byte `cbor:"4,keyasint"`
}

// Generate creates a new identity with fresh random keys from crypto/rand.
func Generate() (*Identity, error) {
	signing, err := hybridsig.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("identity: generating signing key: %w", err)
	}
	kem, err := sealbox.GenerateKey()
	if err != nil {
		signing.Destroy()
		return nil, fmt.Errorf("identity: generating encryption key: %w", err)
	}
	return newIdentity(signing, kem), nil
}

// fromSeeds rebuilds an identity from its three 32-byte seeds.
func fromSeeds(edSeed, mldsaSeed, kemKey []byte) (*Identity, error) {
	signing, err := hybridsig.NewPrivateKeyFromSeeds(edSeed, mldsaSeed)
	if err != nil {
		return nil, err
	}
	kem, err := sealbox.NewPrivateKey(kemKey)
	if err != nil {
		signing.Destroy()
		return nil, err
	}
	return newIdentity(signing, kem), nil
}

func newIdentity(signing *hybridsig.PrivateKey, kem *sealbox.PrivateKey) *Identity {
	return &Identity{signing: signing, kem: kem, id: IDFromSigningKey(signing.Public())}
}

// MarshalSecret returns the versioned secret-key record of the identity:
//
//	CBOR{1: version (=1), 2: Ed25519 seed, 3: ML-DSA-65 seed, 4: HPKE private key}
//
// The record is the complete private identity. It must only ever be stored
// encrypted (package profile seals it with package vault), and the caller
// should clear the returned slice as soon as it is no longer needed.
// Clearing is best effort: the CBOR encoder and the Go runtime may leave
// copies in memory that cannot be reached from here.
func (i *Identity) MarshalSecret() ([]byte, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.destroyed {
		return nil, ErrDestroyed
	}
	edSeed, mldsaSeed := i.signing.Seeds()
	kemKey := i.kem.Bytes()
	defer clear(edSeed)
	defer clear(mldsaSeed)
	defer clear(kemKey)
	record, err := encMode.Marshal(secretRecord{
		Version:   SecretVersion,
		EdSeed:    edSeed,
		MLDSASeed: mldsaSeed,
		KEMKey:    kemKey,
	})
	if err != nil {
		return nil, fmt.Errorf("identity: encoding secret key record: %w", err)
	}
	return record, nil
}

// UnmarshalSecret rebuilds an identity from a record produced by
// [Identity.MarshalSecret]. It accepts only the exact canonical encoding of
// a version 1 record with seeds of the right sizes and returns
// [ErrMalformedSecret] or [ErrUnsupportedVersion] otherwise. The input is
// not retained; the caller may clear it afterwards.
func UnmarshalSecret(b []byte) (*Identity, error) {
	var record secretRecord
	defer func() {
		clear(record.EdSeed)
		clear(record.MLDSASeed)
		clear(record.KEMKey)
	}()
	if err := decodeCanonical(b, &record); err != nil {
		if version, ok := peekVersion(b); ok && version > SecretVersion {
			return nil, ErrUnsupportedVersion
		}
		return nil, ErrMalformedSecret
	}
	if record.Version > SecretVersion {
		return nil, ErrUnsupportedVersion
	}
	if record.Version != SecretVersion {
		return nil, ErrMalformedSecret
	}
	if len(record.EdSeed) != hybridsig.SeedSize || len(record.MLDSASeed) != hybridsig.SeedSize ||
		len(record.KEMKey) != sealbox.PrivateKeySize {
		return nil, ErrMalformedSecret
	}
	identity, err := fromSeeds(record.EdSeed, record.MLDSASeed, record.KEMKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedSecret, err)
	}
	return identity, nil
}

// ID returns the identity's ID. It remains available after
// [Identity.Destroy].
func (i *Identity) ID() ID {
	return i.id
}

// SigningKey returns the hybrid signing public key. It remains available
// after [Identity.Destroy].
func (i *Identity) SigningKey() *hybridsig.PublicKey {
	return i.signing.Public()
}

// KEMKey returns the HPKE public key that peers encrypt messages to. It
// remains available after [Identity.Destroy].
func (i *Identity) KEMKey() *sealbox.PublicKey {
	return i.kem.Public()
}

// sign signs msg under ctx. It is unexported so that every signature this
// package makes goes through one of the purpose-specific methods, each of
// which fixes its own context label: no caller can make the identity sign
// arbitrary bytes under, say, the bundle or auth context.
func (i *Identity) sign(ctx string, msg []byte) ([]byte, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.destroyed {
		return nil, ErrDestroyed
	}
	return i.signing.Sign(ctx, msg)
}

// SignMessage signs the to-be-signed encoding of an end-to-end message
// (fields 1 to 7 of the Inner structure) under [ContextMessage]. It exists
// for package e2e, which defines that encoding; other callers should use
// e2e.Seal instead.
func (i *Identity) SignMessage(tbs []byte) ([]byte, error) {
	return i.sign(ContextMessage, tbs)
}

// SignSignedPrekey signs the to-be-signed encoding of a signed prekey under
// [ContextSignedPrekey]. It exists for package prekey, which defines that
// encoding. Each signing method is fixed to one context, so no caller can
// obtain a signature that is valid in another part of the protocol.
func (i *Identity) SignSignedPrekey(tbs []byte) ([]byte, error) {
	return i.sign(ContextSignedPrekey, tbs)
}

// SignOneTimePrekey signs the to-be-signed encoding of a one-time prekey
// under [ContextOneTimePrekey]. It exists for package prekey.
func (i *Identity) SignOneTimePrekey(tbs []byte) ([]byte, error) {
	return i.sign(ContextOneTimePrekey, tbs)
}

// SignSessionInit signs the to-be-signed encoding of a session Init header
// under [ContextSessionInit]. It exists for package handshake.
func (i *Identity) SignSessionInit(tbs []byte) ([]byte, error) {
	return i.sign(ContextSessionInit, tbs)
}

// Decapsulate recovers the shared secret that sealbox.Encapsulate produced
// for this identity's KEM key under the given info string. It exists for
// package handshake, which encapsulates to the identity key when a session
// starts. It returns [ErrDestroyed] after [Identity.Destroy].
func (i *Identity) Decapsulate(enc, info []byte) ([32]byte, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.destroyed {
		return [32]byte{}, ErrDestroyed
	}
	return sealbox.Decapsulate(i.kem, enc, info)
}

// OpenBox decrypts an HPKE box sealed to this identity's KEM key under the
// given info string, as produced by sealbox.Seal. It exists for package
// e2e; other callers should use e2e.Open, which performs all the checks the
// protocol requires on the decrypted content. Failures are reported as
// sealbox.ErrDecrypt (or another sealbox error), or [ErrDestroyed] after
// [Identity.Destroy].
func (i *Identity) OpenBox(info, box []byte) ([]byte, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.destroyed {
		return nil, ErrDestroyed
	}
	return sealbox.Open(i.kem, info, box)
}

// Destroy overwrites the private key material held by the identity and
// makes every later signing, decryption or export fail with [ErrDestroyed].
// It waits for operations already in progress to finish. Calling Destroy
// more than once is harmless.
//
// Erasure is best effort, as described in packages hybridsig and sealbox:
// the Go runtime and the standard library may hold copies of key material
// that this package cannot reach.
func (i *Identity) Destroy() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.destroyed {
		return
	}
	i.signing.Destroy()
	i.kem.Destroy()
	i.destroyed = true
}
