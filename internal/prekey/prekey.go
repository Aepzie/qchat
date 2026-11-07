package prekey

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/identity"
)

// Format parameters.
const (
	// Version is the format version of both prekey encodings.
	Version = 1

	// ContextSignedPrekey labels the owner signature of a signed prekey.
	ContextSignedPrekey = "qchat/v1/signed-prekey"

	// ContextOneTimePrekey labels the owner signature of a one-time prekey.
	ContextOneTimePrekey = "qchat/v1/one-time-prekey"

	// MaxSize is the largest encoded prekey of either kind that the parsers
	// accept. A version 1 signed prekey is about 4.7 KiB (public key 1216,
	// signature 3373, owner 32 and a few bytes of CBOR framing), a one-time
	// prekey slightly less. Oversized input is rejected before any decoding
	// or signature work is done.
	MaxSize = 6 << 10

	// MaxClockSkew is how far in the future the creation time of a signed
	// prekey may lie. The owner's clock and the verifier's clock are never
	// exactly in step; anything beyond this is treated as not yet valid.
	MaxClockSkew = 5 * time.Minute

	// MaxOneTimePrekeysPerCall bounds n in [GenerateOneTimePrekeys]. Each
	// key costs a KEM key generation and a hybrid signature, so the bound
	// keeps a mistaken n from tying up the client.
	MaxOneTimePrekeysPerCall = 1000
)

// Errors returned by this package. Callers compare with [errors.Is].
var (
	// ErrMalformed reports an encoding that is not exactly in the canonical
	// version 1 format: wrong CBOR, missing or unknown fields, non-canonical
	// encoding, fields of the wrong size, a zero key ID, a validity period
	// that ends before it starts, or a public key the KEM rejects.
	ErrMalformed = errors.New("prekey: malformed prekey")

	// ErrBadSignature reports a prekey whose signature does not verify
	// under the owner's signing key and the prekey's own context label.
	ErrBadSignature = errors.New("prekey: signature does not verify")

	// ErrWrongOwner reports a prekey whose Owner field names a different
	// identity than the bundle it was verified against.
	ErrWrongOwner = errors.New("prekey: prekey belongs to a different identity")

	// ErrExpired reports a correctly signed signed prekey that is not valid
	// at the verification time: it has expired, or its creation time lies
	// more than [MaxClockSkew] in the future.
	ErrExpired = errors.New("prekey: signed prekey is outside its validity period")

	// ErrInvalidArgument reports an argument outside its documented range.
	ErrInvalidArgument = errors.New("prekey: invalid argument")
)

// Signer is the part of a private identity that prekey generation needs.
// Each method signs the given to-be-signed bytes under its own fixed
// context label ([ContextSignedPrekey] or [ContextOneTimePrekey]), so no
// caller can make the identity sign prekey bytes under the label of another
// purpose, or arbitrary bytes under a prekey label. *identity.Identity is
// intended to implement this interface.
type Signer interface {
	ID() identity.ID
	SignSignedPrekey(tbs []byte) ([]byte, error)
	SignOneTimePrekey(tbs []byte) ([]byte, error)
}

// SignedPrekey is a parsed and verified signed prekey. It carries guarantees
// only when returned by [ParseSignedPrekey] or [GenerateSignedPrekey]: then
// its signature verified under the owner's identity and the owner's ID is
// Owner. A value assembled by hand carries none of them. Fields must be
// treated as read-only.
type SignedPrekey struct {
	// Owner is the identity that signed the prekey.
	Owner identity.ID

	// KeyID identifies the prekey among the owner's signed prekeys. It is
	// chosen at random by the owner and never zero.
	KeyID uint32

	// Pub is the HPKE public key peers encapsulate to.
	Pub *sealbox.PublicKey

	// Created and Expires bound the validity period, with second precision.
	Created time.Time
	Expires time.Time

	// Raw is the exact encoding, as uploaded to and served by the relay.
	Raw []byte
}

// OneTimePrekey is a parsed and verified one-time prekey, with the same
// guarantees as [SignedPrekey]. One-time prekeys have no expiry: they are
// valid until the owner deletes the private key after first use.
type OneTimePrekey struct {
	Owner identity.ID
	KeyID uint32
	Pub   *sealbox.PublicKey
	Raw   []byte
}

// SignedPrekeyPair is a freshly generated signed prekey with its private
// key. The private key must only be stored encrypted (see [MarshalPrivate])
// and must be deleted according to the rotation policy of the design
// document; keeping it longer silently weakens forward secrecy.
type SignedPrekeyPair struct {
	Public  *SignedPrekey
	Private *sealbox.PrivateKey
}

// OneTimePrekeyPair is a freshly generated one-time prekey with its private
// key. The private key must be deleted as soon as the first message of the
// session that used it has been decrypted.
type OneTimePrekeyPair struct {
	Public  *OneTimePrekey
	Private *sealbox.PrivateKey
}

// signedTBS holds fields 1 to 6 of a signed prekey; its canonical encoding
// is the message the signature covers.
type signedTBS struct {
	Version uint8  `cbor:"1,keyasint"`
	Owner   []byte `cbor:"2,keyasint"`
	KeyID   uint32 `cbor:"3,keyasint"`
	Pub     []byte `cbor:"4,keyasint"`
	Created int64  `cbor:"5,keyasint"`
	Expires int64  `cbor:"6,keyasint"`
}

// signedWire is the complete encoded signed prekey, fields 1 to 7.
type signedWire struct {
	Version uint8  `cbor:"1,keyasint"`
	Owner   []byte `cbor:"2,keyasint"`
	KeyID   uint32 `cbor:"3,keyasint"`
	Pub     []byte `cbor:"4,keyasint"`
	Created int64  `cbor:"5,keyasint"`
	Expires int64  `cbor:"6,keyasint"`
	Sig     []byte `cbor:"7,keyasint"`
}

func (w *signedWire) tbs() signedTBS {
	return signedTBS{Version: w.Version, Owner: w.Owner, KeyID: w.KeyID, Pub: w.Pub, Created: w.Created, Expires: w.Expires}
}

// oneTimeTBS holds fields 1 to 4 of a one-time prekey; its canonical
// encoding is the message the signature covers.
type oneTimeTBS struct {
	Version uint8  `cbor:"1,keyasint"`
	Owner   []byte `cbor:"2,keyasint"`
	KeyID   uint32 `cbor:"3,keyasint"`
	Pub     []byte `cbor:"4,keyasint"`
}

// oneTimeWire is the complete encoded one-time prekey, fields 1 to 5.
type oneTimeWire struct {
	Version uint8  `cbor:"1,keyasint"`
	Owner   []byte `cbor:"2,keyasint"`
	KeyID   uint32 `cbor:"3,keyasint"`
	Pub     []byte `cbor:"4,keyasint"`
	Sig     []byte `cbor:"5,keyasint"`
}

func (w *oneTimeWire) tbs() oneTimeTBS {
	return oneTimeTBS{Version: w.Version, Owner: w.Owner, KeyID: w.KeyID, Pub: w.Pub}
}

// GenerateSignedPrekey creates a new signed prekey for id, valid from now
// for lifetime (at least one second; the client policy of the design
// document is 21 days). The key ID is random and non-zero. Times are
// truncated to whole seconds, as in the encoding.
func GenerateSignedPrekey(id Signer, now time.Time, lifetime time.Duration) (*SignedPrekeyPair, error) {
	if id == nil {
		return nil, fmt.Errorf("%w: nil signer", ErrInvalidArgument)
	}
	if lifetime < time.Second {
		return nil, fmt.Errorf("%w: lifetime %v shorter than one second", ErrInvalidArgument, lifetime)
	}
	keyID, err := randomKeyID()
	if err != nil {
		return nil, err
	}
	priv, err := sealbox.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("prekey: generating key: %w", err)
	}
	owner := id.ID()
	created := now.Unix()
	wire := signedWire{
		Version: Version,
		Owner:   owner[:],
		KeyID:   keyID,
		Pub:     priv.Public().Bytes(),
		Created: created,
		Expires: created + int64(lifetime/time.Second),
	}
	raw, err := signAndEncode(wire.tbs(), func(tbs []byte) error {
		var err error
		wire.Sig, err = id.SignSignedPrekey(tbs)
		return err
	}, &wire)
	if err != nil {
		priv.Destroy()
		return nil, fmt.Errorf("prekey: signed prekey: %w", err)
	}
	return &SignedPrekeyPair{
		Public: &SignedPrekey{
			Owner:   owner,
			KeyID:   keyID,
			Pub:     priv.Public(),
			Created: time.Unix(wire.Created, 0),
			Expires: time.Unix(wire.Expires, 0),
			Raw:     raw,
		},
		Private: priv,
	}, nil
}

// GenerateOneTimePrekeys creates n (1 to [MaxOneTimePrekeysPerCall])
// one-time prekeys for id with random, non-zero key IDs that are distinct
// within the batch.
//
// Uniqueness against key IDs generated earlier is the caller's job: the
// store must refuse (and the caller regenerate) a key whose ID it already
// holds, otherwise the private key of a published prekey would be
// overwritten and sessions started with it would fail. With 32-bit random
// IDs and a pool of about 50 keys this is rare, but not impossible.
func GenerateOneTimePrekeys(id Signer, n int) ([]*OneTimePrekeyPair, error) {
	if id == nil {
		return nil, fmt.Errorf("%w: nil signer", ErrInvalidArgument)
	}
	if n < 1 || n > MaxOneTimePrekeysPerCall {
		return nil, fmt.Errorf("%w: count %d out of range", ErrInvalidArgument, n)
	}
	owner := id.ID()
	pairs := make([]*OneTimePrekeyPair, 0, n)
	fail := func(err error) ([]*OneTimePrekeyPair, error) {
		for _, pair := range pairs {
			pair.Private.Destroy()
		}
		return nil, err
	}
	used := make(map[uint32]bool, n)
	for len(pairs) < n {
		keyID, err := randomKeyID()
		if err != nil {
			return fail(err)
		}
		if used[keyID] {
			continue
		}
		used[keyID] = true
		pair, err := generateOneTime(id, owner, keyID)
		if err != nil {
			return fail(err)
		}
		pairs = append(pairs, pair)
	}
	return pairs, nil
}

func generateOneTime(id Signer, owner identity.ID, keyID uint32) (*OneTimePrekeyPair, error) {
	priv, err := sealbox.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("prekey: generating key: %w", err)
	}
	wire := oneTimeWire{Version: Version, Owner: owner[:], KeyID: keyID, Pub: priv.Public().Bytes()}
	raw, err := signAndEncode(wire.tbs(), func(tbs []byte) error {
		var err error
		wire.Sig, err = id.SignOneTimePrekey(tbs)
		return err
	}, &wire)
	if err != nil {
		priv.Destroy()
		return nil, fmt.Errorf("prekey: one-time prekey: %w", err)
	}
	return &OneTimePrekeyPair{
		Public:  &OneTimePrekey{Owner: owner, KeyID: keyID, Pub: priv.Public(), Raw: raw},
		Private: priv,
	}, nil
}

// signAndEncode encodes tbs, lets sign fill in the signature field of wire,
// and returns the encoding of wire.
func signAndEncode(tbs any, sign func([]byte) error, wire any) ([]byte, error) {
	tbsBytes, err := encMode.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("encoding: %w", err)
	}
	if err := sign(tbsBytes); err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	raw, err := encMode.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encoding: %w", err)
	}
	return raw, nil
}

// randomKeyID returns a uniformly random non-zero uint32. Zero is reserved:
// in the session start it means "no one-time prekey".
func randomKeyID() (uint32, error) {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("prekey: reading randomness: %w", err)
		}
		if keyID := binary.BigEndian.Uint32(b[:]); keyID != 0 {
			return keyID, nil
		}
	}
}

// ParseSignedPrekey decodes and verifies a signed prekey of owner, which
// must be a bundle returned by identity.ParseBundleForID for the identity
// the caller expects (never one taken unverified from the relay).
//
// Checks, in order: size, exact canonical version 1 encoding with fields of
// the right sizes, non-zero key ID, Expires after Created, a public key the
// KEM accepts, Owner equal to owner.ID ([ErrWrongOwner]), the signature
// under [ContextSignedPrekey] ([ErrBadSignature]), and finally the validity
// period at now ([ErrExpired]): now must be before Expires, and Created at
// most [MaxClockSkew] after now. The time checks come last so that
// [ErrExpired] is only ever reported for prekeys the owner really signed.
//
// Expiry is what bounds the relay's ability to keep serving an old signed
// prekey after the owner rotated it (and eventually deleted its private
// key, or had it stolen): past Expires, no client starts a session with it.
func ParseSignedPrekey(b []byte, owner *identity.Bundle, now time.Time) (*SignedPrekey, error) {
	if owner == nil || owner.SigningKey == nil {
		return nil, fmt.Errorf("%w: nil owner bundle", ErrInvalidArgument)
	}
	if len(b) == 0 || len(b) > MaxSize {
		return nil, fmt.Errorf("%w: size %d out of range", ErrMalformed, len(b))
	}
	var wire signedWire
	if err := decodeCanonical(b, &wire); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if wire.Version != Version {
		return nil, fmt.Errorf("%w: version %d", ErrMalformed, wire.Version)
	}
	if wire.Expires <= wire.Created {
		return nil, fmt.Errorf("%w: expires before it is created", ErrMalformed)
	}
	pub, err := checkCommon(wire.Owner, wire.KeyID, wire.Pub, wire.Sig, owner)
	if err != nil {
		return nil, err
	}
	tbs, err := encMode.Marshal(wire.tbs())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := owner.SigningKey.Verify(ContextSignedPrekey, tbs, wire.Sig); err != nil {
		return nil, ErrBadSignature
	}
	nowUnix := now.Unix()
	if nowUnix >= wire.Expires {
		return nil, fmt.Errorf("%w: expired at %d", ErrExpired, wire.Expires)
	}
	if wire.Created > nowUnix && wire.Created-nowUnix > int64(MaxClockSkew/time.Second) {
		return nil, fmt.Errorf("%w: created in the future (%d)", ErrExpired, wire.Created)
	}
	return &SignedPrekey{
		Owner:   owner.ID,
		KeyID:   wire.KeyID,
		Pub:     pub,
		Created: time.Unix(wire.Created, 0),
		Expires: time.Unix(wire.Expires, 0),
		Raw:     append([]byte(nil), b...),
	}, nil
}

// ParseOneTimePrekey decodes and verifies a one-time prekey of owner (a
// bundle returned by identity.ParseBundleForID). The checks are those of
// [ParseSignedPrekey] without the validity period, and the signature is
// verified under [ContextOneTimePrekey].
//
// A successful parse does not mean the key is still unused: the relay may
// serve the same one-time prekey to several peers. The owner detects this
// when a second session start names a key ID it has already deleted, and
// rejects it.
func ParseOneTimePrekey(b []byte, owner *identity.Bundle) (*OneTimePrekey, error) {
	if owner == nil || owner.SigningKey == nil {
		return nil, fmt.Errorf("%w: nil owner bundle", ErrInvalidArgument)
	}
	if len(b) == 0 || len(b) > MaxSize {
		return nil, fmt.Errorf("%w: size %d out of range", ErrMalformed, len(b))
	}
	var wire oneTimeWire
	if err := decodeCanonical(b, &wire); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if wire.Version != Version {
		return nil, fmt.Errorf("%w: version %d", ErrMalformed, wire.Version)
	}
	pub, err := checkCommon(wire.Owner, wire.KeyID, wire.Pub, wire.Sig, owner)
	if err != nil {
		return nil, err
	}
	tbs, err := encMode.Marshal(wire.tbs())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := owner.SigningKey.Verify(ContextOneTimePrekey, tbs, wire.Sig); err != nil {
		return nil, ErrBadSignature
	}
	return &OneTimePrekey{Owner: owner.ID, KeyID: wire.KeyID, Pub: pub, Raw: append([]byte(nil), b...)}, nil
}

// checkCommon validates the fields shared by both prekey kinds and parses
// the public key. The owner comparison happens before any signature work,
// so a prekey of the wrong identity is rejected cheaply and reported
// precisely.
func checkCommon(ownerField []byte, keyID uint32, pubField, sig []byte, owner *identity.Bundle) (*sealbox.PublicKey, error) {
	if len(ownerField) != identity.IDSize || len(pubField) != sealbox.PublicKeySize || len(sig) != hybridsig.SignatureSize {
		return nil, fmt.Errorf("%w: field of wrong size", ErrMalformed)
	}
	if keyID == 0 {
		return nil, fmt.Errorf("%w: zero key ID", ErrMalformed)
	}
	pub, err := sealbox.ParsePublicKey(pubField)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if identity.ID(ownerField) != owner.ID {
		return nil, ErrWrongOwner
	}
	return pub, nil
}
