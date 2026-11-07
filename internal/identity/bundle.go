package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/protocol"
)

// Bundle format parameters.
const (
	// BundleVersion is the bundle format version written by
	// [Identity.Bundle].
	BundleVersion = 1

	// MaxBundleSize is the largest encoded bundle [ParseBundle] accepts,
	// equal to the relay protocol limit. A version 1 bundle is about 6.6 KiB.
	MaxBundleSize = protocol.MaxBundleSize
)

// Errors returned for bundles. Callers compare with [errors.Is].
var (
	// ErrMalformedBundle reports a bundle that is not exactly in the
	// canonical version 1 format: wrong CBOR, missing or unknown fields,
	// non-canonical encoding, keys or signature of the wrong size, or keys
	// that the key decoders reject.
	ErrMalformedBundle = errors.New("identity: malformed bundle")

	// ErrBadBundleSignature reports a bundle whose self-signature does not
	// verify under its own signing key.
	ErrBadBundleSignature = errors.New("identity: bundle signature does not verify")

	// ErrIDMismatch reports a valid bundle that belongs to a different
	// identity than the one requested.
	ErrIDMismatch = errors.New("identity: bundle belongs to a different identity")
)

// Bundle is a parsed and verified public identity bundle: the public keys of
// an identity as published on the relay.
//
// A Bundle carries guarantees only when it was returned by [ParseBundle] or
// [ParseBundleForID]: then its self-signature verified, ID is the ID
// computed from SigningKey, and KEMKey is the encryption key the identity
// itself signed. A Bundle assembled by hand from its fields carries none of
// these guarantees and must not be passed to code that expects a verified
// bundle. The fields must be treated as read-only.
type Bundle struct {
	// ID is computed from SigningKey by [IDFromSigningKey]; it is never
	// read from the encoding.
	ID ID

	// SigningKey is the hybrid signing public key.
	SigningKey *hybridsig.PublicKey

	// KEMKey is the HPKE public key messages to this identity are sealed to.
	KEMKey *sealbox.PublicKey

	// Serial orders bundles of the same identity: a newer bundle (for
	// example after a KEM key rotation) has a higher serial. It is at least 1.
	Serial uint64

	// Created is the creation time claimed by the bundle owner, with second
	// precision. It is informational only and not checked.
	Created time.Time

	// Raw is the exact encoding the bundle was parsed from. It is what
	// clients store and what the relay serves.
	Raw []byte
}

// bundleTBS holds fields 1 to 5 of a bundle; its canonical encoding is the
// message the self-signature covers.
type bundleTBS struct {
	Version uint8  `cbor:"1,keyasint"`
	SigKey  []byte `cbor:"2,keyasint"`
	KEMKey  []byte `cbor:"3,keyasint"`
	Serial  uint64 `cbor:"4,keyasint"`
	Created int64  `cbor:"5,keyasint"`
}

// bundleWire is the complete encoded bundle, fields 1 to 6.
type bundleWire struct {
	Version uint8  `cbor:"1,keyasint"`
	SigKey  []byte `cbor:"2,keyasint"`
	KEMKey  []byte `cbor:"3,keyasint"`
	Serial  uint64 `cbor:"4,keyasint"`
	Created int64  `cbor:"5,keyasint"`
	Sig     []byte `cbor:"6,keyasint"`
}

func (w *bundleWire) tbs() bundleTBS {
	return bundleTBS{Version: w.Version, SigKey: w.SigKey, KEMKey: w.KEMKey, Serial: w.Serial, Created: w.Created}
}

// Bundle returns the encoded, self-signed public bundle of the identity:
//
//	CBOR{1: version (=1), 2: signing public key, 3: KEM public key,
//	     4: serial, 5: created (Unix seconds), 6: signature}
//
// where the signature is a hybrid signature under [ContextBundle] over the
// canonical CBOR encoding of fields 1 to 5. serial must be at least 1 and
// must increase whenever the identity publishes a bundle with different
// content; now is recorded as the creation time.
//
// The ML-DSA half of the signature is randomised, so two calls with the same
// arguments return different, equally valid encodings. Because the relay
// treats a different bundle with the same serial as a conflict, a client
// must store the bundle it registered and re-send those exact bytes rather
// than calling Bundle again (package profile does this).
func (i *Identity) Bundle(serial uint64, now time.Time) ([]byte, error) {
	if serial == 0 {
		return nil, fmt.Errorf("%w: bundle serial must be at least 1", ErrInvalidArgument)
	}
	wire := bundleWire{
		Version: BundleVersion,
		SigKey:  i.SigningKey().Bytes(),
		KEMKey:  i.KEMKey().Bytes(),
		Serial:  serial,
		Created: now.Unix(),
	}
	tbs, err := encMode.Marshal(wire.tbs())
	if err != nil {
		return nil, fmt.Errorf("identity: encoding bundle: %w", err)
	}
	if wire.Sig, err = i.sign(ContextBundle, tbs); err != nil {
		return nil, err
	}
	encoded, err := encMode.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("identity: encoding bundle: %w", err)
	}
	return encoded, nil
}

// ParseBundle decodes and verifies an encoded bundle. It accepts only the
// exact canonical encoding of a version 1 bundle no larger than
// [MaxBundleSize], with a signing key, KEM key and signature of exactly the
// right sizes, a serial of at least 1 and a self-signature that verifies.
// The ID of the result is computed from the signing key.
//
// ParseBundle proves only that the bundle is internally consistent: whoever
// holds the private signing key published these keys. It does not prove
// that the bundle belongs to the person the caller has in mind. When the
// caller expects a particular identity (every time a bundle comes from the
// relay), it must use [ParseBundleForID] instead.
//
// Errors are [ErrMalformedBundle], [ErrUnsupportedVersion] and
// [ErrBadBundleSignature].
func ParseBundle(b []byte) (*Bundle, error) {
	if len(b) == 0 || len(b) > MaxBundleSize {
		return nil, fmt.Errorf("%w: size %d out of range", ErrMalformedBundle, len(b))
	}
	var wire bundleWire
	if err := decodeCanonical(b, &wire); err != nil {
		if version, ok := peekVersion(b); ok && version > BundleVersion {
			return nil, ErrUnsupportedVersion
		}
		return nil, fmt.Errorf("%w: %w", ErrMalformedBundle, err)
	}
	if wire.Version > BundleVersion {
		return nil, ErrUnsupportedVersion
	}
	if wire.Version != BundleVersion {
		return nil, fmt.Errorf("%w: version %d", ErrMalformedBundle, wire.Version)
	}
	if len(wire.SigKey) != hybridsig.PublicKeySize || len(wire.KEMKey) != sealbox.PublicKeySize ||
		len(wire.Sig) != hybridsig.SignatureSize {
		return nil, fmt.Errorf("%w: field of wrong size", ErrMalformedBundle)
	}
	if wire.Serial == 0 {
		return nil, fmt.Errorf("%w: serial must be at least 1", ErrMalformedBundle)
	}
	signingKey, err := hybridsig.ParsePublicKey(wire.SigKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedBundle, err)
	}
	kemKey, err := sealbox.ParsePublicKey(wire.KEMKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedBundle, err)
	}

	// The signed bytes are rebuilt from the decoded fields. Since the input
	// was required to be canonical, they are byte for byte the prefix of
	// what the signer encoded, and the signature binds the KEM key, serial
	// and creation time to the signing key (and therefore to the ID).
	tbs, err := encMode.Marshal(wire.tbs())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedBundle, err)
	}
	if err := signingKey.Verify(ContextBundle, tbs, wire.Sig); err != nil {
		return nil, ErrBadBundleSignature
	}
	return &Bundle{
		ID:         IDFromSigningKey(signingKey),
		SigningKey: signingKey,
		KEMKey:     kemKey,
		Serial:     wire.Serial,
		Created:    time.Unix(wire.Created, 0),
		Raw:        append([]byte(nil), b...),
	}, nil
}

// ParseBundleForID is [ParseBundle] followed by a check that the bundle's
// computed ID equals want; otherwise it returns [ErrIDMismatch].
//
// This check is what makes the untrusted relay unable to substitute keys.
// A client asks the relay for the bundle of an ID it already knows (typed
// in, scanned, or stored with the contact). The relay could answer with any
// validly self-signed bundle, for example one it generated itself, and
// ParseBundle alone would accept it. Because the ID is the hash of the
// signing key, and the signing key signs the KEM key, a bundle that passes
// this check can only have been produced by the holder of the private key
// behind want. Every bundle obtained from the network must go through this
// function, never through ParseBundle alone.
func ParseBundleForID(b []byte, want ID) (*Bundle, error) {
	bundle, err := ParseBundle(b)
	if err != nil {
		return nil, err
	}
	if bundle.ID != want {
		return nil, ErrIDMismatch
	}
	return bundle, nil
}
