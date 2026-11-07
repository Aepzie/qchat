package identity

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/transport"
	"github.com/fxamacker/cbor/v2"
)

func decodeWire(t *testing.T, raw []byte) bundleWire {
	t.Helper()
	var wire bundleWire
	if err := decodeCanonical(raw, &wire); err != nil {
		t.Fatal(err)
	}
	return wire
}

// signWire signs and encodes wire with signer, bypassing the argument checks
// of Identity.Bundle so that tests can build bundles the parser must reject.
func signWire(t *testing.T, signer *Identity, wire bundleWire) []byte {
	t.Helper()
	tbs, err := encMode.Marshal(wire.tbs())
	if err != nil {
		t.Fatal(err)
	}
	if wire.Sig, err = signer.sign(ContextBundle, tbs); err != nil {
		t.Fatal(err)
	}
	raw, err := encMode.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBundleRoundTrip(t *testing.T) {
	identity := generate(t)
	created := time.Unix(1750000000, 999)
	raw, err := identity.Bundle(3, created)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.ID != identity.ID() || bundle.Serial != 3 || !bundle.Created.Equal(time.Unix(1750000000, 0)) {
		t.Errorf("bundle = %+v", bundle)
	}
	if !bundle.SigningKey.Equal(identity.SigningKey()) || !bundle.KEMKey.Equal(identity.KEMKey()) {
		t.Error("bundle keys differ")
	}
	if !bytes.Equal(bundle.Raw, raw) {
		t.Error("Raw differs from input")
	}
	raw[0] ^= 0xff
	if bundle.Raw[0] == raw[0] {
		t.Error("Raw aliases the input")
	}
	if _, err := identity.Bundle(0, created); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("serial 0: %v", err)
	}
}

func TestParseBundleForID(t *testing.T) {
	identity := generate(t)
	raw, err := identity.Bundle(1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBundleForID(raw, identity.ID()); err != nil {
		t.Errorf("own ID rejected: %v", err)
	}
	if _, err := ParseBundleForID(raw, generate(t).ID()); !errors.Is(err, ErrIDMismatch) {
		t.Errorf("other ID: %v, want ErrIDMismatch", err)
	}
	if _, err := ParseBundleForID(raw[:10], identity.ID()); !errors.Is(err, ErrMalformedBundle) {
		t.Errorf("truncated: %v", err)
	}
}

func TestParseBundleTamper(t *testing.T) {
	identity := katIdentity(t)
	raw, err := identity.Bundle(1, time.Unix(katCreated, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		for _, flip := range []byte{0x01, 0x80} {
			tampered := append([]byte(nil), raw...)
			tampered[i] ^= flip
			if _, err := ParseBundle(tampered); err == nil {
				t.Fatalf("bundle with byte %d ^ %#x accepted", i, flip)
			}
		}
	}
}

func TestParseBundleRejects(t *testing.T) {
	identity := generate(t)
	other := generate(t)
	raw, err := identity.Bundle(5, time.Unix(katCreated, 0))
	if err != nil {
		t.Fatal(err)
	}
	wire := decodeWire(t, raw)

	swappedKEM := wire
	swappedKEM.KEMKey = other.KEMKey().Bytes()
	swappedKEM.Sig = decodeWire(t, raw).Sig
	swappedKEMRaw, err := encMode.Marshal(swappedKEM)
	if err != nil {
		t.Fatal(err)
	}

	foreignSig := wire
	foreignSigRaw := signWire(t, other, foreignSig)

	serialZero := wire
	serialZero.Serial = 0
	newer := wire
	newer.Version = 2
	versionZero := wire
	versionZero.Version = 0

	encode := func(v any) []byte {
		b, err := encMode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	type reordered struct {
		Sig     []byte `cbor:"6,keyasint"`
		Version uint8  `cbor:"1,keyasint"`
		SigKey  []byte `cbor:"2,keyasint"`
		KEMKey  []byte `cbor:"3,keyasint"`
		Serial  uint64 `cbor:"4,keyasint"`
		Created int64  `cbor:"5,keyasint"`
	}
	unsorted, err := cbor.EncOptions{}.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical, err := unsorted.Marshal(reordered{wire.Sig, wire.Version, wire.SigKey, wire.KEMKey, wire.Serial, wire.Created})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input []byte
		want  error
	}{
		{"empty", nil, ErrMalformedBundle},
		{"oversized", make([]byte, MaxBundleSize+1), ErrMalformedBundle},
		{"trailing byte", append(append([]byte(nil), raw...), 0), ErrMalformedBundle},
		{"truncated", raw[:len(raw)-1], ErrMalformedBundle},
		{"swapped KEM key", swappedKEMRaw, ErrBadBundleSignature},
		{"signed by another key", foreignSigRaw, ErrBadBundleSignature},
		{"serial zero", signWire(t, identity, serialZero), ErrMalformedBundle},
		{"newer version", signWire(t, identity, newer), ErrUnsupportedVersion},
		{"newer version with new field", encode(map[int]any{1: 2, 2: wire.SigKey, 7: true}), ErrUnsupportedVersion},
		{"version zero", signWire(t, identity, versionZero), ErrMalformedBundle},
		{"unknown field", encode(map[int]any{1: 1, 2: wire.SigKey, 3: wire.KEMKey, 4: 5, 5: wire.Created, 6: wire.Sig, 7: 0}), ErrMalformedBundle},
		{"missing signature", encode(map[int]any{1: 1, 2: wire.SigKey, 3: wire.KEMKey, 4: 5, 5: wire.Created}), ErrMalformedBundle},
		{"short signing key", encode(map[int]any{1: 1, 2: wire.SigKey[1:], 3: wire.KEMKey, 4: 5, 5: wire.Created, 6: wire.Sig}), ErrMalformedBundle},
		{"short signature", encode(map[int]any{1: 1, 2: wire.SigKey, 3: wire.KEMKey, 4: 5, 5: wire.Created, 6: wire.Sig[1:]}), ErrMalformedBundle},
		{"non-canonical order", nonCanonical, ErrMalformedBundle},
		{"array instead of map", encode([]any{1, wire.SigKey}), ErrMalformedBundle},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseBundle(tc.input); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAuthProof(t *testing.T) {
	identity := generate(t)
	bundle := mustBundle(t, identity, 1)
	server := transport.Fingerprint{0x01, 0x02, 0x03}
	nonce := bytes.Repeat([]byte{0x5a}, NonceSize)

	sig, err := identity.SignAuth(server, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuth(bundle, server, nonce, sig); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}

	otherNonce := bytes.Repeat([]byte{0x5b}, NonceSize)
	otherServer := transport.Fingerprint{0x09}
	otherBundle := mustBundle(t, generate(t), 1)
	forged := *bundle
	forged.ID = otherBundle.ID

	cases := []struct {
		name   string
		bundle *Bundle
		server transport.Fingerprint
		nonce  []byte
		sig    []byte
		want   error
	}{
		{"wrong nonce", bundle, server, otherNonce, sig, ErrInvalidAuth},
		{"wrong server fingerprint", bundle, otherServer, nonce, sig, ErrInvalidAuth},
		{"wrong key", otherBundle, server, nonce, sig, ErrInvalidAuth},
		{"ID field disagrees with key", &forged, server, nonce, sig, ErrInvalidAuth},
		{"truncated signature", bundle, server, nonce, sig[1:], ErrInvalidAuth},
		{"short nonce", bundle, server, nonce[1:], sig, ErrInvalidArgument},
		{"zero fingerprint", bundle, transport.Fingerprint{}, nonce, sig, ErrInvalidArgument},
		{"nil bundle", nil, server, nonce, sig, ErrInvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyAuth(tc.bundle, tc.server, tc.nonce, tc.sig); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}

	bundleSig, err := identity.sign(ContextBundle, mustAuthMessage(t, server, nonce, identity.ID()))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuth(bundle, server, nonce, bundleSig); !errors.Is(err, ErrInvalidAuth) {
		t.Errorf("signature under another context accepted: %v", err)
	}
	if _, err := identity.SignAuth(server, nonce[1:]); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("SignAuth short nonce: %v", err)
	}
}

func mustAuthMessage(t *testing.T, server transport.Fingerprint, nonce []byte, id ID) []byte {
	t.Helper()
	msg, err := authMessage(server, nonce, id)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}
