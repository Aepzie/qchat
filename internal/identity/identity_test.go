package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Aepzie/qchat/internal/crypto/safety"
	"github.com/Aepzie/qchat/internal/crypto/sealbox"
	"github.com/Aepzie/qchat/internal/transport"
	"github.com/fxamacker/cbor/v2"
)

var updateKAT = flag.Bool("update-kat", false, "rewrite testdata/kat_bundle.hex from the KAT identity")

// Known-answer values for the identity expanded from katSeeds. They pin the
// ID derivation (domain prefix, hash, key encoding), the textual ID format
// and the canonical encoding of the signed part of a bundle.
const (
	katID      = "qc1-a2us-rgnf-kggl-gea5-7icx-yxfe-oyfj-f6rk-42st-5qqc-7eia-v3ip-odwa"
	katTBSHash = "a04c2eebf696f9113f8ad6563a9d3ec0e2c1af207e93c2e20c27bb459bd65274"

	// katBundleHash is the SHA-256 of the committed bundle in
	// testdata/kat_bundle.hex. Bundle signatures are randomised (hedged
	// ML-DSA), so the bundle is committed once rather than recomputed.
	katBundleHash = "84e99a3b3dc1495af131f9842a404a25f4c5e8f81291c150c85c1bf2bd39c180"

	katSerial  = 7
	katCreated = 1700000000
)

func katSeeds() (edSeed, mldsaSeed, kemKey []byte) {
	edSeed = make([]byte, 32)
	mldsaSeed = make([]byte, 32)
	kemKey = make([]byte, 32)
	for i := range edSeed {
		edSeed[i] = byte(i)
		mldsaSeed[i] = byte(0x80 + i)
		kemKey[i] = byte(0x40 + i)
	}
	return edSeed, mldsaSeed, kemKey
}

func katIdentity(t testing.TB) *Identity {
	t.Helper()
	identity, err := fromSeeds(katSeeds())
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func generate(t testing.TB) *Identity {
	t.Helper()
	identity, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Destroy)
	return identity
}

func mustBundle(t testing.TB, identity *Identity, serial uint64) *Bundle {
	t.Helper()
	raw, err := identity.Bundle(serial, time.Unix(katCreated, 0))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func randomID(t testing.TB) ID {
	t.Helper()
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestIDStringFormat(t *testing.T) {
	for range 100 {
		id := randomID(t)
		s := id.String()
		if !strings.HasPrefix(s, IDPrefix) {
			t.Fatalf("%q lacks prefix", s)
		}
		groups := strings.Split(strings.TrimPrefix(s, IDPrefix), "-")
		if len(groups) != 13 {
			t.Fatalf("%q has %d groups, want 13", s, len(groups))
		}
		for _, g := range groups {
			if len(g) != 4 || strings.ToLower(g) != g {
				t.Fatalf("%q: bad group %q", s, g)
			}
		}
		compactForm := strings.ReplaceAll(strings.TrimPrefix(s, IDPrefix), "-", "")
		variants := []string{
			s,
			strings.ToUpper(s),
			strings.TrimPrefix(s, IDPrefix),
			compactForm,
			"QC1" + strings.ToUpper(compactForm),
			"  " + strings.ReplaceAll(s, "-", " ") + "\n",
			s[:30] + "\r\n" + s[30:],
		}
		for _, v := range variants {
			got, err := ParseID(v)
			if err != nil || got != id {
				t.Fatalf("ParseID(%q) = %v, %v; want %v", v, got, err, id)
			}
		}
	}
}

func TestParseIDRejects(t *testing.T) {
	valid := randomID(t).String()
	body := strings.ReplaceAll(strings.TrimPrefix(valid, IDPrefix), "-", "")

	// 256 bits fill 51 characters and one bit of the 52nd; the other 4
	// bits of the last character are padding. In the all-zero ID the last
	// character is "a" (0); "b" (1) sets a padding bit.
	zeroBody := strings.Repeat("a", idChars)
	nonZeroPadding := zeroBody[:idChars-1] + "b"

	cases := map[string]string{
		"empty":             "",
		"prefix only":       IDPrefix,
		"too short":         body[:idChars-1],
		"too long":          body + "a",
		"digit one":         body[:10] + "1" + body[11:],
		"digit zero":        body[:10] + "0" + body[11:],
		"digit eight":       body[:10] + "8" + body[11:],
		"padding character": body[:idChars-1] + "=",
		"trailing padding":  body + "====",
		"non-zero padding":  nonZeroPadding,
		"kelvin sign":       "K" + body[1:],
		"non-ascii letter":  body[:10] + "é" + body[12:],
		"other version":     "qc2-" + body,
		"double prefix":     "qc1-qc1-" + body,
		"underscore":        body[:10] + "_" + body[11:],
		"huge input":        strings.Repeat("-", maxIDInput) + body,
		"prefix in middle":  body[:20] + "qc1" + body[20:],
		"nul byte":          body[:10] + "\x00" + body[11:],
		"vertical tab":      body[:10] + "\v" + body[10:],
		"form feed":         body[:10] + "\f" + body[10:],
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if id, err := ParseID(input); !errors.Is(err, ErrInvalidID) {
				t.Errorf("ParseID(%q) = %v, %v; want ErrInvalidID", input, id, err)
			}
		})
	}
	if id, err := ParseID(zeroBody); err != nil || !id.IsZero() {
		t.Errorf("ParseID(all a) = %v, %v; want zero ID", id, err)
	}
}

func TestShortStringAndIsZero(t *testing.T) {
	id := randomID(t)
	short := id.ShortString()
	if !strings.HasPrefix(id.String(), short+"-") || len(short) != len(IDPrefix)+14 {
		t.Errorf("ShortString %q is not the first three groups of %q", short, id)
	}
	if id.IsZero() || !(ID{}).IsZero() {
		t.Error("IsZero is wrong")
	}
}

func TestKnownAnswerID(t *testing.T) {
	identity := katIdentity(t)
	if got := identity.ID().String(); got != katID {
		t.Errorf("KAT ID = %s, want %s", got, katID)
	}
	want := sha256.Sum256(append([]byte("qchat-identity-v1"), identity.SigningKey().Bytes()...))
	if identity.ID() != ID(want) {
		t.Error("ID is not SHA-256(domain || signing key)")
	}
}

func TestKnownAnswerBundle(t *testing.T) {
	identity := katIdentity(t)
	tbs, err := encMode.Marshal(bundleTBS{
		Version: BundleVersion,
		SigKey:  identity.SigningKey().Bytes(),
		KEMKey:  identity.KEMKey().Bytes(),
		Serial:  katSerial,
		Created: katCreated,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(tbs); hex.EncodeToString(got[:]) != katTBSHash {
		t.Errorf("SHA-256 of signed bundle fields = %x, want %s", got, katTBSHash)
	}

	if *updateKAT {
		raw, err := identity.Bundle(katSerial, time.Unix(katCreated, 0))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("testdata/kat_bundle.hex", []byte(hex.EncodeToString(raw)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	committed, err := os.ReadFile("testdata/kat_bundle.hex")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(committed)))
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(raw); hex.EncodeToString(got[:]) != katBundleHash {
		t.Errorf("SHA-256 of committed KAT bundle = %x, want %s", got, katBundleHash)
	}
	if len(raw) < len(tbs) || !bytes.Equal(raw[1:len(tbs)], tbs[1:]) {
		t.Error("committed bundle does not contain the signed fields in canonical form")
	}
	bundle, err := ParseBundleForID(raw, identity.ID())
	if err != nil {
		t.Fatalf("committed KAT bundle does not parse: %v", err)
	}
	if bundle.Serial != katSerial || bundle.Created.Unix() != katCreated {
		t.Errorf("KAT bundle serial %d created %v", bundle.Serial, bundle.Created)
	}
	if !bundle.KEMKey.Equal(identity.KEMKey()) || !bundle.SigningKey.Equal(identity.SigningKey()) {
		t.Error("KAT bundle keys differ from the KAT identity")
	}
}

func TestSecretRoundTrip(t *testing.T) {
	identity := generate(t)
	secret, err := identity.MarshalSecret()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Destroy()
	if restored.ID() != identity.ID() || !restored.KEMKey().Equal(identity.KEMKey()) {
		t.Fatal("restored identity differs")
	}
	again, err := restored.MarshalSecret()
	if err != nil || !bytes.Equal(again, secret) {
		t.Fatal("secret record is not stable across a round trip")
	}

	box, err := sealbox.Seal(identity.KEMKey(), []byte("info"), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := restored.OpenBox([]byte("info"), box); err != nil || string(pt) != "hello" {
		t.Fatalf("restored identity cannot decrypt: %q, %v", pt, err)
	}
}

func TestUnmarshalSecretRejects(t *testing.T) {
	edSeed, mldsaSeed, kemKey := katSeeds()
	encode := func(v any) []byte {
		b, err := encMode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	valid := encode(secretRecord{Version: 1, EdSeed: edSeed, MLDSASeed: mldsaSeed, KEMKey: kemKey})
	if _, err := UnmarshalSecret(valid); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}

	type reordered struct {
		KEMKey    []byte `cbor:"4,keyasint"`
		Version   uint8  `cbor:"1,keyasint"`
		EdSeed    []byte `cbor:"2,keyasint"`
		MLDSASeed []byte `cbor:"3,keyasint"`
	}
	unsorted, err := cbor.EncOptions{}.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical, err := unsorted.Marshal(reordered{KEMKey: kemKey, Version: 1, EdSeed: edSeed, MLDSASeed: mldsaSeed})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input []byte
		want  error
	}{
		{"empty", nil, ErrMalformedSecret},
		{"truncated", valid[:len(valid)-1], ErrMalformedSecret},
		{"trailing byte", append(append([]byte(nil), valid...), 0), ErrMalformedSecret},
		{"newer version", encode(secretRecord{Version: 2, EdSeed: edSeed, MLDSASeed: mldsaSeed, KEMKey: kemKey}), ErrUnsupportedVersion},
		{"newer version with new field", encode(map[int]any{1: 2, 2: edSeed, 3: mldsaSeed, 4: kemKey, 5: 1}), ErrUnsupportedVersion},
		{"version zero", encode(secretRecord{Version: 0, EdSeed: edSeed, MLDSASeed: mldsaSeed, KEMKey: kemKey}), ErrMalformedSecret},
		{"short seed", encode(secretRecord{Version: 1, EdSeed: edSeed[:31], MLDSASeed: mldsaSeed, KEMKey: kemKey}), ErrMalformedSecret},
		{"long kem key", encode(secretRecord{Version: 1, EdSeed: edSeed, MLDSASeed: mldsaSeed, KEMKey: append(kemKey, 0)}), ErrMalformedSecret},
		{"missing field", encode(map[int]any{1: 1, 2: edSeed, 3: mldsaSeed}), ErrMalformedSecret},
		{"unknown field", encode(map[int]any{1: 1, 2: edSeed, 3: mldsaSeed, 4: kemKey, 5: 0}), ErrMalformedSecret},
		{"text instead of bytes", encode(map[int]any{1: 1, 2: string(edSeed), 3: mldsaSeed, 4: kemKey}), ErrMalformedSecret},
		{"non-canonical order", nonCanonical, ErrMalformedSecret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := UnmarshalSecret(tc.input); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDestroy(t *testing.T) {
	identity, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	id := identity.ID()
	identity.Destroy()
	identity.Destroy()
	if identity.ID() != id || identity.SigningKey() == nil || identity.KEMKey() == nil {
		t.Error("public parts unavailable after Destroy")
	}
	if _, err := identity.Bundle(1, time.Now()); !errors.Is(err, ErrDestroyed) {
		t.Errorf("Bundle after Destroy: %v", err)
	}
	if _, err := identity.MarshalSecret(); !errors.Is(err, ErrDestroyed) {
		t.Errorf("MarshalSecret after Destroy: %v", err)
	}
	if _, err := identity.SignAuth(transport.Fingerprint{1}, make([]byte, NonceSize), make([]byte, BindingSize)); !errors.Is(err, ErrDestroyed) {
		t.Errorf("SignAuth after Destroy: %v", err)
	}
	if _, err := identity.SignMessage([]byte("x")); !errors.Is(err, ErrDestroyed) {
		t.Errorf("SignMessage after Destroy: %v", err)
	}
	if _, err := identity.OpenBox([]byte("info"), make([]byte, sealbox.Overhead)); !errors.Is(err, ErrDestroyed) {
		t.Errorf("OpenBox after Destroy: %v", err)
	}
}

func TestSafetyNumber(t *testing.T) {
	a := mustBundle(t, generate(t), 1)
	b := mustBundle(t, generate(t), 1)
	ab, ba := SafetyNumber(a, b), SafetyNumber(b, a)
	if ab != ba || len(ab) != safety.Digits {
		t.Fatalf("safety numbers %q and %q", ab, ba)
	}
	if ab != safety.Number(a.ID, a.SigningKey.Bytes(), b.ID, b.SigningKey.Bytes()) {
		t.Error("SafetyNumber does not match package safety")
	}
	qr := SafetyQR(a, b)
	if qr != SafetyQR(b, a) || !safety.VerifyQRPayload(qr, b.ID, b.SigningKey.Bytes(), a.ID, a.SigningKey.Bytes()) {
		t.Errorf("QR payload %q does not verify", qr)
	}
	c := mustBundle(t, generate(t), 1)
	if SafetyNumber(a, c) == ab || safety.VerifyQRPayload(qr, a.ID, a.SigningKey.Bytes(), c.ID, c.SigningKey.Bytes()) {
		t.Error("safety number does not depend on the peer")
	}
}
