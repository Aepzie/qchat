package prekey

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

var testNow = time.Unix(1_800_000_000, 0)

const testLifetime = 21 * 24 * time.Hour

func generateSigned(t *testing.T, s *testSigner) *SignedPrekeyPair {
	t.Helper()
	pair, err := GenerateSignedPrekey(s, testNow, testLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func encodeSigned(t *testing.T, s *testSigner, wire signedWire, ctx string) []byte {
	t.Helper()
	tbs, err := encMode.Marshal(wire.tbs())
	if err != nil {
		t.Fatal(err)
	}
	if wire.Sig, err = s.sig.Sign(ctx, tbs); err != nil {
		t.Fatal(err)
	}
	raw, err := encMode.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeSigned(t *testing.T, raw []byte) signedWire {
	t.Helper()
	var wire signedWire
	if err := decodeCanonical(raw, &wire); err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestSignedPrekeyRoundTrip(t *testing.T) {
	s := newTestSigner(t)
	pair := generateSigned(t, s)
	if pair.Public.KeyID == 0 {
		t.Fatal("zero key ID")
	}
	if len(pair.Public.Raw) > MaxSize {
		t.Fatalf("encoding of %d bytes exceeds MaxSize", len(pair.Public.Raw))
	}
	if !pair.Private.Public().Equal(pair.Public.Pub) {
		t.Fatal("private key does not match public key")
	}
	parsed, err := ParseSignedPrekey(pair.Public.Raw, s.bundle, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Owner != s.ID() || parsed.KeyID != pair.Public.KeyID || !parsed.Pub.Equal(pair.Public.Pub) ||
		!parsed.Created.Equal(testNow) || !parsed.Expires.Equal(testNow.Add(testLifetime)) ||
		!bytes.Equal(parsed.Raw, pair.Public.Raw) {
		t.Fatalf("parsed prekey differs: %+v", parsed)
	}
}

func TestSignedPrekeyValidity(t *testing.T) {
	s := newTestSigner(t)
	pair := generateSigned(t, s)
	raw := pair.Public.Raw
	cases := []struct {
		name string
		now  time.Time
		err  error
	}{
		{"at creation", testNow, nil},
		{"just before expiry", testNow.Add(testLifetime - time.Second), nil},
		{"at expiry", testNow.Add(testLifetime), ErrExpired},
		{"long after expiry", testNow.Add(10 * testLifetime), ErrExpired},
		{"created within skew", testNow.Add(-MaxClockSkew), nil},
		{"created beyond skew", testNow.Add(-MaxClockSkew - time.Second), ErrExpired},
	}
	for _, tc := range cases {
		_, err := ParseSignedPrekey(raw, s.bundle, tc.now)
		if !errors.Is(err, tc.err) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.err)
		}
	}
}

func TestSignedPrekeyWrongOwner(t *testing.T) {
	alice, bob := newTestSigner(t), newTestSigner(t)
	pair := generateSigned(t, alice)
	if _, err := ParseSignedPrekey(pair.Public.Raw, bob.bundle, testNow); !errors.Is(err, ErrWrongOwner) {
		t.Fatalf("got %v, want ErrWrongOwner", err)
	}

	wire := decodeSigned(t, pair.Public.Raw)
	bobID := bob.ID()
	wire.Owner = bobID[:]
	forged := encodeSigned(t, alice, wire, ContextSignedPrekey)
	if _, err := ParseSignedPrekey(forged, bob.bundle, testNow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("prekey naming bob but signed by alice: got %v, want ErrBadSignature", err)
	}
}

func TestSignedPrekeyTampering(t *testing.T) {
	s := newTestSigner(t)
	pair := generateSigned(t, s)
	base := decodeSigned(t, pair.Public.Raw)

	mutations := map[string]func(w *signedWire){
		"key ID":  func(w *signedWire) { w.KeyID ^= 1 },
		"created": func(w *signedWire) { w.Created-- },
		"expires": func(w *signedWire) { w.Expires += 3600 },
		"pub":     func(w *signedWire) { w.Pub = generateSigned(t, s).Public.Pub.Bytes() },
		"sig":     func(w *signedWire) { w.Sig[10] ^= 1 },
	}
	for name, mutate := range mutations {
		wire := base
		wire.Pub = bytes.Clone(base.Pub)
		wire.Sig = bytes.Clone(base.Sig)
		mutate(&wire)
		raw, err := encMode.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseSignedPrekey(raw, s.bundle, testNow); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: got %v, want ErrBadSignature", name, err)
		}
	}
}

func TestSignedPrekeyMalformed(t *testing.T) {
	s := newTestSigner(t)
	pair := generateSigned(t, s)
	base := decodeSigned(t, pair.Public.Raw)

	withExtra, err := encMode.Marshal(map[int]any{
		1: base.Version, 2: base.Owner, 3: base.KeyID, 4: base.Pub, 5: base.Created, 6: base.Expires, 7: base.Sig, 8: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	withoutExpires, err := encMode.Marshal(map[int]any{
		1: base.Version, 2: base.Owner, 3: base.KeyID, 4: base.Pub, 5: base.Created, 7: base.Sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	zeroID := base
	zeroID.KeyID = 0
	backwards := base
	backwards.Expires = base.Created
	version2 := base
	version2.Version = 2
	shortPub := base
	shortPub.Pub = base.Pub[:100]

	inputs := map[string][]byte{
		"empty":           nil,
		"oversized":       make([]byte, MaxSize+1),
		"truncated":       pair.Public.Raw[:len(pair.Public.Raw)-1],
		"trailing byte":   append(bytes.Clone(pair.Public.Raw), 0),
		"unknown field":   withExtra,
		"missing field":   withoutExpires,
		"zero key ID":     encodeSigned(t, s, zeroID, ContextSignedPrekey),
		"expires<created": encodeSigned(t, s, backwards, ContextSignedPrekey),
		"version 2":       encodeSigned(t, s, version2, ContextSignedPrekey),
		"short pub":       encodeSigned(t, s, shortPub, ContextSignedPrekey),
	}
	for name, raw := range inputs {
		if _, err := ParseSignedPrekey(raw, s.bundle, testNow); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}
	if _, err := ParseSignedPrekey(pair.Public.Raw, nil, testNow); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("nil bundle: got %v", err)
	}
}

func TestContextSeparation(t *testing.T) {
	s := newTestSigner(t)
	pair := generateSigned(t, s)
	wire := decodeSigned(t, pair.Public.Raw)
	wrongCtx := encodeSigned(t, s, wire, ContextOneTimePrekey)
	if _, err := ParseSignedPrekey(wrongCtx, s.bundle, testNow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("signed prekey signed under the one-time context: got %v, want ErrBadSignature", err)
	}

	opks, err := GenerateOneTimePrekeys(s, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSignedPrekey(opks[0].Public.Raw, s.bundle, testNow); !errors.Is(err, ErrMalformed) {
		t.Fatalf("one-time prekey parsed as signed prekey: got %v, want ErrMalformed", err)
	}
	if _, err := ParseOneTimePrekey(pair.Public.Raw, s.bundle); !errors.Is(err, ErrMalformed) {
		t.Fatalf("signed prekey parsed as one-time prekey: got %v, want ErrMalformed", err)
	}

	var otw oneTimeWire
	if err := decodeCanonical(opks[0].Public.Raw, &otw); err != nil {
		t.Fatal(err)
	}
	tbs, err := encMode.Marshal(otw.tbs())
	if err != nil {
		t.Fatal(err)
	}
	if otw.Sig, err = s.sig.Sign(ContextSignedPrekey, tbs); err != nil {
		t.Fatal(err)
	}
	raw, err := encMode.Marshal(otw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOneTimePrekey(raw, s.bundle); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("one-time prekey signed under the signed-prekey context: got %v, want ErrBadSignature", err)
	}
}

func TestOneTimePrekeys(t *testing.T) {
	alice, bob := newTestSigner(t), newTestSigner(t)
	pairs, err := GenerateOneTimePrekeys(alice, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 20 {
		t.Fatalf("got %d keys", len(pairs))
	}
	seen := map[uint32]bool{}
	for _, pair := range pairs {
		if pair.Public.KeyID == 0 || seen[pair.Public.KeyID] {
			t.Fatalf("zero or duplicate key ID %d", pair.Public.KeyID)
		}
		seen[pair.Public.KeyID] = true
		parsed, err := ParseOneTimePrekey(pair.Public.Raw, alice.bundle)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.KeyID != pair.Public.KeyID || !parsed.Pub.Equal(pair.Private.Public()) || parsed.Owner != alice.ID() {
			t.Fatal("parsed one-time prekey differs")
		}
	}
	if _, err := ParseOneTimePrekey(pairs[0].Public.Raw, bob.bundle); !errors.Is(err, ErrWrongOwner) {
		t.Fatalf("other owner: got %v, want ErrWrongOwner", err)
	}
	tampered := bytes.Clone(pairs[0].Public.Raw)
	tampered[len(tampered)-5] ^= 1
	if _, err := ParseOneTimePrekey(tampered, alice.bundle); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered: got %v, want ErrBadSignature", err)
	}
	for _, n := range []int{0, -1, MaxOneTimePrekeysPerCall + 1} {
		if _, err := GenerateOneTimePrekeys(alice, n); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("n=%d: got %v", n, err)
		}
	}
	if _, err := GenerateSignedPrekey(alice, testNow, 0); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("zero lifetime: got %v", err)
	}
}

func TestPrivateRecord(t *testing.T) {
	s := newTestSigner(t)
	pair := generateSigned(t, s)
	record, err := MarshalPrivate(pair.Public.KeyID, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	keyID, priv, err := UnmarshalPrivate(record)
	if err != nil {
		t.Fatal(err)
	}
	if keyID != pair.Public.KeyID || !priv.Public().Equal(pair.Public.Pub) {
		t.Fatal("private record round trip differs")
	}
	if _, err := MarshalPrivate(0, pair.Private); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("zero key ID: got %v", err)
	}
	zeroID, err := encMode.Marshal(privateRecord{Version: PrivateVersion, KeyID: 0, Priv: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	shortKey, err := encMode.Marshal(privateRecord{Version: PrivateVersion, KeyID: 7, Priv: make([]byte, 31)})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"empty": nil, "truncated": record[:len(record)-1], "trailing": append(bytes.Clone(record), 0),
		"zero ID": zeroID, "short key": shortKey,
	} {
		if _, _, err := UnmarshalPrivate(raw); !errors.Is(err, ErrMalformedPrivate) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
