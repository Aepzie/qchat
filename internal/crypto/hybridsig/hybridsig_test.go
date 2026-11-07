package hybridsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

const (
	testContext = "qchat/test/v1"
	katContext  = "qchat/test/kat"
	katMessage  = "qchat hybrid signature known-answer test"

	// katPublicKeyHash is SHA-256 of the public key expanded from katSeeds.
	// It pins the exact key expansion of both components and the encoding
	// order, so a change in either is caught.
	katPublicKeyHash = "752de61d444c2c5a432d3da8df1136c48a961df97f236a40f9dfe20cbd8b3762"

	// katEd25519Public is the Ed25519 public key for the seed 00 01 .. 1f.
	katEd25519Public = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
)

func katSeeds() (edSeed, mldsaSeed []byte) {
	edSeed = make([]byte, SeedSize)
	mldsaSeed = make([]byte, SeedSize)
	for i := range edSeed {
		edSeed[i] = byte(i)
		mldsaSeed[i] = byte(0x80 + i)
	}
	return edSeed, mldsaSeed
}

func katKey(t testing.TB) *PrivateKey {
	t.Helper()
	edSeed, mldsaSeed := katSeeds()
	key, err := NewPrivateKeyFromSeeds(edSeed, mldsaSeed)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromSeeds: %v", err)
	}
	return key
}

// katSignature loads the committed signature produced once by katKey over
// katMessage. ML-DSA signing is randomised, so the test cannot recompute it;
// instead it checks that this fixed signature still verifies.
func katSignature(t testing.TB) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/kat_signature.hex")
	if err != nil {
		t.Fatalf("reading KAT signature: %v", err)
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decoding KAT signature: %v", err)
	}
	return sig
}

func newKey(t testing.TB) *PrivateKey {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func TestSizes(t *testing.T) {
	if PublicKeySize != 1984 {
		t.Errorf("PublicKeySize = %d, want 1984", PublicKeySize)
	}
	if SignatureSize != 64+3309 {
		t.Errorf("SignatureSize = %d, want %d", SignatureSize, 64+3309)
	}
	key := newKey(t)
	if got := len(key.Public().Bytes()); got != PublicKeySize {
		t.Errorf("len(Public().Bytes()) = %d, want %d", got, PublicKeySize)
	}
	sig, err := key.Sign(testContext, []byte("m"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Errorf("len(sig) = %d, want %d", len(sig), SignatureSize)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := newKey(t)
	for _, msg := range [][]byte{nil, {}, []byte("hello"), bytes.Repeat([]byte{0xa5}, 70000)} {
		sig, err := key.Sign(testContext, msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := key.Public().Verify(testContext, msg, sig); err != nil {
			t.Errorf("Verify(len %d): %v", len(msg), err)
		}
	}
}

func TestSigningIsHedged(t *testing.T) {
	key := newKey(t)
	msg := []byte("same message")
	a, err := key.Sign(testContext, msg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := key.Sign(testContext, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a[:ed25519.SignatureSize], b[:ed25519.SignatureSize]) {
		t.Error("Ed25519 halves differ; Ed25519 signing must be deterministic")
	}
	if bytes.Equal(a[ed25519.SignatureSize:], b[ed25519.SignatureSize:]) {
		t.Error("ML-DSA halves are identical; expected hedged (randomised) signing")
	}
}

// TestConstructionMatchesSpec verifies each component independently with the
// standard library, over an M' assembled by hand from the specification. This
// guards against the package silently drifting from the documented format.
func TestConstructionMatchesSpec(t *testing.T) {
	key := newKey(t)
	msg := []byte("spec check")
	sig, err := key.Sign(testContext, msg)
	if err != nil {
		t.Fatal(err)
	}

	var manual []byte
	manual = append(manual, "qchat-hybridsig-v1"...)
	manual = append(manual, byte(len(testContext)))
	manual = append(manual, testContext...)
	manual = append(manual, msg...)

	pub := key.Public().Bytes()
	if !ed25519.Verify(ed25519.PublicKey(pub[:32]), manual, sig[:64]) {
		t.Error("Ed25519 component does not verify over the specified M'")
	}
	mlPub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub[32:])
	if err != nil {
		t.Fatal(err)
	}
	if err := mldsa.Verify(mlPub, manual, sig[64:], &mldsa.Options{Context: testContext}); err != nil {
		t.Errorf("ML-DSA-65 component does not verify over the specified M' with ctx: %v", err)
	}
	if err := mldsa.Verify(mlPub, manual, sig[64:], nil); err == nil {
		t.Error("ML-DSA-65 component verifies without its FIPS 204 context")
	}
}

func TestKnownAnswer(t *testing.T) {
	key := katKey(t)
	pub := key.Public().Bytes()
	sum := sha256.Sum256(pub)
	if got := hex.EncodeToString(sum[:]); got != katPublicKeyHash {
		t.Errorf("SHA-256(public key) = %s, want %s", got, katPublicKeyHash)
	}
	if got := hex.EncodeToString(pub[:32]); got != katEd25519Public {
		t.Errorf("Ed25519 public key = %s, want %s", got, katEd25519Public)
	}

	sig := katSignature(t)
	if err := key.Public().Verify(katContext, []byte(katMessage), sig); err != nil {
		t.Fatalf("committed KAT signature does not verify: %v", err)
	}

	// The Ed25519 half is deterministic, so a fresh signature must reproduce
	// it exactly.
	fresh, err := key.Sign(katContext, []byte(katMessage))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fresh[:64], sig[:64]) {
		t.Error("fresh Ed25519 half differs from the committed KAT signature")
	}
}

func TestSeedsRoundTrip(t *testing.T) {
	key := newKey(t)
	edSeed, mldsaSeed := key.Seeds()
	if len(edSeed) != SeedSize || len(mldsaSeed) != SeedSize {
		t.Fatalf("seed lengths %d, %d", len(edSeed), len(mldsaSeed))
	}
	again, err := NewPrivateKeyFromSeeds(edSeed, mldsaSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Public().Equal(key.Public()) {
		t.Error("key rebuilt from seeds has a different public key")
	}

	// Seeds must return copies: scribbling over them must not change the key.
	clear(edSeed)
	clear(mldsaSeed)
	ed2, ml2 := key.Seeds()
	if bytes.Equal(ed2, edSeed) || bytes.Equal(ml2, mldsaSeed) {
		t.Error("Seeds returned aliases of internal state")
	}
}

func TestSeedsAreIndependent(t *testing.T) {
	edSeed, mldsaSeed := newKey(t).Seeds()
	if bytes.Equal(edSeed, mldsaSeed) {
		t.Error("the two component seeds are identical")
	}
}

func TestNewPrivateKeyFromSeedsRejectsBadLengths(t *testing.T) {
	good := make([]byte, SeedSize)
	for _, tc := range []struct{ ed, ml []byte }{
		{nil, good}, {good, nil},
		{make([]byte, SeedSize-1), good}, {good, make([]byte, SeedSize+1)},
		{make([]byte, 64), good},
	} {
		if _, err := NewPrivateKeyFromSeeds(tc.ed, tc.ml); !errors.Is(err, ErrInvalidSeed) {
			t.Errorf("lengths (%d, %d): err = %v, want ErrInvalidSeed", len(tc.ed), len(tc.ml), err)
		}
	}
}

func TestNewPrivateKeyFromSeedsCopiesInput(t *testing.T) {
	edSeed, mldsaSeed := katSeeds()
	key, err := NewPrivateKeyFromSeeds(edSeed, mldsaSeed)
	if err != nil {
		t.Fatal(err)
	}
	clear(edSeed)
	clear(mldsaSeed)
	gotEd, gotML := key.Seeds()
	wantEd, wantML := katSeeds()
	if !bytes.Equal(gotEd, wantEd) || !bytes.Equal(gotML, wantML) {
		t.Error("key aliases the caller's seed slices")
	}
}

func TestWrongContextFails(t *testing.T) {
	key := newKey(t)
	msg := []byte("bound to a context")
	sig, err := key.Sign("qchat/v1/bundle", msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []string{"qchat/v1/auth", "qchat/v1/bundlE", "qchat/v1/bundle ", "qchat/v1/bundl"} {
		if err := key.Public().Verify(ctx, msg, sig); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("Verify with ctx %q: err = %v, want ErrInvalidSignature", ctx, err)
		}
	}
}

// TestContextMessageBoundary checks that moving bytes between ctx and msg
// changes M', which is what the length prefix is for.
func TestContextMessageBoundary(t *testing.T) {
	key := newKey(t)
	sig, err := key.Sign("ab", []byte("cd"))
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Public().Verify("abc", []byte("d"), sig); err == nil {
		t.Error("signature over (ab, cd) verifies as (abc, d)")
	}
	if err := key.Public().Verify("a", []byte("bcd"), sig); err == nil {
		t.Error("signature over (ab, cd) verifies as (a, bcd)")
	}
}

func TestInvalidContextRejected(t *testing.T) {
	key := newKey(t)
	sig, err := key.Sign(testContext, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []string{"", strings.Repeat("a", MaxContextSize+1), "tab\there", "nul\x00", "caf\xc3\xa9", "\x7f"} {
		if _, err := key.Sign(ctx, []byte("m")); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("Sign(%q): err = %v, want ErrInvalidContext", ctx, err)
		}
		if err := key.Public().Verify(ctx, []byte("m"), sig); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("Verify(%q): err = %v, want ErrInvalidContext", ctx, err)
		}
	}
	longest := strings.Repeat("z", MaxContextSize)
	longSig, err := key.Sign(longest, []byte("m"))
	if err != nil {
		t.Fatalf("Sign with %d-byte ctx: %v", MaxContextSize, err)
	}
	if err := key.Public().Verify(longest, []byte("m"), longSig); err != nil {
		t.Errorf("Verify with %d-byte ctx: %v", MaxContextSize, err)
	}
}

func TestWrongMessageAndKeyFail(t *testing.T) {
	key := newKey(t)
	other := newKey(t)
	sig, err := key.Sign(testContext, []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Public().Verify(testContext, []byte("originaL"), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("modified message: err = %v", err)
	}
	if err := other.Public().Verify(testContext, []byte("original"), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("other key: err = %v", err)
	}
}

// TestTamperEverySignatureRegion flips one bit in a sample of positions
// covering both components (start, middle and end of each) and requires every
// variant to fail.
func TestTamperEverySignatureRegion(t *testing.T) {
	key := katKey(t)
	sig := katSignature(t)
	msg := []byte(katMessage)
	positions := []int{0, 31, 32, 63, 64, 65, 1000, 2000, SignatureSize - 2, SignatureSize - 1}
	for i := 0; i < SignatureSize; i += 97 {
		positions = append(positions, i)
	}
	for _, pos := range positions {
		for _, bit := range []byte{0x01, 0x80} {
			tampered := bytes.Clone(sig)
			tampered[pos] ^= bit
			if err := key.Public().Verify(katContext, msg, tampered); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("flip bit %#x at %d: err = %v, want ErrInvalidSignature", bit, pos, err)
			}
		}
	}
}

// TestComponentMixingFails combines halves of two valid signatures over
// different messages. Each half is individually valid for its own message, so
// this would succeed if either component were ignored.
func TestComponentMixingFails(t *testing.T) {
	key := newKey(t)
	a, err := key.Sign(testContext, []byte("message a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := key.Sign(testContext, []byte("message b"))
	if err != nil {
		t.Fatal(err)
	}
	mixed := append(bytes.Clone(a[:64]), b[64:]...)
	if err := key.Public().Verify(testContext, []byte("message a"), mixed); err == nil {
		t.Error("valid Ed25519 half with foreign ML-DSA half verifies")
	}
	if err := key.Public().Verify(testContext, []byte("message b"), mixed); err == nil {
		t.Error("foreign Ed25519 half with valid ML-DSA half verifies")
	}

	other := newKey(t)
	c, err := other.Sign(testContext, []byte("message a"))
	if err != nil {
		t.Fatal(err)
	}
	crossKey := append(bytes.Clone(a[:64]), c[64:]...)
	if err := key.Public().Verify(testContext, []byte("message a"), crossKey); err == nil {
		t.Error("ML-DSA half from another key verifies")
	}
}

func TestSignatureLengthChecks(t *testing.T) {
	key := katKey(t)
	sig := katSignature(t)
	msg := []byte(katMessage)
	cases := map[string][]byte{
		"nil":            nil,
		"empty":          {},
		"ed25519 only":   sig[:64],
		"mldsa only":     sig[64:],
		"truncated by 1": sig[:len(sig)-1],
		"extended by 1":  append(bytes.Clone(sig), 0),
		"doubled":        append(bytes.Clone(sig), sig...),
	}
	for name, s := range cases {
		if err := key.Public().Verify(katContext, msg, s); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: err = %v, want ErrInvalidSignature", name, err)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	key := newKey(t)
	encoding := key.Public().Bytes()
	parsed, err := ParsePublicKey(encoding)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !parsed.Equal(key.Public()) || !bytes.Equal(parsed.Bytes(), encoding) {
		t.Error("parsed key differs from original")
	}
	sig, err := key.Sign(testContext, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(testContext, []byte("m"), sig); err != nil {
		t.Errorf("parsed key does not verify: %v", err)
	}

	// The parser must copy its input.
	encoding[0] ^= 0xff
	encoding[PublicKeySize-1] ^= 0xff
	if !parsed.Equal(key.Public()) {
		t.Error("ParsePublicKey aliases its input")
	}

	for _, n := range []int{0, 1, 32, PublicKeySize - 1, PublicKeySize + 1, 2 * PublicKeySize} {
		if _, err := ParsePublicKey(make([]byte, n)); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("length %d: err = %v, want ErrInvalidPublicKey", n, err)
		}
	}
}

func TestBytesReturnsCopy(t *testing.T) {
	key := newKey(t)
	b := key.Public().Bytes()
	b[0] ^= 0xff
	if bytes.Equal(b, key.Public().Bytes()) {
		t.Error("Bytes returned an alias of internal state")
	}
}

func TestTamperedPublicKeyFails(t *testing.T) {
	key := katKey(t)
	sig := katSignature(t)
	for _, pos := range []int{0, 31, 32, 1000, PublicKeySize - 1} {
		encoding := key.Public().Bytes()
		encoding[pos] ^= 0x01
		pub, err := ParsePublicKey(encoding)
		if err != nil {
			continue
		}
		if err := pub.Verify(katContext, []byte(katMessage), sig); err == nil {
			t.Errorf("signature verifies under public key modified at byte %d", pos)
		}
	}
}

func TestEqual(t *testing.T) {
	a := newKey(t).Public()
	b := newKey(t).Public()
	if !a.Equal(a) || a.Equal(b) {
		t.Error("Equal gives wrong result for non-nil keys")
	}
	var nilKey *PublicKey
	if a.Equal(nil) || nilKey.Equal(a) || !nilKey.Equal(nil) {
		t.Error("Equal mishandles nil")
	}
}

func TestDestroy(t *testing.T) {
	key := newKey(t)
	pub := key.Public()
	sig, err := key.Sign(testContext, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
	if _, err := key.Sign(testContext, []byte("m")); !errors.Is(err, ErrDestroyed) {
		t.Errorf("Sign after Destroy: err = %v, want ErrDestroyed", err)
	}
	if ed, ml := key.Seeds(); ed != nil || ml != nil {
		t.Error("Seeds after Destroy returned key material")
	}
	if key.edSeed != [SeedSize]byte{} || key.mldsaSeed != [SeedSize]byte{} {
		t.Error("Destroy did not zero the seeds")
	}
	if err := pub.Verify(testContext, []byte("m"), sig); err != nil {
		t.Errorf("public key unusable after Destroy: %v", err)
	}
	key.Destroy()
}

func FuzzParsePublicKey(f *testing.F) {
	f.Add(katKey(f).Public().Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, PublicKeySize))
	f.Add(bytes.Repeat([]byte{0xff}, PublicKeySize))
	f.Fuzz(func(t *testing.T, encoding []byte) {
		pub, err := ParsePublicKey(encoding)
		if err != nil {
			if pub != nil {
				t.Fatal("non-nil key returned with error")
			}
			return
		}
		if len(encoding) != PublicKeySize {
			t.Fatalf("accepted %d-byte key", len(encoding))
		}
		if !bytes.Equal(pub.Bytes(), encoding) {
			t.Fatal("Bytes does not round-trip the parsed encoding")
		}
		again, err := ParsePublicKey(pub.Bytes())
		if err != nil || !again.Equal(pub) {
			t.Fatal("re-parsing the encoding failed")
		}
	})
}

func FuzzVerify(f *testing.F) {
	key := katKey(f)
	pub := key.Public().Bytes()
	sig := katSignature(f)
	f.Add(pub, katContext, []byte(katMessage), sig)
	f.Add(pub, katContext, []byte(katMessage), sig[:64])
	f.Add(pub, "", []byte{}, []byte{})
	f.Add(make([]byte, PublicKeySize), katContext, []byte(katMessage), make([]byte, SignatureSize))
	f.Fuzz(func(t *testing.T, pubEncoding []byte, ctx string, msg, signature []byte) {
		p, err := ParsePublicKey(pubEncoding)
		if err != nil {
			return
		}
		if p.Verify(ctx, msg, signature) != nil {
			return
		}
		// The only signature known to be valid is the committed one; any
		// other accepted input would indicate a forgery or a parsing flaw.
		if !bytes.Equal(pubEncoding, pub) || ctx != katContext || string(msg) != katMessage || !bytes.Equal(signature, sig) {
			t.Fatalf("unexpected valid signature: ctx=%q msg=%x", ctx, msg)
		}
	})
}
