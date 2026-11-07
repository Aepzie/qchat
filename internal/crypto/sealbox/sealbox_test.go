package sealbox

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// katPublicKeyHash is SHA-256 of the public key belonging to the private key
// 00 01 02 .. 1f. It pins the X-Wing key expansion and the serialisation.
const katPublicKeyHash = "c9a3565ffde4f72b51661be391ee13e46378d7f06dd5c8bf5af9d2cfb5b8336b"

var testInfo = []byte("qchat/test/v1")

var katInfo = []byte("qchat/test/kat")

const katPlaintext = "qchat sealbox known-answer test"

func katPrivateKeyBytes() []byte {
	seed := make([]byte, PrivateKeySize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func newKey(t testing.TB) *PrivateKey {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func TestSuiteIdentifiers(t *testing.T) {
	if got := hpke.MLKEM768X25519().ID(); got != 0x647a {
		t.Errorf("MLKEM768X25519 KEM ID = %#04x, want 0x647a", got)
	}
	if kem.ID() != KEMID || kdf.ID() != KDFID || aead.ID() != AEADID {
		t.Errorf("suite IDs = %#04x/%#04x/%#04x, want %#04x/%#04x/%#04x",
			kem.ID(), kdf.ID(), aead.ID(), KEMID, KDFID, AEADID)
	}
	if KDFID != 0x0001 || AEADID != 0x0003 {
		t.Error("KDF or AEAD identifier constant changed")
	}
}

func TestSizes(t *testing.T) {
	key := newKey(t)
	if got := len(key.Public().Bytes()); got != PublicKeySize {
		t.Errorf("public key length = %d, want %d", got, PublicKeySize)
	}
	if got := len(key.Bytes()); got != PrivateKeySize {
		t.Errorf("private key length = %d, want %d", got, PrivateKeySize)
	}
	for _, n := range []int{0, 1, 100, 65536} {
		box, err := Seal(key.Public(), testInfo, make([]byte, n))
		if err != nil {
			t.Fatal(err)
		}
		if len(box) != n+Overhead {
			t.Errorf("box for %d-byte plaintext has %d bytes, want %d", n, len(box), n+Overhead)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	key := newKey(t)
	for _, msg := range [][]byte{nil, {}, []byte("hello"), bytes.Repeat([]byte{7}, 70000)} {
		box, err := Seal(key.Public(), testInfo, msg)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		got, err := Open(key, testInfo, box)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("round trip of %d bytes returned different plaintext", len(msg))
		}
	}
}

func TestSealIsRandomised(t *testing.T) {
	key := newKey(t)
	a, err := Seal(key.Public(), testInfo, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(key.Public(), testInfo, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[:EncapsulatedKeySize], b[:EncapsulatedKeySize]) || bytes.Equal(a, b) {
		t.Error("two seals of the same plaintext share an encapsulation")
	}
}

func TestKnownAnswerPublicKey(t *testing.T) {
	key, err := NewPrivateKey(katPrivateKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(key.Public().Bytes())
	if got := hex.EncodeToString(sum[:]); got != katPublicKeyHash {
		t.Errorf("SHA-256(public key) = %s, want %s", got, katPublicKeyHash)
	}
	if !bytes.Equal(key.Bytes(), katPrivateKeyBytes()) {
		t.Error("Bytes does not return the deserialised private key")
	}
}

// TestPersistencePath checks that NewPrivateKey(Bytes()) restores the same
// key, and documents that HPKE DeriveKeyPair would not: it hashes its input
// into a different key and therefore must not be used to reload a key.
func TestPersistencePath(t *testing.T) {
	key := newKey(t)
	restored, err := NewPrivateKey(key.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Public().Equal(key.Public()) {
		t.Fatal("restored key has a different public key")
	}
	box, err := Seal(key.Public(), testInfo, []byte("persist"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(restored, testInfo, box); err != nil {
		t.Errorf("restored key cannot open: %v", err)
	}

	derived, err := hpke.MLKEM768X25519().DeriveKeyPair(key.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(derived.PublicKey().Bytes(), key.Public().Bytes()) {
		t.Error("DeriveKeyPair unexpectedly reproduces the key; revisit the documentation")
	}
}

func TestBytesReturnCopies(t *testing.T) {
	key := newKey(t)
	priv := key.Bytes()
	priv[0] ^= 0xff
	if bytes.Equal(priv, key.Bytes()) {
		t.Error("PrivateKey.Bytes aliases internal state")
	}
	pub := key.Public().Bytes()
	pub[0] ^= 0xff
	if bytes.Equal(pub, key.Public().Bytes()) {
		t.Error("PublicKey.Bytes aliases internal state")
	}

	input := katPrivateKeyBytes()
	k, err := NewPrivateKey(input)
	if err != nil {
		t.Fatal(err)
	}
	clear(input)
	if bytes.Equal(k.Bytes(), input) {
		t.Error("NewPrivateKey aliases its input")
	}
}

func TestParsePublicKey(t *testing.T) {
	key := newKey(t)
	parsed, err := ParsePublicKey(key.Public().Bytes())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !parsed.Equal(key.Public()) {
		t.Error("parsed key differs")
	}
	box, err := Seal(parsed, testInfo, []byte("via parsed key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key, testInfo, box); err != nil {
		t.Errorf("Open: %v", err)
	}
	for _, n := range []int{0, 32, 1184, PublicKeySize - 1, PublicKeySize + 1} {
		if _, err := ParsePublicKey(make([]byte, n)); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("length %d: err = %v, want ErrInvalidPublicKey", n, err)
		}
	}
}

func TestNewPrivateKeyRejectsBadLengths(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64, 2400} {
		if _, err := NewPrivateKey(make([]byte, n)); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("length %d: err = %v, want ErrInvalidPrivateKey", n, err)
		}
	}
}

func TestEmptyInfoRejected(t *testing.T) {
	key := newKey(t)
	for _, info := range [][]byte{nil, {}} {
		if _, err := Seal(key.Public(), info, []byte("x")); !errors.Is(err, ErrInvalidInfo) {
			t.Errorf("Seal: err = %v, want ErrInvalidInfo", err)
		}
	}
	box, err := Seal(key.Public(), testInfo, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(key, nil, box); !errors.Is(err, ErrInvalidInfo) || got != nil {
		t.Errorf("Open: got %v, err = %v, want nil, ErrInvalidInfo", got, err)
	}
}

func TestNilKeys(t *testing.T) {
	if _, err := Seal(nil, testInfo, []byte("x")); !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("Seal(nil): err = %v", err)
	}
	if _, err := Open(nil, testInfo, make([]byte, Overhead)); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("Open(nil): err = %v", err)
	}
}

func TestWrongInfoFails(t *testing.T) {
	key := newKey(t)
	box, err := Seal(key.Public(), []byte("qchat/v1/message|from|to"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range []string{"qchat/v1/message|from|tO", "qchat/v1/message|to|from", "qchat/v1/message|from|to ", "q"} {
		got, err := Open(key, []byte(info), box)
		if !errors.Is(err, ErrDecrypt) || got != nil {
			t.Errorf("info %q: got %q, err = %v, want nil, ErrDecrypt", info, got, err)
		}
	}
}

func TestWrongKeyFails(t *testing.T) {
	key := newKey(t)
	other := newKey(t)
	box, err := Seal(key.Public(), testInfo, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(other, testInfo, box); !errors.Is(err, ErrDecrypt) || got != nil {
		t.Errorf("got %q, err = %v, want nil, ErrDecrypt", got, err)
	}
}

// TestTamperEveryRegion flips bits in the ML-KEM ciphertext, the ephemeral
// X25519 key, the AEAD ciphertext and the tag. Each must cause [ErrDecrypt]
// with no plaintext returned.
func TestTamperEveryRegion(t *testing.T) {
	key := newKey(t)
	plaintext := []byte("a message that spans more than a single byte")
	box, err := Seal(key.Public(), testInfo, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	regions := map[string][]int{
		"ML-KEM ciphertext": {0, 1, 500, 1087},
		"X25519 public key": {1088, 1100, 1119},
		"AEAD ciphertext":   {EncapsulatedKeySize, EncapsulatedKeySize + len(plaintext)/2, EncapsulatedKeySize + len(plaintext) - 1},
		"Poly1305 tag":      {len(box) - TagSize, len(box) - 1},
	}
	for region, positions := range regions {
		for _, pos := range positions {
			tampered := bytes.Clone(box)
			tampered[pos] ^= 0x01
			got, err := Open(key, testInfo, tampered)
			if !errors.Is(err, ErrDecrypt) || got != nil {
				t.Errorf("%s byte %d: got %q, err = %v", region, pos, got, err)
			}
		}
	}
}

func TestTruncationAndExtensionFail(t *testing.T) {
	key := newKey(t)
	box, err := Seal(key.Public(), testInfo, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range [][]byte{
		nil, box[:1], box[:EncapsulatedKeySize], box[:Overhead-1], box[:len(box)-1],
		append(bytes.Clone(box), 0), box[1:],
	} {
		if got, err := Open(key, testInfo, variant); !errors.Is(err, ErrDecrypt) || got != nil {
			t.Errorf("%d-byte variant: got %q, err = %v", len(variant), got, err)
		}
	}
}

func TestDestroy(t *testing.T) {
	key := newKey(t)
	pub := key.Public()
	box, err := Seal(pub, testInfo, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
	if key.seed != [PrivateKeySize]byte{} {
		t.Error("Destroy did not clear the seed")
	}
	if key.Bytes() != nil {
		t.Error("Bytes after Destroy returned key material")
	}
	if _, err := Open(key, testInfo, box); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("Open after Destroy: err = %v", err)
	}
	if _, err := Seal(pub, testInfo, []byte("still works")); err != nil {
		t.Errorf("public key unusable after Destroy: %v", err)
	}
}

// katBox is a box sealed once to the KAT key with katInfo around
// katPlaintext. Sealing is randomised, so the box is committed rather than
// recomputed; opening it pins decapsulation, the key schedule and the AEAD.
func katBox(t testing.TB) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/kat_box.hex")
	if err != nil {
		t.Fatalf("reading KAT box: %v", err)
	}
	box, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decoding KAT box: %v", err)
	}
	return box
}

func TestKnownAnswerOpen(t *testing.T) {
	key, err := NewPrivateKey(katPrivateKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	box := katBox(t)
	if len(box) != len(katPlaintext)+Overhead {
		t.Fatalf("KAT box has %d bytes, want %d", len(box), len(katPlaintext)+Overhead)
	}
	got, err := Open(key, katInfo, box)
	if err != nil {
		t.Fatalf("committed KAT box does not open: %v", err)
	}
	if string(got) != katPlaintext {
		t.Errorf("KAT plaintext = %q, want %q", got, katPlaintext)
	}
}

func FuzzOpen(f *testing.F) {
	key, err := NewPrivateKey(katPrivateKeyBytes())
	if err != nil {
		f.Fatal(err)
	}
	valid := katBox(f)
	f.Add(katInfo, valid)
	f.Add(katInfo, valid[:Overhead])
	f.Add([]byte{}, valid)
	f.Add(katInfo, make([]byte, Overhead+3))
	f.Fuzz(func(t *testing.T, info, box []byte) {
		plaintext, err := Open(key, info, box)
		if err != nil {
			if plaintext != nil {
				t.Fatal("plaintext returned together with an error")
			}
			return
		}
		// The committed box is the only one known to be valid for this key;
		// anything else opening would be a forgery.
		if !bytes.Equal(info, katInfo) || !bytes.Equal(box, valid) || string(plaintext) != katPlaintext {
			t.Fatalf("Open accepted an unexpected box (%d bytes)", len(box))
		}
	})
}
