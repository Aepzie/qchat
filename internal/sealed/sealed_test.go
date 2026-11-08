package sealed

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/identity"
)

// party is an identity with its verified bundle.
type party struct {
	ident  *identity.Identity
	bundle *identity.Bundle
}

var (
	partiesOnce sync.Once
	parties     [2]party
	partiesErr  error
)

// testParties returns two identities shared by all tests, since generating
// them is slow.
func testParties(t testing.TB) (alice, bob party) {
	t.Helper()
	partiesOnce.Do(func() {
		for i := range parties {
			ident, err := identity.Generate()
			if err != nil {
				partiesErr = err
				return
			}
			raw, err := ident.Bundle(1, time.Unix(1_700_000_000, 0))
			if err != nil {
				partiesErr = err
				return
			}
			bundle, err := identity.ParseBundle(raw)
			if err != nil {
				partiesErr = err
				return
			}
			parties[i] = party{ident: ident, bundle: bundle}
		}
	})
	if partiesErr != nil {
		t.Fatal(partiesErr)
	}
	return parties[0], parties[1]
}

// renamed opens boxes with a real identity's key but claims another ID.
type renamed struct {
	*identity.Identity
	id identity.ID
}

func (r renamed) ID() identity.ID { return r.id }

func mustSeal(t testing.TB, sender identity.ID, recipient *identity.Bundle, inner []byte) []byte {
	t.Helper()
	sealed, err := Seal(sender, recipient, inner)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed
}

func TestAccessKeyVerifierKAT(t *testing.T) {
	var key AccessKey
	for i := range key {
		key[i] = byte(i)
	}
	got := key.Verifier()
	want, _ := hex.DecodeString("5024d6314dc4738985ced39aa632aa046b04be243308d74c3b0b41ffdd7908cd")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("Verifier = %x, want %x", got, want)
	}
}

func TestAccessKeys(t *testing.T) {
	a, err := NewAccessKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAccessKey()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || a.IsZero() || a.Verifier() == b.Verifier() {
		t.Fatal("two fresh access keys collide")
	}
	parsed, err := ParseAccessKey(a[:])
	if err != nil || parsed != a {
		t.Fatalf("ParseAccessKey = %x, %v", parsed, err)
	}
	for name, raw := range map[string][]byte{
		"Short": a[:15], "Long": append(a[:], 0), "Zero": make([]byte, AccessKeySize), "Nil": nil,
	} {
		if _, err := ParseAccessKey(raw); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseAccessKey(%s) = %v, want ErrMalformed", name, err)
		}
	}
	if !(AccessKey{}).IsZero() {
		t.Fatal("zero key is not zero")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	alice, bob := testParties(t)
	for _, inner := range [][]byte{{0x01}, []byte("pairwise envelope"), bytes.Repeat([]byte{0xab}, 70_000)} {
		sealed := mustSeal(t, alice.ident.ID(), bob.bundle, inner)
		if !IsEnvelope(sealed) {
			t.Fatalf("IsEnvelope(%x...) = false", sealed[:8])
		}
		if len(sealed) > len(inner)+MaxOverhead {
			t.Fatalf("envelope of %d bytes for %d-byte inner, overhead above %d", len(sealed), len(inner), MaxOverhead)
		}
		if bytes.Contains(sealed, alice.bundle.ID[:]) || bytes.Contains(sealed, inner[:min(len(inner), 16)]) && len(inner) > 1 {
			t.Fatal("envelope reveals the sender ID or the inner payload")
		}
		opened, err := Open(bob.ident, sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if opened.ClaimedSender != alice.ident.ID() || !bytes.Equal(opened.Inner, inner) {
			t.Fatalf("Open = %x, %d bytes", opened.ClaimedSender, len(opened.Inner))
		}
	}
	if a, b := mustSeal(t, alice.ident.ID(), bob.bundle, []byte("x")), mustSeal(t, alice.ident.ID(), bob.bundle, []byte("x")); bytes.Equal(a, b) {
		t.Fatal("sealing is deterministic")
	}
}

func TestSealMaxInner(t *testing.T) {
	alice, bob := testParties(t)
	inner := bytes.Repeat([]byte{0xcd}, MaxInnerSize)
	sealed := mustSeal(t, alice.ident.ID(), bob.bundle, inner)
	if len(sealed) > MaxEnvelopeSize {
		t.Fatalf("maximal envelope is %d bytes, limit %d", len(sealed), MaxEnvelopeSize)
	}
	if len(sealed) != len(inner)+MaxOverhead {
		t.Fatalf("maximal envelope overhead %d, want exactly %d", len(sealed)-len(inner), MaxOverhead)
	}
	if opened, err := Open(bob.ident, sealed); err != nil || len(opened.Inner) != MaxInnerSize {
		t.Fatalf("Open maximal: %d bytes, %v", len(opened.Inner), err)
	}
	if _, err := Seal(alice.ident.ID(), bob.bundle, append(inner, 0)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Seal above MaxInnerSize: %v", err)
	}
}

func TestSealRejects(t *testing.T) {
	alice, bob := testParties(t)
	cases := map[string]error{}
	_, cases["NilBundle"] = Seal(alice.ident.ID(), nil, []byte("x"))
	_, cases["NoKEMKey"] = Seal(alice.ident.ID(), &identity.Bundle{ID: bob.bundle.ID}, []byte("x"))
	_, cases["ZeroSender"] = Seal(identity.ID{}, bob.bundle, []byte("x"))
	_, cases["EmptyInner"] = Seal(alice.ident.ID(), bob.bundle, nil)
	for name, err := range cases {
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v, want ErrInvalidArgument", name, err)
		}
	}
	if _, err := Open(nil, []byte{1}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("Open(nil recipient): %v", err)
	}
}

func TestOpenWrongRecipient(t *testing.T) {
	alice, bob := testParties(t)
	sealed := mustSeal(t, alice.ident.ID(), bob.bundle, []byte("for bob"))
	if _, err := Open(alice.ident, sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Open by another identity: %v, want ErrDecrypt", err)
	}
	impostor := renamed{Identity: bob.ident, id: alice.ident.ID()}
	if _, err := Open(impostor, sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Open under another recipient ID: %v, want ErrDecrypt", err)
	}
}

func TestOpenTampered(t *testing.T) {
	alice, bob := testParties(t)
	sealed := mustSeal(t, alice.ident.ID(), bob.bundle, []byte("integrity"))
	for _, i := range []int{0, 1, 2, 3, 4, 6, 7, 100, len(sealed) / 2, len(sealed) - 17, len(sealed) - 1} {
		tampered := bytes.Clone(sealed)
		tampered[i] ^= 0x01
		if _, err := Open(bob.ident, tampered); err == nil {
			t.Errorf("flipping byte %d still opens", i)
		}
	}
	for _, n := range []int{0, 1, 4, 8, len(sealed) - 1} {
		if _, err := Open(bob.ident, sealed[:n]); err == nil {
			t.Errorf("truncation to %d bytes still opens", n)
		}
	}
	if _, err := Open(bob.ident, append(bytes.Clone(sealed), 0)); !errors.Is(err, ErrMalformed) {
		t.Errorf("trailing byte: %v, want ErrMalformed", err)
	}
	if _, err := Open(bob.ident, make([]byte, MaxEnvelopeSize+1)); !errors.Is(err, ErrMalformed) {
		t.Errorf("oversized envelope: %v, want ErrMalformed", err)
	}
}

// sealContent seals an arbitrary content encoding to bob, bypassing Seal's
// checks.
func sealContent(t *testing.T, bob party, plaintext []byte) []byte {
	t.Helper()
	box, err := sealbox.Seal(bob.bundle.KEMKey, info(bob.bundle.ID), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	out, err := encMode.Marshal(envelope{Version: Version, Box: box})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOpenRejectsBadContent(t *testing.T) {
	alice, bob := testParties(t)
	id := alice.ident.ID()
	mustMarshal := func(v any) []byte {
		b, err := encMode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	type extra struct {
		Sender []byte `cbor:"1,keyasint"`
		Inner  []byte `cbor:"2,keyasint"`
		More   int    `cbor:"3,keyasint"`
	}
	type senderOnly struct {
		Sender []byte `cbor:"1,keyasint"`
	}
	cases := map[string][]byte{
		"ZeroSender":   mustMarshal(content{Sender: make([]byte, identity.IDSize), Inner: []byte("x")}),
		"ShortSender":  mustMarshal(content{Sender: id[:31], Inner: []byte("x")}),
		"EmptyInner":   mustMarshal(content{Sender: id[:], Inner: []byte{}}),
		"MissingInner": mustMarshal(senderOnly{Sender: id[:]}),
		"ExtraField":   mustMarshal(extra{Sender: id[:], Inner: []byte("x"), More: 1}),
		"NotAMap":      {0x80},
		"Empty":        {},
	}
	for name, plaintext := range cases {
		if _, err := Open(bob.ident, sealContent(t, bob, plaintext)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v, want ErrMalformed", name, err)
		}
	}
	if opened, err := Open(bob.ident, sealContent(t, bob, mustMarshal(content{Sender: id[:], Inner: []byte("ok")}))); err != nil || opened.ClaimedSender != id {
		t.Fatalf("control case: %v", err)
	}
}

func TestOpenRejectsBadOuter(t *testing.T) {
	_, bob := testParties(t)
	box := bytes.Repeat([]byte{0x11}, sealbox.Overhead+8)
	encode := func(v any) []byte {
		b, err := encMode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	type future struct {
		Version uint64 `cbor:"1,keyasint"`
		Box     []byte `cbor:"2,keyasint"`
		Extra   []byte `cbor:"3,keyasint"`
	}
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"VersionTwo", encode(envelope{Version: 2, Box: box}), ErrUnsupportedVersion},
		{"VersionZero", encode(envelope{Version: 0, Box: box}), ErrUnsupportedVersion},
		{"FutureLayout", encode(future{Version: 2, Box: box, Extra: []byte{1}}), ErrUnsupportedVersion},
		{"HugeVersion", encode(future{Version: 1 << 40, Box: box, Extra: []byte{1}}), ErrUnsupportedVersion},
		{"ExtraField", encode(future{Version: 1, Box: box, Extra: []byte{1}}), ErrMalformed},
		{"NoVersion", encode(struct {
			Box []byte `cbor:"2,keyasint"`
		}{box}), ErrMalformed},
		{"NonCanonicalLength", append([]byte{0xa2, 0x01, 0x01, 0x02, 0x5a, 0x00, 0x00, 0x04, 0x68}, box...), ErrMalformed},
		{"ShortBox", encode(envelope{Version: 1, Box: box[:sealbox.Overhead-1]}), ErrDecrypt},
		{"RandomBox", encode(envelope{Version: 1, Box: box}), ErrDecrypt},
		{"IndefiniteMap", []byte{0xbf, 0x01, 0x01, 0xff}, ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Open(bob.ident, tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("Open = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestOpenAfterDestroy(t *testing.T) {
	alice, _ := testParties(t)
	ident, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ident.Bundle(1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := identity.ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	sealed := mustSeal(t, alice.ident.ID(), bundle, []byte("late"))
	ident.Destroy()
	if _, err := Open(ident, sealed); !errors.Is(err, identity.ErrDestroyed) {
		t.Fatalf("Open after Destroy: %v, want ErrDestroyed", err)
	}
}

func TestIsEnvelope(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []byte
		want bool
	}{
		"Sealed":   {[]byte{0xa2, 0x01, 0x01, 0x02, 0x5a}, true},
		"Pairwise": {[]byte{0xa3, 0x01, 0x03, 0x03, 0x59}, false},
		"Group":    {[]byte{0xa5, 0x01, 0x04, 0x02, 0x58, 0x18}, false},
		"Short":    {[]byte{0xa2, 0x01}, false},
		"Empty":    {nil, false},
	} {
		if got := IsEnvelope(tc.in); got != tc.want {
			t.Errorf("IsEnvelope(%s) = %v, want %v", name, got, tc.want)
		}
	}
}

// FuzzOpen checks that Open never panics on arbitrary input and that
// whatever it accepts decrypts to a valid content.
func FuzzOpen(f *testing.F) {
	alice, bob := testParties(f)
	f.Add(mustSeal(f, alice.ident.ID(), bob.bundle, []byte("seed")))
	f.Add([]byte{0xa2, 0x01, 0x01, 0x02, 0x40})
	f.Add([]byte{0xa2, 0x01, 0x02, 0x02, 0x40})
	f.Add([]byte{0xa1, 0x01, 0x01})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		opened, err := Open(bob.ident, in)
		if err != nil {
			return
		}
		if opened.ClaimedSender.IsZero() || len(opened.Inner) == 0 {
			t.Fatalf("Open accepted invalid content: %+v", opened)
		}
	})
}
