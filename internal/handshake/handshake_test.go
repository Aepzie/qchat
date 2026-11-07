package handshake

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/prekey"
)

func initiate(t *testing.T, from, to *testParty, opk int) *Initiation {
	t.Helper()
	initiation, err := InitiateAt(from, from.bundleRaw, to.prekeyBundle(t, opk), testNow)
	if err != nil {
		t.Fatal(err)
	}
	return initiation
}

func accept(to *testParty, relayFrom identity.ID, init []byte) (*Accepted, error) {
	return AcceptAt(to, relayFrom, init, to.lookupSPK, to.lookupOPK, testNow)
}

func TestSessionAgreement(t *testing.T) {
	alice, bob := newTestParty(t), newTestParty(t)
	for _, opk := range []int{-1, 0} {
		initiation := initiate(t, alice, bob, opk)
		if len(initiation.Init) > MaxInitSize {
			t.Fatalf("init of %d bytes exceeds MaxInitSize", len(initiation.Init))
		}
		accepted, err := accept(bob, alice.ID(), initiation.Init)
		if err != nil {
			t.Fatalf("opk %d: %v", opk, err)
		}
		if accepted.SK != initiation.SK || accepted.SK == ([SessionKeySize]byte{}) {
			t.Fatalf("opk %d: session keys differ", opk)
		}
		if accepted.Sender.ID != alice.ID() || !bytes.Equal(accepted.Sender.Raw, alice.bundleRaw) {
			t.Fatalf("opk %d: wrong sender", opk)
		}
		if accepted.SPKID != bob.spk.Public.KeyID || initiation.SPKID != accepted.SPKID {
			t.Fatalf("opk %d: SPKID mismatch", opk)
		}
		if !initiation.PeerInitialPub.Equal(bob.spk.Public.Pub) {
			t.Fatalf("opk %d: PeerInitialPub is not the signed prekey", opk)
		}
		wantOPK := uint32(0)
		if opk >= 0 {
			wantOPK = bob.opkList[opk].Public.KeyID
		}
		if accepted.OPKID != wantOPK || initiation.OPKID != wantOPK {
			t.Fatalf("opk %d: OPKID %d/%d, want %d", opk, accepted.OPKID, initiation.OPKID, wantOPK)
		}
		if !accepted.Created.Equal(testNow) || !initiation.Created.Equal(testNow) {
			t.Fatalf("opk %d: Created %v/%v, want %v", opk, accepted.Created, initiation.Created, testNow)
		}
		key, err := ReplayKey(initiation.Init)
		if err != nil || key != accepted.ReplayKey {
			t.Fatalf("opk %d: ReplayKey = %x, %v; Accepted.ReplayKey = %x", opk, key, err, accepted.ReplayKey)
		}
	}

	again := initiate(t, alice, bob, -1)
	first := initiate(t, alice, bob, -1)
	if again.SK == first.SK {
		t.Fatal("two session starts produced the same SK")
	}
}

func decodeInit(t *testing.T, init []byte) initWire {
	t.Helper()
	var wire initWire
	if err := decodeCanonical(init, &wire); err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestAcceptRejectsTampering(t *testing.T) {
	alice, bob, carol := newTestParty(t), newTestParty(t), newTestParty(t)
	initiation := initiate(t, alice, bob, 0)
	base := decodeInit(t, initiation.Init)

	flip := func(b []byte) []byte {
		out := bytes.Clone(b)
		out[len(out)/2] ^= 0x01
		return out
	}
	cases := []struct {
		name   string
		mutate func(w *initWire)
		want   error
	}{
		{"version 1", func(w *initWire) { w.Version = 1 }, ErrMalformed},
		{"version 3", func(w *initWire) { w.Version = 3 }, ErrMalformed},
		{"created", func(w *initWire) { w.Created-- }, ErrBadSignature},
		{"created zero", func(w *initWire) { w.Created = 0 }, ErrMalformed},
		{"created negative", func(w *initWire) { w.Created = -1 }, ErrMalformed},
		{"sender bundle corrupted", func(w *initWire) { w.SenderBundle = flip(w.SenderBundle) }, ErrMalformed},
		{"sender bundle replaced", func(w *initWire) { w.SenderBundle = carol.bundleRaw }, ErrWrongSender},
		{"spk id", func(w *initWire) { w.SPKID ^= 1 }, ErrBadSignature},
		{"opk id", func(w *initWire) { w.OPKID = bob.opkList[1].Public.KeyID }, ErrBadSignature},
		{"opk id removed", func(w *initWire) { w.OPKID = 0 }, ErrMalformed},
		{"enc ik", func(w *initWire) { w.EncIK = flip(w.EncIK) }, ErrBadSignature},
		{"enc spk", func(w *initWire) { w.EncSPK = flip(w.EncSPK) }, ErrBadSignature},
		{"enc opk", func(w *initWire) { w.EncOPK = flip(w.EncOPK) }, ErrBadSignature},
		{"enc opk removed", func(w *initWire) { w.EncOPK = nil }, ErrMalformed},
		{"enc ik short", func(w *initWire) { w.EncIK = w.EncIK[:100] }, ErrMalformed},
		{"sig", func(w *initWire) { w.Sig = flip(w.Sig) }, ErrBadSignature},
		{"sig short", func(w *initWire) { w.Sig = w.Sig[:64] }, ErrMalformed},
	}
	for _, tc := range cases {
		wire := base
		tc.mutate(&wire)
		raw, err := encMode.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := accept(bob, alice.ID(), raw); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}

	for name, raw := range map[string][]byte{
		"empty":     nil,
		"oversized": make([]byte, MaxInitSize+1),
		"truncated": initiation.Init[:len(initiation.Init)-1],
		"trailing":  append(bytes.Clone(initiation.Init), 0),
	} {
		if _, err := accept(bob, alice.ID(), raw); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}

	noOPK := decodeInit(t, initiate(t, alice, bob, -1).Init)
	withEmpty, err := encMode.Marshal(map[int]any{
		1: noOPK.Version, 2: noOPK.SenderBundle, 3: noOPK.SPKID, 4: noOPK.OPKID,
		5: noOPK.EncIK, 6: noOPK.EncSPK, 7: []byte{}, 8: noOPK.Sig, 9: noOPK.Created,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accept(bob, alice.ID(), withEmpty); !errors.Is(err, ErrMalformed) {
		t.Errorf("explicitly empty EncOPK: got %v, want ErrMalformed", err)
	}
}

func TestAcceptWrongSenderAndRecipient(t *testing.T) {
	alice, bob, carol := newTestParty(t), newTestParty(t), newTestParty(t)
	initiation := initiate(t, alice, bob, 0)

	if _, err := accept(bob, carol.ID(), initiation.Init); !errors.Is(err, ErrWrongSender) {
		t.Fatalf("wrong relayFrom: got %v, want ErrWrongSender", err)
	}

	carol.spk = bob.spk
	carol.opks = bob.opks
	if _, err := accept(carol, alice.ID(), initiation.Init); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("init for another recipient: got %v, want ErrBadSignature", err)
	}
}

func TestAcceptUnknownPrekeys(t *testing.T) {
	alice, bob := newTestParty(t), newTestParty(t)
	initiation := initiate(t, alice, bob, 0)

	noSPK := func(uint32) (*sealbox.PrivateKey, []byte, error) { return nil, nil, errNoSuchKey }
	if _, err := AcceptAt(bob, alice.ID(), initiation.Init, noSPK, bob.lookupOPK, testNow); !errors.Is(err, ErrUnknownPrekey) {
		t.Fatalf("unknown SPK: got %v, want ErrUnknownPrekey", err)
	}
	nilKey := func(uint32) (*sealbox.PrivateKey, []byte, error) { return nil, []byte{1}, nil }
	if _, err := AcceptAt(bob, alice.ID(), initiation.Init, bob.lookupSPK, nilKey, testNow); !errors.Is(err, ErrUnknownPrekey) {
		t.Fatalf("nil OPK: got %v, want ErrUnknownPrekey", err)
	}
	noRaw := func(id uint32) (*sealbox.PrivateKey, []byte, error) {
		priv, _, err := bob.lookupSPK(id)
		return priv, nil, err
	}
	if _, err := AcceptAt(bob, alice.ID(), initiation.Init, noRaw, bob.lookupOPK, testNow); !errors.Is(err, ErrUnknownPrekey) {
		t.Fatalf("SPK without public encoding: got %v, want ErrUnknownPrekey", err)
	}

	if _, err := accept(bob, alice.ID(), initiation.Init); err != nil {
		t.Fatal(err)
	}
	delete(bob.opks, initiation.OPKID)
	if _, err := accept(bob, alice.ID(), initiation.Init); !errors.Is(err, ErrUnknownPrekey) {
		t.Fatalf("replay after OPK deletion: got %v, want ErrUnknownPrekey", err)
	}

	calls := 0
	countOPK := func(uint32) (*sealbox.PrivateKey, []byte, error) { calls++; return nil, nil, errNoSuchKey }
	if _, err := AcceptAt(bob, alice.ID(), initiate(t, alice, bob, -1).Init, bob.lookupSPK, countOPK, testNow); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("OPK lookup called for an init without one-time prekey")
	}
}

func TestAcceptDoesNotLookUpBeforeSignature(t *testing.T) {
	alice, bob := newTestParty(t), newTestParty(t)
	wire := decodeInit(t, initiate(t, alice, bob, 0).Init)
	wire.Sig[0] ^= 1
	raw, err := encMode.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	probe := func(uint32) (*sealbox.PrivateKey, []byte, error) { called = true; return nil, nil, errNoSuchKey }
	if _, err := AcceptAt(bob, alice.ID(), raw, probe, probe, testNow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
	if called {
		t.Fatal("prekey lookup ran before the signature was verified")
	}
}

func TestParseBundle(t *testing.T) {
	alice, bob := newTestParty(t), newTestParty(t)

	if _, err := ParseBundle(bob.ID(), alice.bundleRaw, bob.spk.Public.Raw, nil, testNow); !errors.Is(err, identity.ErrIDMismatch) {
		t.Errorf("identity bundle of another ID: got %v", err)
	}
	if _, err := ParseBundle(bob.ID(), bob.bundleRaw, bob.spk.Public.Raw, nil, testNow.Add(testLifetime)); !errors.Is(err, prekey.ErrExpired) {
		t.Errorf("expired SPK: got %v, want prekey.ErrExpired", err)
	}
	if _, err := ParseBundle(bob.ID(), bob.bundleRaw, alice.spk.Public.Raw, nil, testNow); !errors.Is(err, prekey.ErrWrongOwner) {
		t.Errorf("SPK of another owner: got %v, want prekey.ErrWrongOwner", err)
	}
	if _, err := ParseBundle(bob.ID(), bob.bundleRaw, bob.spk.Public.Raw, alice.opkList[0].Public.Raw, testNow); !errors.Is(err, prekey.ErrWrongOwner) {
		t.Errorf("OPK of another owner: got %v, want prekey.ErrWrongOwner", err)
	}
	if _, err := ParseBundle(bob.ID(), bob.bundleRaw, bob.opkList[0].Public.Raw, nil, testNow); !errors.Is(err, prekey.ErrMalformed) {
		t.Errorf("OPK in place of SPK: got %v, want prekey.ErrMalformed", err)
	}
	bundle := bob.prekeyBundle(t, 1)
	if bundle.OneTime == nil || bundle.OneTime.KeyID != bob.opkList[1].Public.KeyID || bundle.SignedPrekey.KeyID != bob.spk.Public.KeyID {
		t.Error("parsed bundle has wrong prekeys")
	}
	if bob.prekeyBundle(t, -1).OneTime != nil {
		t.Error("bundle without OPK has one")
	}
}

func TestInitiateArguments(t *testing.T) {
	alice, bob := newTestParty(t), newTestParty(t)
	peer := bob.prekeyBundle(t, 0)
	if _, err := Initiate(alice, bob.bundleRaw, peer); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("foreign own bundle: got %v", err)
	}
	if _, err := Initiate(bob, bob.bundleRaw, peer); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("session with oneself: got %v", err)
	}
	if _, err := Initiate(alice, alice.bundleRaw, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("nil peer: got %v", err)
	}
	if _, err := Initiate(alice, alice.bundleRaw, &Bundle{Identity: peer.Identity}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("peer without SPK: got %v", err)
	}
	noRaw := *peer.SignedPrekey
	noRaw.Raw = nil
	if _, err := Initiate(alice, alice.bundleRaw, &Bundle{Identity: peer.Identity, SignedPrekey: &noRaw}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("SPK without encoding: got %v", err)
	}
	if _, err := InitiateAt(alice, alice.bundleRaw, peer, time.Unix(0, 0)); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("creation time 0: got %v", err)
	}
}

func TestAcceptFreshness(t *testing.T) {
	alice, bob := newTestParty(t), newTestParty(t)
	initiation := initiate(t, alice, bob, -1)
	cases := []struct {
		name string
		now  time.Time
		want error
	}{
		{"same second", testNow, nil},
		{"oldest accepted", testNow.Add(MaxInitAge), nil},
		{"too old", testNow.Add(MaxInitAge + time.Second), ErrStaleInit},
		{"far too old", testNow.Add(365 * 24 * time.Hour), ErrStaleInit},
		{"slightly in the future", testNow.Add(-MaxInitClockSkew), nil},
		{"too far in the future", testNow.Add(-MaxInitClockSkew - time.Second), ErrStaleInit},
	}
	for _, tc := range cases {
		probed := false
		probe := func(id uint32) (*sealbox.PrivateKey, []byte, error) { probed = true; return bob.lookupSPK(id) }
		_, err := AcceptAt(bob, alice.ID(), initiation.Init, probe, bob.lookupOPK, tc.now)
		if tc.want == nil && err != nil || !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
		if tc.want != nil && probed {
			t.Errorf("%s: prekey looked up for a stale init", tc.name)
		}
	}
	if MaxInitAge != 16*24*time.Hour || SignedPrekeyRetention != SignedPrekeyLifetime+UndeliveredTTL {
		t.Fatal("prekey policy constants disagree with the design document")
	}
}

func TestReplayKey(t *testing.T) {
	alice, bob := newTestParty(t), newTestParty(t)
	for _, opk := range []int{-1, 0} {
		initiation := initiate(t, alice, bob, opk)
		wire := decodeInit(t, initiation.Init)
		want := sha256.Sum256(append(append(bytes.Clone(wire.EncIK), wire.EncSPK...), wire.EncOPK...))
		got, err := ReplayKey(initiation.Init)
		if err != nil || got != want {
			t.Fatalf("opk %d: ReplayKey = %x, %v, want %x", opk, got, err, want)
		}

		resigned := wire
		msg, err := resigned.signedMessage(bob.ID())
		if err != nil {
			t.Fatal(err)
		}
		if resigned.Sig, err = alice.SignSessionInit(msg); err != nil {
			t.Fatal(err)
		}
		raw, err := encMode.Marshal(resigned)
		if err != nil {
			t.Fatal(err)
		}
		if again, err := ReplayKey(raw); err != nil || again != want {
			t.Fatalf("opk %d: re-signed init has a different replay key", opk)
		}
		if accepted, err := accept(bob, alice.ID(), raw); err != nil || accepted.ReplayKey != want {
			t.Fatalf("opk %d: re-signed init: %v", opk, err)
		}
	}
	first, err := ReplayKey(initiate(t, alice, bob, -1).Init)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReplayKey(initiate(t, alice, bob, -1).Init)
	if err != nil || first == second {
		t.Fatalf("two session starts share a replay key (%v)", err)
	}
	for name, raw := range map[string][]byte{"empty": nil, "garbage": {0xa0}, "oversized": make([]byte, MaxInitSize+1)} {
		if _, err := ReplayKey(raw); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}
}

func TestSessionKeyBindsPublicObjects(t *testing.T) {
	alice, bob := newTestParty(t), newTestParty(t)
	initiation := initiate(t, alice, bob, 0)
	flipped := func(find PrekeyLookup) PrekeyLookup {
		return func(id uint32) (*sealbox.PrivateKey, []byte, error) {
			priv, raw, err := find(id)
			raw = bytes.Clone(raw)
			if len(raw) > 0 {
				raw[len(raw)-1] ^= 1
			}
			return priv, raw, err
		}
	}
	for name, lookups := range map[string][2]PrekeyLookup{
		"signed prekey encoding":   {flipped(bob.lookupSPK), bob.lookupOPK},
		"one-time prekey encoding": {bob.lookupSPK, flipped(bob.lookupOPK)},
	} {
		accepted, err := AcceptAt(bob, alice.ID(), initiation.Init, lookups[0], lookups[1], testNow)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if accepted.SK == initiation.SK {
			t.Errorf("%s: SK does not depend on it", name)
		}
	}
}

func TestDeriveSKKnownAnswer(t *testing.T) {
	var a, b identity.ID
	for i := range a {
		a[i], b[i] = 0x01, 0x02
	}
	fill := func(v byte, n int) []byte { return bytes.Repeat([]byte{v}, n) }
	var ss [3][sealbox.SharedSecretSize]byte
	for i := range ss {
		copy(ss[i][:], fill(0xa1+byte(i), sealbox.SharedSecretSize))
	}
	encs := [][]byte{fill(0xb1, 1120), fill(0xb2, 1120), fill(0xb3, 1120)}
	withOPK := transcriptHashes(fill(0xc1, 100), fill(0xc2, 200), fill(0xc3, 300))
	withoutOPK := transcriptHashes(fill(0xc1, 100), fill(0xc2, 200), nil)

	t2 := transcript(a, b, 0x11223344, 0)
	wantT2 := "71636861742f76312f73657373696f6e" + hex.EncodeToString(a[:]) + hex.EncodeToString(b[:]) + "1122334400000000"
	if hex.EncodeToString(t2) != wantT2 {
		t.Fatalf("transcript = %x", t2)
	}

	cases := []struct {
		name    string
		t       []byte
		secrets [][sealbox.SharedSecretSize]byte
		encs    [][]byte
		objects []byte
		want    string
	}{
		{"with one-time prekey", transcript(a, b, 0x11223344, 0x55667788), ss[:], encs, withOPK,
			"44fd6678d00500f10f04ea0c68d782003c26383a18a4a1384643ad04bbed6d7c"},
		{"without one-time prekey", t2, ss[:2], encs[:2], withoutOPK,
			"b50afa220fb57d96339741e0aac1817e4164facf3e25fb33f0f41df3de627291"},
	}
	for _, tc := range cases {
		sk, err := deriveSK(tc.t, tc.secrets, tc.encs, tc.objects)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(sk[:]); got != tc.want {
			t.Errorf("%s: SK = %s, want %s", tc.name, got, tc.want)
		}
	}
	if _, err := deriveSK(t2, ss[:1], encs[:1], withoutOPK); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("one secret: got %v", err)
	}
	if _, err := deriveSK(t2, ss[:2], encs[:2], withoutOPK[:64]); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("short object hashes: got %v", err)
	}
}

func TestWinner(t *testing.T) {
	var small, large identity.ID
	small[0], large[0] = 0x01, 0x02
	small[31] = 0xff
	if Winner(small, large) != small || Winner(large, small) != small || Winner(small, small) != small {
		t.Fatal("Winner does not pick the smaller ID")
	}
}
