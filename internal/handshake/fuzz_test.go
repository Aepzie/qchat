package handshake

import (
	"bytes"
	"testing"
)

func FuzzAccept(f *testing.F) {
	alice, bob := newTestParty(f), newTestParty(f)
	var seeds [][]byte
	for _, opk := range []int{-1, 0} {
		initiation, err := InitiateAt(alice, alice.bundleRaw, bob.prekeyBundle(f, opk), testNow)
		if err != nil {
			f.Fatal(err)
		}
		seeds = append(seeds, initiation.Init)
		f.Add(initiation.Init)
	}
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, init []byte) {
		accepted, err := AcceptAt(bob, alice.ID(), init, bob.lookupSPK, bob.lookupOPK, testNow)
		if err != nil {
			return
		}
		if accepted.Sender.ID != alice.ID() {
			t.Fatal("accepted init from an unexpected sender")
		}
		for _, seed := range seeds {
			if bytes.Equal(seed, init) {
				return
			}
		}
		t.Fatal("accepted an init that Alice never signed")
	})
}

func FuzzParseBundle(f *testing.F) {
	bob, mallory := newTestParty(f), newTestParty(f)
	want := bob.ID()
	f.Add(bob.bundleRaw, bob.spk.Public.Raw, bob.opkList[0].Public.Raw)
	f.Add(bob.bundleRaw, bob.spk.Public.Raw, []byte(nil))
	f.Add(mallory.bundleRaw, mallory.spk.Public.Raw, mallory.opkList[0].Public.Raw)
	f.Add(bob.bundleRaw, mallory.spk.Public.Raw, []byte(nil))
	f.Add(bob.bundleRaw, bob.spk.Public.Raw, mallory.opkList[0].Public.Raw)
	f.Add([]byte{0xa0}, []byte{0xa0}, []byte{0xa0})
	f.Fuzz(func(t *testing.T, identityBundle, spk, opk []byte) {
		bundle, err := ParseBundle(want, identityBundle, spk, opk, testNow)
		if err != nil {
			if bundle != nil {
				t.Fatal("non-nil bundle with error")
			}
			return
		}
		if bundle.Identity == nil || bundle.Identity.ID != want {
			t.Fatal("accepted a bundle of another identity")
		}
		if bundle.SignedPrekey == nil {
			t.Fatal("accepted a bundle without signed prekey")
		}
		if (bundle.OneTime == nil) != (len(opk) == 0) {
			t.Fatalf("one-time prekey presence %v for %d input bytes", bundle.OneTime != nil, len(opk))
		}
	})
}
