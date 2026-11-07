package handshake

import (
	"bytes"
	"testing"
)

func FuzzAccept(f *testing.F) {
	alice, bob := newTestParty(f), newTestParty(f)
	var seeds [][]byte
	for _, opk := range []int{-1, 0} {
		initiation, err := Initiate(alice, alice.bundleRaw, bob.prekeyBundle(f, opk))
		if err != nil {
			f.Fatal(err)
		}
		seeds = append(seeds, initiation.Init)
		f.Add(initiation.Init)
	}
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, init []byte) {
		accepted, err := Accept(bob, alice.ID(), init, bob.lookupSPK, bob.lookupOPK)
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
