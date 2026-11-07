package handshake

import (
	"errors"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/prekey"
)

var (
	_ Signer        = (*identity.Identity)(nil)
	_ Decapsulator  = (*identity.Identity)(nil)
	_ prekey.Signer = (*identity.Identity)(nil)
)

// TestSessionWithRealIdentities runs prekey generation, Initiate and Accept
// with real identities instead of the test signer, so the identity methods
// the handshake relies on are exercised end to end.
func TestSessionWithRealIdentities(t *testing.T) {
	now := time.Now()
	alice, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	aliceBundle, err := alice.Bundle(1, now)
	if err != nil {
		t.Fatal(err)
	}
	bobBundle, err := bob.Bundle(1, now)
	if err != nil {
		t.Fatal(err)
	}
	spk, err := prekey.GenerateSignedPrekey(bob, now, 21*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	opks, err := prekey.GenerateOneTimePrekeys(bob, 1)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ParseBundle(bob.ID(), bobBundle, spk.Public.Raw, opks[0].Public.Raw, now)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	init, err := Initiate(alice, aliceBundle, peer)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	spkLookup := func(id uint32) (*sealbox.PrivateKey, error) {
		if id != spk.Public.KeyID {
			return nil, errors.New("unknown")
		}
		return spk.Private, nil
	}
	opkLookup := func(id uint32) (*sealbox.PrivateKey, error) {
		if id != opks[0].Public.KeyID {
			return nil, errors.New("unknown")
		}
		return opks[0].Private, nil
	}
	acc, err := Accept(bob, alice.ID(), init.Init, spkLookup, opkLookup)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if acc.SK != init.SK {
		t.Fatal("initiator and responder derived different session keys")
	}
	if acc.Sender.ID != alice.ID() {
		t.Fatal("Accept reported the wrong sender")
	}
}
