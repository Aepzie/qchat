package prekey

import (
	"testing"
	"time"

	"github.com/Aepzie/qchat/internal/crypto/hybridsig"
	"github.com/Aepzie/qchat/internal/identity"
	"github.com/fxamacker/cbor/v2"
)

// testSigner implements [Signer] for tests. It extracts the signing key of
// a real identity from its secret record, so the prekeys it produces verify
// against the identity's real bundle.
type testSigner struct {
	id     *identity.Identity
	sig    *hybridsig.PrivateKey
	bundle *identity.Bundle
}

func newTestSigner(t testing.TB) *testSigner {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := id.MarshalSecret()
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Version   uint8  `cbor:"1,keyasint"`
		EdSeed    []byte `cbor:"2,keyasint"`
		MLDSASeed []byte `cbor:"3,keyasint"`
		KEMKey    []byte `cbor:"4,keyasint"`
	}
	if err := cbor.Unmarshal(secret, &record); err != nil {
		t.Fatal(err)
	}
	sig, err := hybridsig.NewPrivateKeyFromSeeds(record.EdSeed, record.MLDSASeed)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := id.Bundle(1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := identity.ParseBundleForID(raw, id.ID())
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{id: id, sig: sig, bundle: bundle}
}

func (s *testSigner) ID() identity.ID { return s.id.ID() }

func (s *testSigner) SignSignedPrekey(tbs []byte) ([]byte, error) {
	return s.sig.Sign(ContextSignedPrekey, tbs)
}

func (s *testSigner) SignOneTimePrekey(tbs []byte) ([]byte, error) {
	return s.sig.Sign(ContextOneTimePrekey, tbs)
}
