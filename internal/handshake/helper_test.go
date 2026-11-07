package handshake

import (
	"errors"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/prekey"
	"github.com/fxamacker/cbor/v2"
)

var testNow = time.Unix(1_800_000_000, 0)

const testLifetime = 21 * 24 * time.Hour

// testParty is a real identity whose private keys were extracted from its
// secret record, so that it can implement [Signer], [Decapsulator] and
// prekey.Signer for tests. It also holds the party's prekeys.
type testParty struct {
	id        *identity.Identity
	sig       *hybridsig.PrivateKey
	kem       *sealbox.PrivateKey
	bundleRaw []byte
	bundle    *identity.Bundle
	spk       *prekey.SignedPrekeyPair
	opks      map[uint32]*prekey.OneTimePrekeyPair
	opkList   []*prekey.OneTimePrekeyPair
}

func newTestParty(t testing.TB) *testParty {
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
	p := &testParty{id: id, opks: map[uint32]*prekey.OneTimePrekeyPair{}}
	if p.sig, err = hybridsig.NewPrivateKeyFromSeeds(record.EdSeed, record.MLDSASeed); err != nil {
		t.Fatal(err)
	}
	if p.kem, err = sealbox.NewPrivateKey(record.KEMKey); err != nil {
		t.Fatal(err)
	}
	if p.bundleRaw, err = id.Bundle(1, testNow); err != nil {
		t.Fatal(err)
	}
	if p.bundle, err = identity.ParseBundleForID(p.bundleRaw, id.ID()); err != nil {
		t.Fatal(err)
	}
	if p.spk, err = prekey.GenerateSignedPrekey(p, testNow, testLifetime); err != nil {
		t.Fatal(err)
	}
	if p.opkList, err = prekey.GenerateOneTimePrekeys(p, 3); err != nil {
		t.Fatal(err)
	}
	for _, pair := range p.opkList {
		p.opks[pair.Public.KeyID] = pair
	}
	return p
}

func (p *testParty) ID() identity.ID { return p.id.ID() }

func (p *testParty) SignSessionInit(tbs []byte) ([]byte, error) {
	return p.sig.Sign(ContextSessionInit, tbs)
}

func (p *testParty) SignSignedPrekey(tbs []byte) ([]byte, error) {
	return p.sig.Sign(prekey.ContextSignedPrekey, tbs)
}

func (p *testParty) SignOneTimePrekey(tbs []byte) ([]byte, error) {
	return p.sig.Sign(prekey.ContextOneTimePrekey, tbs)
}

func (p *testParty) Decapsulate(enc, info []byte) ([sealbox.SharedSecretSize]byte, error) {
	return sealbox.Decapsulate(p.kem, enc, info)
}

var errNoSuchKey = errors.New("no such key")

func (p *testParty) lookupSPK(keyID uint32) (*sealbox.PrivateKey, []byte, error) {
	if keyID != p.spk.Public.KeyID {
		return nil, nil, errNoSuchKey
	}
	return p.spk.Private, p.spk.Public.Raw, nil
}

func (p *testParty) lookupOPK(keyID uint32) (*sealbox.PrivateKey, []byte, error) {
	pair, ok := p.opks[keyID]
	if !ok {
		return nil, nil, errNoSuchKey
	}
	return pair.Private, pair.Public.Raw, nil
}

// prekeyBundle returns p's verified prekey bundle, with the one-time prekey
// at index opk or without one-time prekey when opk is negative.
func (p *testParty) prekeyBundle(t testing.TB, opk int) *Bundle {
	t.Helper()
	var opkRaw []byte
	if opk >= 0 {
		opkRaw = p.opkList[opk].Public.Raw
	}
	bundle, err := ParseBundle(p.ID(), p.bundleRaw, p.spk.Public.Raw, opkRaw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}
