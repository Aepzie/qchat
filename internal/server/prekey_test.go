package server

import (
	"bytes"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/fxamacker/cbor/v2"

	"github.com/Aepzie/qchat/internal/crypto/hybridsig"
	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/prekey"
	"github.com/Aepzie/qchat/internal/protocol"
)

// prekeySigner signs prekeys with the signing key of a test identity, which
// it extracts from the identity's secret record, so the prekeys verify
// against the identity's registered bundle.
type prekeySigner struct {
	id  identity.ID
	key *hybridsig.PrivateKey
}

func newPrekeySigner(t *testing.T, u testUser) *prekeySigner {
	t.Helper()
	secret, err := u.ident.MarshalSecret()
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
	key, err := hybridsig.NewPrivateKeyFromSeeds(record.EdSeed, record.MLDSASeed)
	if err != nil {
		t.Fatal(err)
	}
	return &prekeySigner{id: u.ident.ID(), key: key}
}

func (p *prekeySigner) ID() identity.ID { return p.id }

func (p *prekeySigner) SignSignedPrekey(tbs []byte) ([]byte, error) {
	return p.key.Sign(prekey.ContextSignedPrekey, tbs)
}

func (p *prekeySigner) SignOneTimePrekey(tbs []byte) ([]byte, error) {
	return p.key.Sign(prekey.ContextOneTimePrekey, tbs)
}

// signedPrekey returns an encoded signed prekey of u valid from now.
func signedPrekey(t *testing.T, signer *prekeySigner, now time.Time) *prekey.SignedPrekey {
	t.Helper()
	pair, err := prekey.GenerateSignedPrekey(signer, now, 21*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return pair.Public
}

// oneTimePrekeys returns n encoded one-time prekeys.
func oneTimePrekeys(t *testing.T, signer *prekeySigner, n int) [][]byte {
	t.Helper()
	pairs, err := prekey.GenerateOneTimePrekeys(signer, n)
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, len(pairs))
	for i, pair := range pairs {
		out[i] = pair.Public.Raw
	}
	return out
}

// uploadPrekeys sends a PrekeyUpload and returns the PrekeyStatus answer.
func uploadPrekeys(t *testing.T, conn *websocket.Conn, id uint64, upload protocol.PrekeyUpload) protocol.PrekeyStatus {
	t.Helper()
	sendFrame(t, conn, protocol.TypePrekeyUpload, id, upload)
	return expectBody[protocol.PrekeyStatus](t, conn, protocol.TypePrekeyStatus, id)
}

// requestPrekeys sends a PrekeyRequest for owner and returns the answer.
func requestPrekeys(t *testing.T, conn *websocket.Conn, id uint64, owner []byte) protocol.PrekeyResponse {
	t.Helper()
	sendFrame(t, conn, protocol.TypePrekeyRequest, id, protocol.PrekeyRequest{ID: owner})
	return expectBody[protocol.PrekeyResponse](t, conn, protocol.TypePrekeyResponse, id)
}

// tamper returns a copy of b with its last byte flipped.
func tamper(b []byte) []byte {
	out := bytes.Clone(b)
	out[len(out)-1] ^= 1
	return out
}

func TestPrekeyUploadAndRequest(t *testing.T) {
	ts := startServer(t, serverOptions{config: openMode, tweak: func(s *Server) { s.uploadBurst = 1000 }})
	alice, bob := newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	bobConn := online(t, ts, bob)
	aliceSigner, bobSigner := newPrekeySigner(t, alice), newPrekeySigner(t, bob)

	anonymous := openSession(t, ts)
	sendFrame(t, anonymous, protocol.TypePrekeyUpload, 1, protocol.PrekeyUpload{})
	expectReject(t, anonymous, 1, protocol.ErrCodeUnauthorized)
	sendFrame(t, anonymous, protocol.TypePrekeyRequest, 2, protocol.PrekeyRequest{ID: alice.id()})
	expectReject(t, anonymous, 2, protocol.ErrCodeUnauthorized)

	sendFrame(t, bobConn, protocol.TypePrekeyRequest, 3, protocol.PrekeyRequest{ID: alice.id()})
	expectReject(t, bobConn, 3, protocol.ErrCodeNotFound)
	sendFrame(t, bobConn, protocol.TypePrekeyRequest, 4, protocol.PrekeyRequest{ID: newUser(t).id()})
	expectReject(t, bobConn, 4, protocol.ErrCodeNotFound)

	if status := uploadPrekeys(t, aliceConn, 5, protocol.PrekeyUpload{}); status != (protocol.PrekeyStatus{}) {
		t.Fatalf("empty upload before any prekey: %+v", status)
	}
	oneTime := oneTimePrekeys(t, aliceSigner, 2)
	sendFrame(t, aliceConn, protocol.TypePrekeyUpload, 6, protocol.PrekeyUpload{OneTimePrekeys: oneTime})
	expectBody[protocol.PrekeyStatus](t, aliceConn, protocol.TypePrekeyStatus, 6)
	sendFrame(t, bobConn, protocol.TypePrekeyRequest, 7, protocol.PrekeyRequest{ID: alice.id()})
	expectReject(t, bobConn, 7, protocol.ErrCodeNotFound)

	signed := signedPrekey(t, aliceSigner, time.Now())
	status := uploadPrekeys(t, aliceConn, 8, protocol.PrekeyUpload{SignedPrekey: signed.Raw, OneTimePrekeys: oneTime})
	if status.OneTimeRemaining != 2 || status.SignedPrekeyExpires != signed.Expires.Unix() {
		t.Fatalf("status after upload %+v, want 2 one-time prekeys and expiry %d", status, signed.Expires.Unix())
	}

	rejected := []struct {
		name   string
		upload protocol.PrekeyUpload
	}{
		{"SignedByOtherIdentity", protocol.PrekeyUpload{SignedPrekey: signedPrekey(t, bobSigner, time.Now()).Raw}},
		{"TamperedSigned", protocol.PrekeyUpload{SignedPrekey: tamper(signed.Raw)}},
		{"ExpiredSigned", protocol.PrekeyUpload{SignedPrekey: signedPrekey(t, aliceSigner, time.Now().Add(-30*24*time.Hour)).Raw}},
		{"OneTimeAsSigned", protocol.PrekeyUpload{SignedPrekey: oneTime[0]}},
		{"OneTimeOfOtherIdentity", protocol.PrekeyUpload{OneTimePrekeys: append(oneTimePrekeys(t, aliceSigner, 1), oneTimePrekeys(t, bobSigner, 1)...)}},
		{"TamperedOneTime", protocol.PrekeyUpload{OneTimePrekeys: [][]byte{tamper(oneTimePrekeys(t, aliceSigner, 1)[0])}}},
		{"SignedAsOneTime", protocol.PrekeyUpload{OneTimePrekeys: [][]byte{signed.Raw}}},
		{"Garbage", protocol.PrekeyUpload{OneTimePrekeys: [][]byte{[]byte("not a prekey")}}},
	}
	for i, tc := range rejected {
		id := uint64(20 + i)
		sendFrame(t, aliceConn, protocol.TypePrekeyUpload, id, tc.upload)
		frame := expectError(t, aliceConn, protocol.ErrCodeBadRequest)
		if frame.ID != id {
			t.Fatalf("%s: Error ID %d, want %d", tc.name, frame.ID, id)
		}
	}
	if status := uploadPrekeys(t, aliceConn, 30, protocol.PrekeyUpload{}); status.OneTimeRemaining != 2 || status.SignedPrekeyExpires != signed.Expires.Unix() {
		t.Fatalf("rejected uploads changed the stored prekeys: %+v", status)
	}

	aliceBundle, err := identity.ParseBundleForID(alice.bundle, alice.ident.ID())
	if err != nil {
		t.Fatal(err)
	}
	handedOut := make(map[string]bool)
	for i := range 2 {
		response := requestPrekeys(t, bobConn, uint64(40+i), alice.id())
		if !bytes.Equal(response.Bundle, alice.bundle) || !bytes.Equal(response.SignedPrekey, signed.Raw) {
			t.Fatalf("request %d returned another bundle or signed prekey", i)
		}
		if _, err := prekey.ParseSignedPrekey(response.SignedPrekey, aliceBundle, time.Now()); err != nil {
			t.Fatalf("served signed prekey does not verify: %v", err)
		}
		if _, err := prekey.ParseOneTimePrekey(response.OneTimePrekey, aliceBundle); err != nil {
			t.Fatalf("served one-time prekey does not verify: %v", err)
		}
		if handedOut[string(response.OneTimePrekey)] {
			t.Fatal("one-time prekey handed out twice")
		}
		handedOut[string(response.OneTimePrekey)] = true
	}
	if response := requestPrekeys(t, bobConn, 42, alice.id()); response.OneTimePrekey != nil || !bytes.Equal(response.SignedPrekey, signed.Raw) {
		t.Fatalf("exhausted bundle: one-time prekey %x, signed prekey changed %v", response.OneTimePrekey, !bytes.Equal(response.SignedPrekey, signed.Raw))
	}
	if status := uploadPrekeys(t, aliceConn, 43, protocol.PrekeyUpload{}); status.OneTimeRemaining != 0 {
		t.Fatalf("status after exhaustion %+v", status)
	}
	if status := uploadPrekeys(t, aliceConn, 44, protocol.PrekeyUpload{OneTimePrekeys: oneTime}); status.OneTimeRemaining != 2 {
		t.Fatalf("re-upload of handed-out key IDs: %+v", status)
	}

	newer := signedPrekey(t, aliceSigner, time.Now().Add(time.Minute))
	if status := uploadPrekeys(t, aliceConn, 45, protocol.PrekeyUpload{SignedPrekey: newer.Raw}); status.SignedPrekeyExpires != newer.Expires.Unix() {
		t.Fatalf("newer signed prekey not stored: %+v", status)
	}
	if status := uploadPrekeys(t, aliceConn, 46, protocol.PrekeyUpload{SignedPrekey: signed.Raw}); status.SignedPrekeyExpires != newer.Expires.Unix() {
		t.Fatalf("older signed prekey replaced the newer one: %+v", status)
	}
	expectAlive(t, aliceConn)
}

func TestPrekeyRequestRateLimit(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		c.Registration = RegistrationOpen
		c.Limits.PrekeyRequestsPerHour = 2
	}})
	alice, bob := newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	bobConn := online(t, ts, bob)
	uploadPrekeys(t, aliceConn, 1, protocol.PrekeyUpload{SignedPrekey: signedPrekey(t, newPrekeySigner(t, alice), time.Now()).Raw})

	requestPrekeys(t, bobConn, 2, alice.id())
	requestPrekeys(t, bobConn, 3, alice.id())
	sendFrame(t, bobConn, protocol.TypePrekeyRequest, 4, protocol.PrekeyRequest{ID: alice.id()})
	expectReject(t, bobConn, 4, protocol.ErrCodeRateLimited)

	other := openSession(t, ts)
	authenticate(t, ts, other, bob)
	requestPrekeys(t, other, 5, alice.id())
}

func TestPrekeyUploadRateLimit(t *testing.T) {
	ts := startServer(t, serverOptions{config: openMode})
	alice := newUser(t)
	conn := online(t, ts, alice)
	for i := range uploadBurst {
		uploadPrekeys(t, conn, uint64(i+1), protocol.PrekeyUpload{})
	}
	sendFrame(t, conn, protocol.TypePrekeyUpload, 99, protocol.PrekeyUpload{})
	expectReject(t, conn, 99, protocol.ErrCodeRateLimited)
}

// TestPrekeyMaximalUpload uploads the largest number of one-time prekeys a
// frame may carry, twice, and checks the per-identity cap.
func TestPrekeyMaximalUpload(t *testing.T) {
	ts := startServer(t, serverOptions{config: openMode})
	alice := newUser(t)
	conn := online(t, ts, alice)
	signer := newPrekeySigner(t, alice)
	for i, want := range []uint32{100, 200, 200} {
		status := uploadPrekeys(t, conn, uint64(i+1), protocol.PrekeyUpload{
			OneTimePrekeys: oneTimePrekeys(t, signer, protocol.MaxOneTimePrekeysPerUpload),
		})
		if status.OneTimeRemaining != want {
			t.Fatalf("upload %d: %d one-time prekeys stored, want %d", i, status.OneTimeRemaining, want)
		}
	}
}
