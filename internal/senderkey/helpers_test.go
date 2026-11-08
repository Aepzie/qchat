package senderkey

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/padding"
)

// testEpoch and testBinding are the group state helpers encrypt claims.
const testEpoch = 7

var testBinding = [StateBindingSize]byte{0xb1, 0x2d, 0x3e}

func randomGroup(t testing.TB) GroupID {
	t.Helper()
	var g GroupID
	if _, err := rand.Read(g[:]); err != nil {
		t.Fatal(err)
	}
	return g
}

func randomID(t testing.TB) identity.ID {
	t.Helper()
	var id identity.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func newSender(t testing.TB, group GroupID, owner identity.ID, generation uint32) *Sender {
	t.Helper()
	s, err := NewSender(group, owner, generation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Destroy)
	return s
}

func newReceiver(t testing.TB, s *Sender, groupEpoch uint64) *Receiver {
	t.Helper()
	dist, err := s.Distribution(groupEpoch)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReceiver(dist, s.Owner())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Destroy)
	return r
}

func newPair(t testing.TB) (*Sender, *Receiver) {
	t.Helper()
	s := newSender(t, randomGroup(t), randomID(t), 1)
	return s, newReceiver(t, s, 7)
}

func encrypt(t testing.TB, s *Sender, text string) []byte {
	t.Helper()
	env, err := s.Encrypt([]byte(text), testEpoch, testBinding)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func mustDecrypt(t testing.TB, r *Receiver, env []byte, want string) Header {
	t.Helper()
	got, h, err := r.Decrypt(env)
	if err != nil {
		t.Fatalf("Decrypt(%q): %v", want, err)
	}
	if string(got) != want {
		t.Fatalf("Decrypt = %q, want %q", got, want)
	}
	return h
}

func decryptErr(r *Receiver, env []byte) error {
	_, _, err := r.Decrypt(env)
	return err
}

func wantErr(t testing.TB, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want %v", err, target)
	}
}

// setClock makes skipped keys derived during the test carry the time now
// returns.
func setClock(t testing.TB, now func() time.Time) {
	t.Helper()
	saved := clock
	clock = now
	t.Cleanup(func() { clock = saved })
}

// advanceSender moves s forward by n chain steps without producing envelopes,
// as if n messages had been sent and lost.
func advanceSender(s *Sender, n int) {
	for range n {
		_, next := chainStep(s.chain)
		s.chain = next
		s.iteration++
	}
}

// forge builds an envelope for header h whose message key comes from chain
// (the chain key at h.iteration), with the header sealed under headerKey and
// the envelope signed by signer. A zero h.commitment is replaced by the
// commitment to the message key; a non-zero one is used as given. The
// plaintext is padded as Encrypt pads it.
func forge(t testing.TB, h header, chain [keySize]byte, headerKey [HeaderKeySize]byte, signer *hybridsig.PrivateKey, plaintext []byte) []byte {
	t.Helper()
	padded, err := padding.Pad(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return forgeSealed(t, h, chain, headerKey, signer, padded)
}

// forgeSealed is forge without padding: plaintext is encrypted exactly as
// given.
func forgeSealed(t testing.TB, h header, chain [keySize]byte, headerKey [HeaderKeySize]byte, signer *hybridsig.PrivateKey, plaintext []byte) []byte {
	t.Helper()
	mk, _ := chainStep(chain)
	if h.commitment == ([commitmentSize]byte{}) {
		h.commitment = commitMessageKey(mk)
	}
	hb := encodeHeader(h)
	ct, err := sealMessage(mk, h.salt[:], plaintext, hb)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, HeaderNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	encHeader, err := sealHeader(&headerKey, nonce, hb)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(MessageContext, signedPayload(nonce, encHeader, ct, hb))
	if err != nil {
		t.Fatal(err)
	}
	env, err := encodeEnvelope(envelope{nonce: nonce, encHeader: encHeader, ciphertext: ct, sig: sig})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// senderHeader returns the header s would use for its next message, without
// salt or commitment.
func senderHeader(s *Sender) header {
	return header{group: s.group, sender: s.owner, generation: s.generation, iteration: s.iteration, groupEpoch: testEpoch, binding: testBinding}
}

// candidate returns the header candidate of s's generation.
func candidate(s *Sender) HeaderCandidate {
	return HeaderCandidate{Group: s.group, Sender: s.owner, Generation: s.generation, Key: s.headerKey}
}

// openFor decrypts the header of env under s's header key.
func openFor(t testing.TB, s *Sender, env []byte) header {
	t.Helper()
	parsed, err := parseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := parsed.openWith(&s.headerKey)
	if !ok {
		t.Fatal("header does not open under the sender's header key")
	}
	return h
}

func decodeEnvelopeWire(t testing.TB, env []byte) envelopeWire {
	t.Helper()
	var w envelopeWire
	if err := strictDecMode.Unmarshal(env, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

func encodeWire(t testing.TB, v any) []byte {
	t.Helper()
	b, err := encMode.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cloneBytes(b []byte) []byte {
	return append([]byte(nil), b...)
}
