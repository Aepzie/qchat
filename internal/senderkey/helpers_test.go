package senderkey

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/identity"
)

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
	env, err := s.Encrypt([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func mustDecrypt(t testing.TB, r *Receiver, env []byte, want string) {
	t.Helper()
	got, err := r.Decrypt(env)
	if err != nil {
		t.Fatalf("Decrypt(%q): %v", want, err)
	}
	if string(got) != want {
		t.Fatalf("Decrypt = %q, want %q", got, want)
	}
}

func wantErr(t testing.TB, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want %v", err, target)
	}
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
// (the chain key at h.iteration), signed by signer.
func forge(t testing.TB, h header, chain [keySize]byte, signer *hybridsig.PrivateKey, plaintext []byte) []byte {
	t.Helper()
	hb, err := encodeHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	mk, _ := chainStep(chain)
	ct, err := sealMessage(mk, h.salt[:], plaintext, hb)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(MessageContext, signedPayload(hb, ct))
	if err != nil {
		t.Fatal(err)
	}
	env, err := encodeEnvelope(hb, ct, sig)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// senderHeader returns the header s would use for its next message.
func senderHeader(s *Sender) header {
	return header{group: s.group, sender: s.owner, generation: s.generation, iteration: s.iteration}
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
