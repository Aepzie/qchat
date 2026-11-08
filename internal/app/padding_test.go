package app

import (
	"context"
	"strings"
	"testing"

	"github.com/Aepzie/qchat/internal/client"
	"github.com/Aepzie/qchat/internal/e2e"
	"github.com/Aepzie/qchat/internal/ratchet"
	"github.com/Aepzie/qchat/internal/senderkey"
)

// paddingProbeLengths are body lengths that fall into the smallest padding
// bucket, so their payloads must be indistinguishable on the wire.
var paddingProbeLengths = []int{1, 100, 400}

// payloadSizes returns the sizes of the payloads queued for u whose kind
// matches group.
func payloadSizes(r *fakeRelay, u *fakeUser, group bool) []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	var sizes []int
	for _, d := range r.queues[u.id] {
		if senderkey.IsGroupEnvelope(d.Payload) == group {
			sizes = append(sizes, len(d.Payload))
		}
	}
	return sizes
}

func wantEqualSizes(t *testing.T, what string, sizes []int) {
	t.Helper()
	if len(sizes) != len(paddingProbeLengths) {
		t.Fatalf("%s: %d payloads, want %d", what, len(sizes), len(paddingProbeLengths))
	}
	for _, size := range sizes[1:] {
		if size != sizes[0] {
			t.Fatalf("%s: payload sizes %v differ for bodies of %v bytes", what, sizes, paddingProbeLengths)
		}
	}
}

func probeTexts() []string {
	texts := make([]string, len(paddingProbeLengths))
	for i, n := range paddingProbeLengths {
		texts[i] = strings.Repeat("p", n)
	}
	return texts
}

func TestPairwisePayloadSizesHideBodyLength(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)

	texts := probeTexts()
	for _, text := range texts {
		alice.send(bob, text)
	}
	wantEqualSizes(t, "with Init", payloadSizes(r, bob, false))
	wantTexts(t, "bob", bob.receive(), texts...)

	bob.send(alice, "reply")
	wantTexts(t, "alice", alice.receive(), "reply")
	for _, text := range texts {
		alice.send(bob, text)
	}
	wantEqualSizes(t, "without Init", payloadSizes(r, bob, false))
	wantTexts(t, "bob", bob.receive(), texts...)
	if bob.dropped() != 0 {
		t.Fatalf("bob dropped %d deliveries", bob.dropped())
	}
}

func TestGroupPayloadSizesHideBodyLength(t *testing.T) {
	r, alice, bob, carol, gid := newGroupOfThree(t)
	texts := probeTexts()
	for _, text := range texts {
		alice.sendGroup(gid, text)
	}
	wantEqualSizes(t, "group", payloadSizes(r, bob, true))
	got := settle(t, alice, bob, carol)
	wantTexts(t, "bob", got[bob], texts...)
	wantTexts(t, "carol", got[carol], texts...)
}

// sealRaw encrypts raw with from's current ratchet state for to, exactly
// as Send would but without padding raw first and without storing the
// advanced state, and returns the relay payload.
func sealRaw(t *testing.T, from, to *fakeUser, raw []byte) []byte {
	t.Helper()
	cur, found := from.session(to)
	if !found {
		t.Fatal("no session")
	}
	st, err := ratchet.Unmarshal(cur.State)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Destroy()
	header, ciphertext, err := st.Encrypt(raw)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := e2e.MarshalEnvelope(e2e.Envelope{Header: header, Ciphertext: ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestMalformedPaddingDropped(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)
	alice.send(bob, "hello")
	wantTexts(t, "bob", bob.receive(), "hello")
	bob.send(alice, "hi")
	wantTexts(t, "alice", alice.receive(), "hi")

	pt, err := e2e.NewPlaintext(e2e.KindText, []byte("forged"), r.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	unpadded, err := e2e.MarshalPlaintext(pt)
	if err != nil {
		t.Fatal(err)
	}
	trailing, err := e2e.MarshalPaddedPlaintext(pt)
	if err != nil {
		t.Fatal(err)
	}
	trailing[len(trailing)-1] = 1
	noMarker := make([]byte, len(trailing))
	copy(noMarker, unpadded)

	for i, raw := range [][]byte{unpadded, trailing, noMarker} {
		payload := sealRaw(t, alice, bob, raw)
		bob.app.handleDelivery(context.Background(), client.Delivery{From: [32]byte(alice.id), Payload: payload, QueueID: uint64(1000 + i)})
		if texts := bob.receive(); len(texts) != 0 {
			t.Fatalf("malformed padding %d shown: %q", i, texts)
		}
		if bob.dropped() != i+1 {
			t.Fatalf("malformed padding %d: bob dropped %d deliveries", i, bob.dropped())
		}
	}
	control, err := e2e.MarshalPaddedPlaintext(pt)
	if err != nil {
		t.Fatal(err)
	}
	payload := sealRaw(t, alice, bob, control)
	bob.app.handleDelivery(context.Background(), client.Delivery{From: [32]byte(alice.id), Payload: payload, QueueID: 2000})
	wantTexts(t, "bob", bob.receive(), "forged")
}
