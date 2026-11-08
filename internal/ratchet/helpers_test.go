package ratchet

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/Aepzie/qchat/internal/crypto/sealbox"
)

var (
	aliceID = [32]byte{0: 0xa1, 31: 0x01}
	bobID   = [32]byte{0: 0xb0, 31: 0x02}
)

type session struct {
	a, b *State
	spk  *sealbox.PrivateKey
	sk   [32]byte
}

type message struct {
	header, ciphertext []byte
	text               string
}

func newSession(t testing.TB) *session {
	t.Helper()
	spk, err := sealbox.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var sk [32]byte
	rand.Read(sk[:])
	a, err := New(Params{Self: aliceID, Peer: bobID, SK: sk, Role: Initiator, PeerInitialPub: spk.Public()})
	if err != nil {
		t.Fatalf("New(initiator): %v", err)
	}
	b, err := New(Params{Self: bobID, Peer: aliceID, SK: sk, Role: Responder, OwnInitialKey: spk})
	if err != nil {
		t.Fatalf("New(responder): %v", err)
	}
	return &session{a: a, b: b, spk: spk, sk: sk}
}

func send(t testing.TB, s *State, text string) message {
	t.Helper()
	header, ciphertext, err := s.Encrypt([]byte(text))
	if err != nil {
		t.Fatalf("Encrypt(%q): %v", text, err)
	}
	return message{header: header, ciphertext: ciphertext, text: text}
}

func deliver(t testing.TB, s *State, m message) {
	t.Helper()
	got, err := s.Decrypt(m.header, m.ciphertext)
	if err != nil {
		t.Fatalf("Decrypt(%q): %v", m.text, err)
	}
	if string(got) != m.text {
		t.Fatalf("Decrypt = %q, want %q", got, m.text)
	}
}

func deliverErr(t testing.TB, s *State, m message, want error) {
	t.Helper()
	before := snapshot(t, s)
	_, err := s.Decrypt(m.header, m.ciphertext)
	if !errors.Is(err, want) {
		t.Fatalf("Decrypt(%q) error = %v, want %v", m.text, err, want)
	}
	if after := snapshot(t, s); !bytes.Equal(before, after) {
		t.Fatalf("failed Decrypt(%q) changed the state", m.text)
	}
}

func snapshot(t testing.TB, s *State) []byte {
	t.Helper()
	encoded, err := s.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return encoded
}

func parse(t testing.TB, header []byte) Header {
	t.Helper()
	h, err := ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	return h
}

func reencode(t testing.TB, h Header) []byte {
	t.Helper()
	encoded, err := encodeHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func restore(t testing.TB, s *State) *State {
	t.Helper()
	encoded := snapshot(t, s)
	restored, err := Unmarshal(encoded)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if again := snapshot(t, restored); !bytes.Equal(again, encoded) {
		t.Fatal("Marshal(Unmarshal(b)) != b")
	}
	s.Destroy()
	return restored
}

func ownTarget(s *State) [TargetSize]byte {
	return targetOf(s.ownKeys[len(s.ownKeys)-1].Public())
}
