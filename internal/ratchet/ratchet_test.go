package ratchet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"testing"

	"github.com/craguS/qchat/internal/crypto/sealbox"
)

func sequence(start byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func checkHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("%s = %x, want %s", name, got, want)
	}
}

// The expected values were computed independently from RFC 5869 HKDF and
// RFC 2104 HMAC with SHA-256, not with this package.
func TestKnownAnswers(t *testing.T) {
	ab, ba, err := deriveRoots(sequence(0x00))
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, "root A->B", ab[:], "c705567f017de7f08e1d33921c323fd3d132cb655ed8788bf6b829e510472c92")
	checkHex(t, "root B->A", ba[:], "cc31db97fd7258a85c38f9e45668bc5563627b814c3eac95463b991481a60f61")

	rk, ck, err := kdfRK(sequence(0x00), sequence(0x20))
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, "KDF_RK root", rk[:], "d8bd318589ce5b772b7c3b9e106d4a92b33556883a909ae5c0a6fd78beaaeeab")
	checkHex(t, "KDF_RK chain", ck[:], "e25c1bf14909c78e8e8254eecbf811621c88fcf5a2b7f4783805c1e1ca06ab9f")

	mk, next := chainStep(sequence(0x40))
	checkHex(t, "message key", mk[:], "01156abd78ef59f755f1e6945e5d1e2d7ddd1f1e5fe0a164b2f5fa8ad500bfba")
	checkHex(t, "next chain key", next[:], "f0bdefbbad3cf097dccb03f2c87159f7608e2480543eef7741c8f2e7f226e78f")

	key, nonce, err := messageAEADKey(sequence(0x60))
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, "AEAD key", key[:], "e685fec03d10c6e702fe3c1cbb6360397ec3987136550bbd57650683b7036ca0")
	checkHex(t, "AEAD nonce", nonce[:], "efada88c63350bf966b65bcf")

	info := ratchetInfo(aliceID, bobID, 0x01020304)
	wantInfo := append(append(append([]byte("qchat/v1/ratchet"), aliceID[:]...), bobID[:]...), 1, 2, 3, 4)
	if !bytes.Equal(info, wantInfo) {
		t.Errorf("ratchetInfo = %x, want %x", info, wantInfo)
	}
	ad := associatedData([]byte{0xa7}, aliceID, bobID)
	wantAD := append(append([]byte{0xa7}, aliceID[:]...), bobID[:]...)
	if !bytes.Equal(ad, wantAD) {
		t.Errorf("associatedData = %x, want %x", ad, wantAD)
	}
}

func TestBasicConversation(t *testing.T) {
	s := newSession(t)
	if s.a.ReceivedAny() || s.b.ReceivedAny() {
		t.Fatal("ReceivedAny true before any message")
	}
	for round := range 5 {
		for i := range 3 {
			deliver(t, s.b, send(t, s.a, fmt.Sprintf("a%d.%d", round, i)))
		}
		if !s.b.ReceivedAny() {
			t.Fatal("responder ReceivedAny false after decrypting")
		}
		for i := range 2 {
			deliver(t, s.a, send(t, s.b, fmt.Sprintf("b%d.%d", round, i)))
		}
		if !s.a.ReceivedAny() {
			t.Fatal("initiator ReceivedAny false after decrypting")
		}
	}
	if s.a.send.epoch != 5 || s.b.send.epoch != 5 {
		t.Errorf("epochs after 5 round trips = %d/%d, want 5/5", s.a.send.epoch, s.b.send.epoch)
	}
	deliver(t, s.b, send(t, s.a, ""))
}

func TestResponderCannotSendFirst(t *testing.T) {
	s := newSession(t)
	if _, _, err := s.b.Encrypt([]byte("hi")); !errors.Is(err, ErrNoPeerKey) {
		t.Fatalf("responder Encrypt before receiving = %v, want ErrNoPeerKey", err)
	}
}

func TestInitialEpoch(t *testing.T) {
	s := newSession(t)
	spkTarget := targetOf(s.spk.Public())
	m0 := send(t, s.a, "m0")
	m1 := send(t, s.a, "m1")
	h0, h1 := parse(t, m0.header), parse(t, m1.header)
	if h0.Epoch != 1 || h0.N != 0 || h0.PN != 0 || h1.Epoch != 1 || h1.N != 1 {
		t.Fatalf("first headers: epoch %d/%d n %d/%d pn %d", h0.Epoch, h1.Epoch, h0.N, h1.N, h0.PN)
	}
	if !bytes.Equal(h0.Target, spkTarget[:]) {
		t.Fatal("initiator's first epoch does not target the signed prekey")
	}
	if !bytes.Equal(h0.KEMCT, h1.KEMCT) || !bytes.Equal(h0.Target, h1.Target) {
		t.Fatal("messages of one epoch carry different KEMCT/Target")
	}
	if !bytes.Equal(h0.RatchetPub, s.a.ownKeys[0].Public().Bytes()) {
		t.Fatal("header does not announce the sender's current key")
	}

	other, err := sealbox.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := New(Params{Self: bobID, Peer: aliceID, SK: s.sk, Role: Responder, OwnInitialKey: other})
	if err != nil {
		t.Fatal(err)
	}
	deliverErr(t, wrong, m0, ErrUnknownTarget)

	deliver(t, s.b, m1)
	deliver(t, s.b, m0)
	if len(s.b.ownKeys) != 1 || s.b.ownKeys[0].Public().Equal(s.spk.Public()) {
		t.Fatal("responder still holds the signed prekey after it was used")
	}
	if s.spk.Bytes() == nil {
		t.Fatal("responder destroyed the caller's signed prekey")
	}
}

func TestEpochAdvanceRules(t *testing.T) {
	s := newSession(t)
	a0 := send(t, s.a, "a0")
	a1 := send(t, s.a, "a1")
	kemA1 := parse(t, a0.header).KEMCT
	deliver(t, s.b, a0)
	ka1 := ownTarget(s.a)

	b0 := send(t, s.b, "b0")
	hb0 := parse(t, b0.header)
	if hb0.Epoch != 1 || !bytes.Equal(hb0.Target, ka1[:]) {
		t.Fatal("responder's first epoch does not target the initiator's announced key")
	}
	if bytes.Equal(hb0.RatchetPub, s.spk.Public().Bytes()) {
		t.Fatal("responder still announces its signed prekey")
	}
	deliver(t, s.b, a1)
	b1 := send(t, s.b, "b1")
	if h := parse(t, b1.header); h.Epoch != 1 || h.N != 1 {
		t.Fatalf("responder started an epoch without a newer peer key: epoch %d n %d", h.Epoch, h.N)
	}

	a2 := send(t, s.a, "a2")
	if h := parse(t, a2.header); h.Epoch != 1 || !bytes.Equal(h.KEMCT, kemA1) {
		t.Fatal("initiator started an epoch without having received a newer key")
	}

	deliver(t, s.a, b0)
	if len(s.a.ownKeys) != 1 || ownTarget(s.a) == ka1 {
		t.Fatal("initiator did not replace its consumed ratchet key")
	}
	a3 := send(t, s.a, "a3")
	h3 := parse(t, a3.header)
	if h3.Epoch != 2 || h3.N != 0 || h3.PN != 3 || !bytes.Equal(h3.Target, sha256Of(hb0.RatchetPub)) {
		t.Fatalf("new epoch header: epoch %d n %d pn %d", h3.Epoch, h3.N, h3.PN)
	}
	a4 := send(t, s.a, "a4")
	if h := parse(t, a4.header); h.Epoch != 2 || !bytes.Equal(h.KEMCT, h3.KEMCT) {
		t.Fatal("epoch changed without a newer peer key")
	}

	deliver(t, s.b, a3)
	deliver(t, s.b, a2)
	deliver(t, s.b, a4)
	b2 := send(t, s.b, "b2")
	if h := parse(t, b2.header); h.Epoch != 2 || h.PN != 2 || !bytes.Equal(h.Target, sha256Of(h3.RatchetPub)) {
		t.Fatalf("responder's second epoch: epoch %d pn %d", h.Epoch, h.PN)
	}
	deliver(t, s.a, b1)
	deliver(t, s.a, b2)
}

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func TestConsumedOwnKeyIsDeleted(t *testing.T) {
	s := newSession(t)
	m0 := send(t, s.a, "m0")
	deliver(t, s.b, m0)
	h := parse(t, m0.header)
	h.Epoch, h.PN = 2, 1
	deliverErr(t, s.b, message{header: reencode(t, h), ciphertext: m0.ciphertext, text: "forged"}, ErrUnknownTarget)

	b0 := send(t, s.b, "b0")
	consumed := ownTarget(s.a)
	deliver(t, s.a, b0)
	for _, own := range s.a.ownKeys {
		if targetOf(own.Public()) == consumed {
			t.Fatal("initiator kept a consumed ratchet key")
		}
	}
	hb := parse(t, b0.header)
	hb.Epoch, hb.PN = 2, 1
	deliverErr(t, s.a, message{header: reencode(t, hb), ciphertext: b0.ciphertext, text: "forged"}, ErrUnknownTarget)
}

func TestOutOfOrderWithinEpoch(t *testing.T) {
	s := newSession(t)
	var msgs []message
	for i := range 5 {
		msgs = append(msgs, send(t, s.a, fmt.Sprintf("m%d", i)))
	}
	for _, i := range []int{4, 0, 2, 1, 3} {
		deliver(t, s.b, msgs[i])
	}
	if len(s.b.skipped) != 0 {
		t.Fatalf("%d skipped keys left after all messages arrived", len(s.b.skipped))
	}
}

func TestOutOfOrderAcrossEpochs(t *testing.T) {
	s := newSession(t)
	e1 := []message{send(t, s.a, "e1.0"), send(t, s.a, "e1.1"), send(t, s.a, "e1.2")}
	deliver(t, s.b, e1[0])
	deliver(t, s.a, send(t, s.b, "b0"))
	e2 := []message{send(t, s.a, "e2.0"), send(t, s.a, "e2.1")}
	if h := parse(t, e2[1].header); h.Epoch != 2 || h.PN != 3 {
		t.Fatalf("epoch 2 header: epoch %d pn %d", h.Epoch, h.PN)
	}
	deliver(t, s.b, e2[1])
	if len(s.b.skipped) != 3 {
		t.Fatalf("skipped keys = %d, want 3", len(s.b.skipped))
	}
	s.b = restore(t, s.b)
	deliver(t, s.b, e1[2])
	deliver(t, s.b, e2[0])
	deliver(t, s.b, e1[1])
	if len(s.b.skipped) != 0 {
		t.Fatalf("%d skipped keys left", len(s.b.skipped))
	}
	deliver(t, s.a, send(t, s.b, "b1"))
}

func TestMaxSkipWithinEpoch(t *testing.T) {
	s := newSession(t)
	var msgs []message
	for i := range MaxSkip + 2 {
		msgs = append(msgs, send(t, s.a, fmt.Sprintf("m%d", i)))
	}
	deliverErr(t, s.b, msgs[MaxSkip+1], ErrTooManySkipped)
	deliver(t, s.b, msgs[MaxSkip])
	if len(s.b.skipped) != MaxSkip {
		t.Fatalf("skipped = %d, want %d", len(s.b.skipped), MaxSkip)
	}
	for _, m := range msgs[:MaxSkip] {
		deliver(t, s.b, m)
	}
	deliver(t, s.b, msgs[MaxSkip+1])
}

func TestMaxSkipAcrossEpochs(t *testing.T) {
	s := newSession(t)
	deliver(t, s.b, send(t, s.a, "a0"))
	b0 := send(t, s.b, "b0")
	var late []message
	for i := range MaxSkip {
		late = append(late, send(t, s.a, fmt.Sprintf("late%d", i)))
	}
	deliver(t, s.a, b0)
	n0 := send(t, s.a, "n0")
	n1 := send(t, s.a, "n1")
	deliverErr(t, s.b, n1, ErrTooManySkipped)
	deliver(t, s.b, n0)
	deliver(t, s.b, n1)
	deliver(t, s.b, late[MaxSkip-1])
	deliver(t, s.b, late[0])
}

func TestSkippedEviction(t *testing.T) {
	s := newSession(t)
	var msgs []message
	for i := range MaxStoredSkipped + 3 {
		msgs = append(msgs, send(t, s.a, fmt.Sprintf("m%d", i)))
	}
	deliver(t, s.b, msgs[MaxStoredSkipped])
	deliver(t, s.b, msgs[MaxStoredSkipped+2])
	if len(s.b.skipped) != MaxStoredSkipped {
		t.Fatalf("stored skipped = %d, want %d", len(s.b.skipped), MaxStoredSkipped)
	}
	deliverErr(t, s.b, msgs[0], ErrReplay)
	deliver(t, s.b, msgs[1])
	deliver(t, s.b, msgs[MaxStoredSkipped+1])
}

func TestConcurrentSending(t *testing.T) {
	s := newSession(t)
	deliver(t, s.b, send(t, s.a, "hello"))
	for round := range 8 {
		var fromA, fromB []message
		for i := range 3 {
			fromA = append(fromA, send(t, s.a, fmt.Sprintf("a%d.%d", round, i)))
			fromB = append(fromB, send(t, s.b, fmt.Sprintf("b%d.%d", round, i)))
		}
		for i := range 3 {
			deliver(t, s.a, fromB[2-i])
			deliver(t, s.b, fromA[i])
		}
	}
	if s.a.send.epoch < 4 || s.b.send.epoch < 4 {
		t.Errorf("epochs did not advance under concurrent sending: %d/%d", s.a.send.epoch, s.b.send.epoch)
	}
}

func TestReplay(t *testing.T) {
	s := newSession(t)
	m0 := send(t, s.a, "m0")
	m1 := send(t, s.a, "m1")
	m2 := send(t, s.a, "m2")
	deliver(t, s.b, m0)
	deliverErr(t, s.b, m0, ErrReplay)
	deliver(t, s.b, m2)
	deliverErr(t, s.b, m2, ErrReplay)
	deliver(t, s.b, m1)
	deliverErr(t, s.b, m1, ErrReplay)

	deliver(t, s.a, send(t, s.b, "b0"))
	n0 := send(t, s.a, "n0")
	deliver(t, s.b, n0)
	deliverErr(t, s.b, n0, ErrReplay)
	deliverErr(t, s.b, m0, ErrReplay)
}

func TestTamperingLeavesStateUsable(t *testing.T) {
	s := newSession(t)
	first := send(t, s.a, "first")
	second := send(t, s.a, "second")
	for _, m := range []message{first, second} {
		for i := 0; i < len(m.header); i += 41 {
			header := bytes.Clone(m.header)
			header[i] ^= 0x10
			before := snapshot(t, s.b)
			if _, err := s.b.Decrypt(header, m.ciphertext); err == nil {
				t.Fatalf("tampered header byte %d accepted", i)
			}
			if !bytes.Equal(before, snapshot(t, s.b)) {
				t.Fatalf("tampered header byte %d changed the state", i)
			}
		}
		for i := range m.ciphertext {
			ciphertext := bytes.Clone(m.ciphertext)
			ciphertext[i] ^= 0x01
			deliverErr(t, s.b, message{header: m.header, ciphertext: ciphertext, text: "tampered"}, ErrDecrypt)
		}
		deliverErr(t, s.b, message{header: m.header, ciphertext: m.ciphertext[:len(m.ciphertext)-1], text: "truncated"}, ErrDecrypt)
	}
	deliverErr(t, s.b, message{header: first.header, ciphertext: second.ciphertext, text: "swapped"}, ErrDecrypt)
	deliver(t, s.b, first)
	deliverErr(t, s.b, message{header: second.header, ciphertext: first.ciphertext, text: "swapped"}, ErrDecrypt)
	deliver(t, s.b, second)
}

func TestIdentitiesAreBound(t *testing.T) {
	s := newSession(t)
	m0 := send(t, s.a, "m0")
	mallory := [32]byte{0: 0xee}
	for _, ids := range [][2][32]byte{{bobID, mallory}, {mallory, aliceID}, {aliceID, bobID}} {
		wrong, err := New(Params{Self: ids[0], Peer: ids[1], SK: s.sk, Role: Responder, OwnInitialKey: s.spk})
		if err != nil {
			t.Fatal(err)
		}
		deliverErr(t, wrong, m0, ErrDecrypt)
	}
	deliver(t, s.b, m0)
}

func TestHostileHeaders(t *testing.T) {
	s := newSession(t)
	m0 := send(t, s.a, "m0")
	m1 := send(t, s.a, "m1")
	deliver(t, s.b, m0)
	h := parse(t, m1.header)

	mutate := func(change func(*Header)) []byte {
		bad := h
		bad.RatchetPub = bytes.Clone(h.RatchetPub)
		bad.Target = bytes.Clone(h.Target)
		bad.KEMCT = bytes.Clone(h.KEMCT)
		change(&bad)
		return reencode(t, bad)
	}
	unknownField := append([]byte{0xa8}, m1.header[1:]...)
	unknownField = append(unknownField, 0x08, 0x00)

	cases := []struct {
		name   string
		header []byte
		want   error
	}{
		{"empty", nil, ErrMalformedHeader},
		{"garbage", []byte{0xff, 0x00}, ErrMalformedHeader},
		{"oversized", make([]byte, maxHeaderSize+1), ErrMalformedHeader},
		{"trailing byte", append(bytes.Clone(m1.header), 0), ErrMalformedHeader},
		{"unknown field", unknownField, ErrMalformedHeader},
		{"version 2", mutate(func(b *Header) { b.Version = 2 }), ErrMalformedHeader},
		{"epoch 0", mutate(func(b *Header) { b.Epoch = 0 }), ErrMalformedHeader},
		{"short pub", mutate(func(b *Header) { b.RatchetPub = b.RatchetPub[:100] }), ErrMalformedHeader},
		{"long pub", mutate(func(b *Header) { b.RatchetPub = append(b.RatchetPub, 0) }), ErrMalformedHeader},
		{"short target", mutate(func(b *Header) { b.Target = b.Target[:31] }), ErrMalformedHeader},
		{"missing kemct", mutate(func(b *Header) { b.KEMCT = nil }), ErrMalformedHeader},
		{"short kemct", mutate(func(b *Header) { b.KEMCT = b.KEMCT[:1119] }), ErrMalformedHeader},
		{"max n", mutate(func(b *Header) { b.N = math.MaxUint32 }), ErrMalformedHeader},
		{"huge n", mutate(func(b *Header) { b.N = math.MaxUint32 - 1 }), ErrTooManySkipped},
		{"n just above limit", mutate(func(b *Header) { b.N = MaxSkip + 2 }), ErrTooManySkipped},
		{"huge pn new epoch", mutate(func(b *Header) {
			b.Epoch = 2
			b.PN = math.MaxUint32
			b.Target[0] ^= 1
		}), ErrTooManySkipped},
		{"pn below received", mutate(func(b *Header) { b.Epoch = 2; b.PN = 0 }), ErrMalformedHeader},
		{"unknown target", mutate(func(b *Header) { b.Epoch = 2; b.PN = 2; b.Target[0] ^= 1 }), ErrUnknownTarget},
		{"skipped epoch", mutate(func(b *Header) { b.Epoch = 3 }), ErrUnknownTarget},
		{"far future epoch", mutate(func(b *Header) { b.Epoch = math.MaxUint32 }), ErrUnknownTarget},
		{"other target same epoch", mutate(func(b *Header) { b.Target[5] ^= 1 }), ErrDecrypt},
		{"other kemct same epoch", mutate(func(b *Header) { b.KEMCT[5] ^= 1 }), ErrDecrypt},
		{"replayed position", mutate(func(b *Header) { b.N = 0 }), ErrReplay},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deliverErr(t, s.b, message{header: tc.header, ciphertext: m1.ciphertext, text: tc.name}, tc.want)
		})
	}
	deliverErr(t, s.b, message{header: m1.header, ciphertext: m1.ciphertext[:15], text: "short ciphertext"}, ErrDecrypt)
	deliver(t, s.b, m1)
}

func TestMarshalRoundTrip(t *testing.T) {
	s := newSession(t)
	s.b = restore(t, s.b)
	s.a = restore(t, s.a)
	m0 := send(t, s.a, "m0")
	m1 := send(t, s.a, "m1")
	m2 := send(t, s.a, "m2")
	s.a = restore(t, s.a)
	deliver(t, s.b, m2)
	s.b = restore(t, s.b)
	b0 := send(t, s.b, "b0")
	s.b = restore(t, s.b)
	deliver(t, s.a, b0)
	s.a = restore(t, s.a)
	deliver(t, s.b, send(t, s.a, "n0"))
	s.b = restore(t, s.b)
	deliver(t, s.b, m0)
	deliver(t, s.b, m1)
	deliverErr(t, s.b, m1, ErrReplay)
	deliver(t, s.a, send(t, s.b, "b1"))

	encoded := snapshot(t, s.b)
	if _, err := Unmarshal(append(bytes.Clone(encoded), 0)); !errors.Is(err, ErrInvalidState) {
		t.Errorf("Unmarshal with trailing byte = %v", err)
	}
	for _, n := range []int{0, 1, len(encoded) / 2, len(encoded) - 1} {
		if _, err := Unmarshal(encoded[:n]); !errors.Is(err, ErrInvalidState) {
			t.Errorf("Unmarshal of %d-byte prefix = %v", n, err)
		}
	}
	invalid := map[string]func(*stateWire){
		"version":     func(w *stateWire) { w.Version = 2 },
		"role":        func(w *stateWire) { w.Role = 0 },
		"short root":  func(w *stateWire) { w.RootSend = w.RootSend[:31] },
		"no own keys": func(w *stateWire) { w.OwnKeys = nil },
		"too many keys": func(w *stateWire) {
			w.OwnKeys = [][]byte{w.OwnKeys[0], w.OwnKeys[0], w.OwnKeys[0], w.OwnKeys[0], w.OwnKeys[0]}
		},
		"recv n zero":     func(w *stateWire) { w.RecvN = 0 },
		"bad peer pub":    func(w *stateWire) { w.PeerPub = w.PeerPub[:10] },
		"future skipped":  func(w *stateWire) { w.Skipped = []skippedWire{{Epoch: w.RecvEpoch + 1, N: 0, Key: make([]byte, 32)}} },
		"current skipped": func(w *stateWire) { w.Skipped = []skippedWire{{Epoch: w.RecvEpoch, N: w.RecvN, Key: make([]byte, 32)}} },
		"dup skipped": func(w *stateWire) {
			w.Skipped = []skippedWire{{Epoch: 1, N: 0, Key: make([]byte, 32)}, {Epoch: 1, N: 0, Key: make([]byte, 32)}}
		},
		"send without chain": func(w *stateWire) { w.SendChain = nil },
	}
	for name, change := range invalid {
		var copyWire stateWire
		if err := stateDecMode.Unmarshal(encoded, &copyWire); err != nil {
			t.Fatal(err)
		}
		change(&copyWire)
		bad, err := encMode.Marshal(copyWire)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Unmarshal(bad); !errors.Is(err, ErrInvalidState) {
			t.Errorf("%s: Unmarshal = %v, want ErrInvalidState", name, err)
		}
	}
}

func TestNewValidation(t *testing.T) {
	key, err := sealbox.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sk := [32]byte{1}
	cases := map[string]Params{
		"no role":                 {SK: sk, PeerInitialPub: key.Public()},
		"zero sk":                 {Role: Initiator, PeerInitialPub: key.Public()},
		"initiator without pub":   {SK: sk, Role: Initiator},
		"initiator with own key":  {SK: sk, Role: Initiator, PeerInitialPub: key.Public(), OwnInitialKey: key},
		"responder without key":   {SK: sk, Role: Responder},
		"responder with peer pub": {SK: sk, Role: Responder, OwnInitialKey: key, PeerInitialPub: key.Public()},
	}
	for name, p := range cases {
		if _, err := New(p); !errors.Is(err, ErrInvalidParams) {
			t.Errorf("%s: New = %v, want ErrInvalidParams", name, err)
		}
	}
	destroyed, err := sealbox.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	destroyed.Destroy()
	if _, err := New(Params{SK: sk, Role: Responder, OwnInitialKey: destroyed}); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("destroyed key: New = %v, want ErrInvalidParams", err)
	}
}

func TestDestroy(t *testing.T) {
	s := newSession(t)
	m0 := send(t, s.a, "m0")
	s.a.Destroy()
	s.b.Destroy()
	if _, _, err := s.a.Encrypt(nil); !errors.Is(err, ErrDestroyed) {
		t.Errorf("Encrypt after Destroy = %v", err)
	}
	if _, err := s.b.Decrypt(m0.header, m0.ciphertext); !errors.Is(err, ErrDestroyed) {
		t.Errorf("Decrypt after Destroy = %v", err)
	}
	if _, err := s.b.Marshal(); !errors.Is(err, ErrDestroyed) {
		t.Errorf("Marshal after Destroy = %v", err)
	}
	if s.a.rootSend != [32]byte{} || s.a.rootRecv != [32]byte{} || s.b.rootSend != [32]byte{} || s.b.ownKeys != nil {
		t.Error("Destroy left key material in place")
	}
}

type inFlight struct {
	message
	id int
}

// TestRandomizedConversation drives a long conversation with a fixed seed:
// both sides send at random, and messages are reordered, dropped, duplicated
// and the states periodically persisted and restored. Every message that is
// delivered for the first time must decrypt; every repeat must fail with
// ErrReplay.
func TestRandomizedConversation(t *testing.T) {
	steps := 10000
	if testing.Short() {
		steps = 1000
	}
	rng := rand.New(rand.NewPCG(20261107, 3))
	s := newSession(t)
	states := [2]*State{s.a, s.b}
	var queues [2][]inFlight
	delivered := map[int]bool{}
	nextID := 0
	sent, received, replays := 0, 0, 0

	sendFrom := func(side int) {
		if side == 1 && !states[1].ReceivedAny() {
			if _, _, err := states[1].Encrypt([]byte("x")); !errors.Is(err, ErrNoPeerKey) {
				t.Fatalf("responder Encrypt before receiving = %v", err)
			}
			return
		}
		m := send(t, states[side], fmt.Sprintf("msg %d from %d", nextID, side))
		queues[1-side] = append(queues[1-side], inFlight{message: m, id: nextID})
		nextID++
		sent++
	}
	receive := func(to, index int) {
		f := queues[to][index]
		queues[to] = append(queues[to][:index], queues[to][index+1:]...)
		got, err := states[to].Decrypt(f.header, f.ciphertext)
		if delivered[f.id] {
			if !errors.Is(err, ErrReplay) {
				t.Fatalf("duplicate of message %d: err = %v, want ErrReplay", f.id, err)
			}
			replays++
			return
		}
		if err != nil {
			t.Fatalf("message %d (%q) to side %d: %v", f.id, f.text, to, err)
		}
		if string(got) != f.text {
			t.Fatalf("message %d decrypted to %q, want %q", f.id, got, f.text)
		}
		delivered[f.id] = true
		received++
	}

	for range steps {
		roll := rng.IntN(100)
		to := rng.IntN(2)
		switch {
		case roll < 22:
			sendFrom(0)
		case roll < 44:
			sendFrom(1)
		case roll < 88:
			if len(queues[to]) > 0 {
				index := len(queues[to]) - 1
				if rng.IntN(3) == 0 {
					index = rng.IntN(len(queues[to]))
				}
				receive(to, index)
			}
		case roll < 93:
			if len(queues[to]) > 0 {
				index := rng.IntN(len(queues[to]))
				queues[to] = append(queues[to][:index], queues[to][index+1:]...)
			}
		case roll < 97:
			if len(queues[to]) > 0 {
				queues[to] = append(queues[to], queues[to][rng.IntN(len(queues[to]))])
			}
		default:
			states[to] = restore(t, states[to])
		}
	}
	for to := range 2 {
		for len(queues[to]) > 0 {
			receive(to, rng.IntN(len(queues[to])))
		}
	}
	deliver(t, states[1], send(t, states[0], "final a"))
	deliver(t, states[0], send(t, states[1], "final b"))
	if sent == 0 || received == 0 || replays == 0 || states[0].send.epoch < 10 || states[1].send.epoch < 10 {
		t.Fatalf("weak run: sent %d received %d replays %d epochs %d/%d",
			sent, received, replays, states[0].send.epoch, states[1].send.epoch)
	}
	t.Logf("sent %d received %d replays %d epochs %d/%d", sent, received, replays, states[0].send.epoch, states[1].send.epoch)
	for side, st := range states {
		if len(st.skipped) > MaxStoredSkipped || len(st.ownKeys) > MaxUnconsumedOwnKeys {
			t.Fatalf("side %d exceeds bounds: %d skipped, %d own keys", side, len(st.skipped), len(st.ownKeys))
		}
	}
}
