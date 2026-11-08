package senderkey

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/Aepzie/qchat/internal/crypto/hybridsig"
	"github.com/Aepzie/qchat/internal/identity"
)

func TestRoundTrip(t *testing.T) {
	s, r := newPair(t)
	for i := range 5 {
		text := fmt.Sprintf("message %d", i)
		env := encrypt(t, s, text)
		if !IsGroupEnvelope(env) {
			t.Fatal("IsGroupEnvelope = false for a group envelope")
		}
		want := Header{Group: s.Group(), Sender: s.Owner(), Generation: 1, Iteration: uint32(i), GroupEpoch: testEpoch, StateBinding: testBinding}
		idx, routed, err := OpenHeader(env, []HeaderCandidate{candidate(s)})
		if err != nil || idx != 0 || routed != want {
			t.Fatalf("OpenHeader = %d %+v %v", idx, routed, err)
		}
		if got := mustDecrypt(t, r, env, text); got != want {
			t.Fatalf("Decrypt header = %+v, want %+v", got, want)
		}
	}
	if s.Iteration() != 5 || r.Iteration() != 5 {
		t.Fatalf("iterations = %d, %d, want 5, 5", s.Iteration(), r.Iteration())
	}
	if r.GroupEpoch() != 7 || r.Generation() != 1 || r.Group() != s.Group() || r.Sender() != s.Owner() {
		t.Fatal("receiver metadata does not match the distribution")
	}
	mustDecrypt(t, r, encrypt(t, s, ""), "")
}

func TestEpochAndBindingRoundTrip(t *testing.T) {
	s, r := newPair(t)
	for _, tc := range []struct {
		epoch   uint64
		binding [StateBindingSize]byte
	}{
		{0, [StateBindingSize]byte{}},
		{1, [StateBindingSize]byte{0: 1, 31: 0xff}},
		{math.MaxUint64, [StateBindingSize]byte(bytes.Repeat([]byte{0xee}, StateBindingSize))},
	} {
		env, err := s.Encrypt([]byte("state"), tc.epoch, tc.binding)
		if err != nil {
			t.Fatal(err)
		}
		_, routed, err := OpenHeader(env, []HeaderCandidate{candidate(s)})
		if err != nil || routed.GroupEpoch != tc.epoch || routed.StateBinding != tc.binding {
			t.Fatalf("OpenHeader = %+v, %v", routed, err)
		}
		h := mustDecrypt(t, r, env, "state")
		if h.GroupEpoch != tc.epoch || h.StateBinding != tc.binding {
			t.Fatalf("Decrypt header epoch %d binding %x, want %d %x", h.GroupEpoch, h.StateBinding, tc.epoch, tc.binding)
		}
	}
}

func TestEncryptRandomizesEveryEnvelope(t *testing.T) {
	s, _ := newPair(t)
	a, b := encrypt(t, s, "same"), encrypt(t, s, "same")
	wa, wb := decodeEnvelopeWire(t, a), decodeEnvelopeWire(t, b)
	if bytes.Equal(wa.HeaderNonce, wb.HeaderNonce) {
		t.Fatal("two envelopes share a header nonce")
	}
	if openFor(t, s, a).salt == openFor(t, s, b).salt {
		t.Fatal("two envelopes share a salt")
	}
}

// TestRelayView checks what a relay holding envelopes but no keys learns:
// nothing of the group, sender, generation, iteration, epoch or binding, and
// envelopes of the same plaintext length are indistinguishable by shape.
func TestRelayView(t *testing.T) {
	group, owner := randomGroup(t), randomID(t)
	const generation = 0x9e3779b9
	s := newSender(t, group, owner, generation)
	s.iteration = 0x7f4a7c15
	const epoch = 0x2545f4914f6cdd1d
	binding := [StateBindingSize]byte(bytes.Repeat([]byte{0x5c}, StateBindingSize))
	env, err := s.Encrypt([]byte("hello group"), epoch, binding)
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string][]byte{
		"group ID":   group[:],
		"sender ID":  owner[:],
		"generation": binary.BigEndian.AppendUint32(nil, generation),
		"iteration":  binary.BigEndian.AppendUint32(nil, 0x7f4a7c15),
		"epoch":      binary.BigEndian.AppendUint64(nil, epoch),
		"binding":    binding[:8],
	} {
		if bytes.Contains(env, secret) {
			t.Errorf("envelope contains the %s", name)
		}
		if bytes.Contains(env, secret[:4]) {
			t.Errorf("envelope contains a prefix of the %s", name)
		}
	}

	other := newSender(t, randomGroup(t), randomID(t), 1)
	small := encrypt(t, other, "hello world")
	if len(small) != len(env) {
		t.Fatalf("envelope lengths %d and %d differ for equal plaintext lengths", len(env), len(small))
	}
	if !bytes.Equal(env[:len(envelopePrefix)], small[:len(envelopePrefix)]) || !IsGroupEnvelope(small) {
		t.Fatal("group envelopes do not share their prefix")
	}
}

func TestIsGroupEnvelope(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		{0xa5, 0x01, EnvelopeVersion, 0x02, 0x58},
		{0xa4, 0x01, 0x03, 0x02},
		{0xa4, 0x01, 0x03, 0x02, 0x58, 0x18},
		{0xa5, 0x01, 0x04, 0x02, 0x58, 0x18},
		{0xa5, 0x01, 0x03, 0x02, 0x58, 0x18},
		{0xa5, 0x01, 0x02, 0x02, 0x58, 0x18},
		{0xa4, 0x01, 0x02, 0x02},
	} {
		if IsGroupEnvelope(b) {
			t.Errorf("IsGroupEnvelope(%x) = true", b)
		}
	}
	if !IsGroupEnvelope([]byte{0xa5, 0x01, EnvelopeVersion, 0x02, 0x58, 0x18}) {
		t.Error("IsGroupEnvelope = false for the group envelope prefix")
	}
}

func TestOldEnvelopeVersionRejected(t *testing.T) {
	s, r := newPair(t)
	w := decodeEnvelopeWire(t, encrypt(t, s, "x"))
	w.Version = EnvelopeVersion - 1
	old := encodeWire(t, w)
	if IsGroupEnvelope(old) {
		t.Fatal("IsGroupEnvelope accepts an old version")
	}
	wantErr(t, decryptErr(r, old), ErrMalformed)
	_, _, err := OpenHeader(old, []HeaderCandidate{candidate(s)})
	wantErr(t, err, ErrMalformed)
}

func TestOpenHeaderPicksCandidate(t *testing.T) {
	groups := []GroupID{randomGroup(t), randomGroup(t), randomGroup(t)}
	var senders []*Sender
	var candidates []HeaderCandidate
	for _, g := range groups {
		for range 40 {
			owner := randomID(t)
			for gen := uint32(1); gen <= 2; gen++ {
				s := newSender(t, g, owner, gen)
				senders = append(senders, s)
				candidates = append(candidates, candidate(s))
			}
		}
	}
	for _, i := range []int{0, 1, 77, 150, len(senders) - 1} {
		s := senders[i]
		env := encrypt(t, s, "routed")
		idx, h, err := OpenHeader(env, candidates)
		if err != nil || idx != i {
			t.Fatalf("OpenHeader picked %d (%v), want %d", idx, err, i)
		}
		if h.Group != s.Group() || h.Sender != s.Owner() || h.Generation != s.Generation() {
			t.Fatalf("OpenHeader header %+v does not match the sender", h)
		}
	}

	stranger := newSender(t, groups[0], randomID(t), 1)
	idx, h, err := OpenHeader(encrypt(t, stranger, "unknown"), candidates)
	wantErr(t, err, ErrNoHeaderKey)
	if idx != -1 || h != (Header{}) {
		t.Fatalf("failed OpenHeader returned %d %+v", idx, h)
	}
	_, _, err = OpenHeader(encrypt(t, stranger, "none"), nil)
	wantErr(t, err, ErrNoHeaderKey)
	_, _, err = OpenHeader([]byte{0xa5, 0x01, EnvelopeVersion}, candidates)
	wantErr(t, err, ErrMalformed)

	s := senders[5]
	env := encrypt(t, s, "relabelled")
	for name, mutate := range map[string]func(*HeaderCandidate){
		"group":      func(c *HeaderCandidate) { c.Group = groups[1] },
		"sender":     func(c *HeaderCandidate) { c.Sender = randomID(t) },
		"generation": func(c *HeaderCandidate) { c.Generation++ },
		"key":        func(c *HeaderCandidate) { c.Key[0] ^= 1 },
	} {
		c := candidate(s)
		mutate(&c)
		if _, _, err := OpenHeader(env, []HeaderCandidate{c}); !errors.Is(err, ErrNoHeaderKey) {
			t.Errorf("candidate with wrong %s: error = %v", name, err)
		}
	}

	w := decodeEnvelopeWire(t, env)
	w.HeaderNonce = cloneBytes(w.HeaderNonce)
	w.HeaderNonce[0] ^= 1
	_, _, err = OpenHeader(encodeWire(t, w), candidates)
	wantErr(t, err, ErrNoHeaderKey)
}

func TestHeaderKeyring(t *testing.T) {
	var ring HeaderKeyring
	group := randomGroup(t)
	a := newSender(t, group, randomID(t), 1)
	b := newSender(t, group, randomID(t), 1)
	c := newSender(t, randomGroup(t), randomID(t), 4)
	envA, envB, envC := encrypt(t, a, "a"), encrypt(t, b, "b"), encrypt(t, c, "c")

	_, err := ring.Open(envA)
	wantErr(t, err, ErrNoHeaderKey)
	for _, s := range []*Sender{a, b, c} {
		ring.Add(candidate(s))
	}
	stale := candidate(b)
	stale.Key[0] ^= 1
	ring.Add(stale)
	if ring.Len() != 3 {
		t.Fatalf("Len = %d, want 3", ring.Len())
	}
	_, err = ring.Open(envB)
	wantErr(t, err, ErrNoHeaderKey)
	ring.Add(candidate(b))
	for env, s := range map[*[]byte]*Sender{&envA: a, &envB: b, &envC: c} {
		h, err := ring.Open(*env)
		if err != nil || h.Sender != s.Owner() {
			t.Fatalf("Open = %+v, %v", h, err)
		}
	}

	ring.Remove(group, a.Owner(), 1)
	_, err = ring.Open(envA)
	wantErr(t, err, ErrNoHeaderKey)
	if _, err := ring.Open(envB); err != nil {
		t.Fatal(err)
	}
	ring.RemoveGroup(group)
	if ring.Len() != 1 {
		t.Fatalf("Len = %d after RemoveGroup, want 1", ring.Len())
	}
	ring.Destroy()
	if ring.Len() != 0 {
		t.Fatal("Destroy left candidates")
	}
	_, err = ring.Open(envC)
	wantErr(t, err, ErrNoHeaderKey)
}

func TestReceiverHeaderCandidate(t *testing.T) {
	s, r := newPair(t)
	c, err := r.HeaderCandidate()
	if err != nil || c != candidate(s) {
		t.Fatalf("HeaderCandidate = %+v, %v", c, err)
	}
	r.Destroy()
	_, err = r.HeaderCandidate()
	wantErr(t, err, ErrDestroyed)
}

func TestPlaintextLimit(t *testing.T) {
	s, r := newPair(t)
	big := bytes.Repeat([]byte{'a'}, MaxPlaintextSize)
	env, err := s.Encrypt(big, 1, testBinding)
	if err != nil {
		t.Fatal(err)
	}
	mustDecrypt(t, r, env, string(big))
	_, err = s.Encrypt(append(big, 'a'), 1, testBinding)
	wantErr(t, err, ErrPlaintextTooLarge)
	if s.Iteration() != 1 {
		t.Fatal("a rejected plaintext advanced the chain")
	}
}

func TestOutOfOrder(t *testing.T) {
	s, r := newPair(t)
	envs := make([][]byte, 6)
	for i := range envs {
		envs[i] = encrypt(t, s, fmt.Sprint(i))
	}
	for _, i := range []int{4, 0, 2, 5, 1, 3} {
		mustDecrypt(t, r, envs[i], fmt.Sprint(i))
	}
	if r.StoredSkipped() != 0 {
		t.Fatalf("%d skipped keys remain after all messages arrived", r.StoredSkipped())
	}
}

func TestMaxSkip(t *testing.T) {
	s, r := newPair(t)
	advanceSender(s, MaxSkip)
	mustDecrypt(t, r, encrypt(t, s, "at limit"), "at limit")
	if r.StoredSkipped() != MaxSkip {
		t.Fatalf("stored %d skipped keys, want %d", r.StoredSkipped(), MaxSkip)
	}

	advanceSender(s, MaxSkip+1)
	wantErr(t, decryptErr(r, encrypt(t, s, "beyond")), ErrTooManySkipped)
	if r.Iteration() != MaxSkip+1 {
		t.Fatal("rejected skip changed the receiver")
	}
}

func TestSkippedEviction(t *testing.T) {
	s, r := newPair(t)
	lost := encrypt(t, s, "oldest")
	advanceSender(s, MaxSkip-1)
	mustDecrypt(t, r, encrypt(t, s, "first"), "first")
	advanceSender(s, 10)
	mustDecrypt(t, r, encrypt(t, s, "second"), "second")
	if r.StoredSkipped() != MaxStoredSkipped {
		t.Fatalf("stored %d skipped keys, want %d", r.StoredSkipped(), MaxStoredSkipped)
	}
	wantErr(t, decryptErr(r, lost), ErrReplay)
}

func TestReplay(t *testing.T) {
	s, r := newPair(t)
	m0, m1, m2 := encrypt(t, s, "m0"), encrypt(t, s, "m1"), encrypt(t, s, "m2")
	mustDecrypt(t, r, m2, "m2")
	mustDecrypt(t, r, m0, "m0")
	for _, env := range [][]byte{m0, m2} {
		wantErr(t, decryptErr(r, env), ErrReplay)
	}
	mustDecrypt(t, r, m1, "m1")
	wantErr(t, decryptErr(r, m1), ErrReplay)
}

func TestFreeze(t *testing.T) {
	s, r := newPair(t)
	envs := make([][]byte, 5)
	for i := range envs {
		envs[i] = encrypt(t, s, fmt.Sprint(i))
	}
	mustDecrypt(t, r, envs[3], "3")
	r.Freeze()
	r.Freeze()
	if !r.Frozen() || r.chain != ([keySize]byte{}) {
		t.Fatal("Freeze did not freeze the receiver or keep the chain key")
	}
	wantErr(t, decryptErr(r, envs[4]), ErrFrozen)
	wantErr(t, decryptErr(r, encrypt(t, s, "later")), ErrFrozen)
	mustDecrypt(t, r, envs[0], "0")
	wantErr(t, decryptErr(r, envs[0]), ErrReplay)
	if _, err := r.HeaderCandidate(); err != nil {
		t.Fatal(err)
	}

	encoded, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var w receiverWire
	if err := stateDecMode.Unmarshal(encoded, &w); err != nil {
		t.Fatal(err)
	}
	if !w.Frozen || w.ChainKey != nil {
		t.Fatal("frozen receiver serialised without the flag or with a chain key")
	}
	restored, err := UnmarshalReceiver(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Destroy()
	if !restored.Frozen() || restored.Iteration() != 4 || restored.StoredSkipped() != 2 {
		t.Fatal("restored receiver lost its frozen state")
	}
	wantErr(t, decryptErr(restored, envs[4]), ErrFrozen)
	mustDecrypt(t, restored, envs[1], "1")
	mustDecrypt(t, restored, envs[2], "2")
	if restored.StoredSkipped() != 0 {
		t.Fatal("skipped keys remain after use")
	}

	for name, mutate := range map[string]func(*receiverWire){
		"frozen with chain": func(w *receiverWire) { w.ChainKey = make([]byte, keySize) },
		"chain dropped":     func(w *receiverWire) { w.Frozen = false },
	} {
		variant := w
		mutate(&variant)
		if _, err := UnmarshalReceiver(encodeWire(t, variant)); !errors.Is(err, ErrInvalidState) {
			t.Errorf("%s: error = %v, want ErrInvalidState", name, err)
		}
	}
}

func TestPruneSkipped(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	now := t0
	setClock(t, func() time.Time { return now })
	s, r := newPair(t)
	envs := make([][]byte, 8)
	for i := range envs {
		envs[i] = encrypt(t, s, fmt.Sprint(i))
	}
	mustDecrypt(t, r, envs[3], "3")
	now = t0.Add(time.Hour)
	mustDecrypt(t, r, envs[7], "7")
	if r.StoredSkipped() != 6 {
		t.Fatalf("stored %d skipped keys, want 6", r.StoredSkipped())
	}

	encoded, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalReceiver(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Destroy()

	for _, recv := range []*Receiver{r, restored} {
		if n := recv.PruneSkipped(t0); n != 0 {
			t.Fatalf("PruneSkipped(t0) deleted %d keys created at t0", n)
		}
		if n := recv.PruneSkipped(t0.Add(time.Minute)); n != 3 {
			t.Fatalf("PruneSkipped deleted %d keys, want 3", n)
		}
		for _, i := range []int{0, 1, 2} {
			wantErr(t, decryptErr(recv, envs[i]), ErrReplay)
		}
		mustDecrypt(t, recv, envs[5], "5")
		if n := recv.PruneSkipped(t0.Add(2 * time.Hour)); n != 2 {
			t.Fatalf("PruneSkipped deleted %d keys, want 2", n)
		}
		if recv.StoredSkipped() != 0 {
			t.Fatal("keys survived pruning")
		}
		wantErr(t, decryptErr(recv, envs[4]), ErrReplay)
	}
	r.Destroy()
	if r.PruneSkipped(t0.Add(48*time.Hour)) != 0 {
		t.Fatal("destroyed receiver pruned keys")
	}
}

func TestTamperingLeavesReceiverUsable(t *testing.T) {
	s, r := newPair(t)
	env := encrypt(t, s, "genuine")
	w := decodeEnvelopeWire(t, env)

	tamperedNonce := w
	tamperedNonce.HeaderNonce = cloneBytes(w.HeaderNonce)
	tamperedNonce.HeaderNonce[5] ^= 1

	tamperedHeader := w
	tamperedHeader.EncHeader = cloneBytes(w.EncHeader)
	tamperedHeader.EncHeader[10] ^= 1

	tamperedCT := w
	tamperedCT.Ciphertext = cloneBytes(w.Ciphertext)
	tamperedCT.Ciphertext[3] ^= 0x80

	tamperedSig := w
	tamperedSig.Sig = cloneBytes(w.Sig)
	tamperedSig.Sig[len(w.Sig)-1] ^= 1

	tamperedEdSig := w
	tamperedEdSig.Sig = cloneBytes(w.Sig)
	tamperedEdSig.Sig[0] ^= 1

	swapped := w
	swapped.Ciphertext = append(cloneBytes(w.Ciphertext[1:]), w.Ciphertext[0])

	for name, tc := range map[string]struct {
		variant envelopeWire
		want    error
	}{
		"header nonce": {tamperedNonce, ErrNoHeaderKey},
		"enc header":   {tamperedHeader, ErrNoHeaderKey},
		"ciphertext":   {tamperedCT, ErrBadSignature},
		"ML-DSA sig":   {tamperedSig, ErrBadSignature},
		"Ed25519 sig":  {tamperedEdSig, ErrBadSignature},
		"rotated ct":   {swapped, ErrBadSignature},
	} {
		if err := decryptErr(r, encodeWire(t, tc.variant)); !errors.Is(err, tc.want) {
			t.Errorf("%s: error = %v, want %v", name, err, tc.want)
		}
	}

	resealed := openFor(t, s, env)
	resealed.salt[0] ^= 1
	reHeader := w
	reHeader.EncHeader, _ = sealHeader(&s.headerKey, w.HeaderNonce, encodeHeader(resealed))
	if err := decryptErr(r, encodeWire(t, reHeader)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("header re-sealed by a key holder: error = %v, want ErrBadSignature", err)
	}

	for i := range env {
		bad := cloneBytes(env)
		bad[i] ^= 0x01
		if decryptErr(r, bad) == nil {
			t.Fatalf("flipping byte %d was accepted", i)
		}
	}
	for _, cut := range []int{0, 1, len(env) / 2, len(env) - 1} {
		if decryptErr(r, env[:cut]) == nil {
			t.Fatalf("truncation to %d bytes was accepted", cut)
		}
	}
	wantErr(t, decryptErr(r, append(cloneBytes(env), 0x00)), ErrMalformed)

	if r.Iteration() != 0 {
		t.Fatal("rejected envelopes advanced the receiver")
	}
	mustDecrypt(t, r, env, "genuine")
}

func TestSignedButUndecryptable(t *testing.T) {
	s, r := newPair(t)
	h := senderHeader(s)
	h.salt[0] = 1
	var wrongChain [keySize]byte
	forged := forge(t, h, wrongChain, s.headerKey, s.signing, []byte("forged"))
	wantErr(t, decryptErr(r, forged), ErrDecrypt)

	advanceSender(s, 3)
	forged = forge(t, senderHeader(s), wrongChain, s.headerKey, s.signing, []byte("forged"))
	wantErr(t, decryptErr(r, forged), ErrDecrypt)
	if r.Iteration() != 0 || r.StoredSkipped() != 0 {
		t.Fatal("failed decryption changed the receiver")
	}
	mustDecrypt(t, r, encrypt(t, s, "after"), "after")
	if r.StoredSkipped() != 3 {
		t.Fatalf("stored %d skipped keys, want 3", r.StoredSkipped())
	}

	skippedHeader := senderHeader(s)
	skippedHeader.iteration = 1
	forged = forge(t, skippedHeader, wrongChain, s.headerKey, s.signing, []byte("forged"))
	wantErr(t, decryptErr(r, forged), ErrDecrypt)
	if r.StoredSkipped() != 3 {
		t.Fatal("failed decryption consumed a skipped key")
	}
}

// TestCommitmentMismatch builds envelopes whose ciphertext is valid under the
// receiver's message key but whose signed header commits to another message
// key, as a sender that distributed different chain keys would. Only the
// commitment check rejects them.
func TestCommitmentMismatch(t *testing.T) {
	s, r := newPair(t)
	var otherChain [keySize]byte
	otherChain[0] = 0x42
	otherMK, _ := chainStep(otherChain)

	h := senderHeader(s)
	h.commitment = commitMessageKey(otherMK)
	forged := forge(t, h, s.chain, s.headerKey, s.signing, []byte("split view"))
	wantErr(t, decryptErr(r, forged), ErrDecrypt)

	control := forge(t, senderHeader(s), s.chain, s.headerKey, s.signing, []byte("control"))
	mustDecrypt(t, r, control, "control")

	advanceSender(s, 1)
	skippedChain := s.chain
	advanceSender(s, 1)
	mustDecrypt(t, r, encrypt(t, s, "ahead"), "ahead")
	if r.StoredSkipped() != 1 {
		t.Fatalf("stored %d skipped keys, want 1", r.StoredSkipped())
	}
	skippedHeader := senderHeader(s)
	skippedHeader.iteration = 1
	skippedHeader.commitment = commitMessageKey(otherMK)
	wantErr(t, decryptErr(r, forge(t, skippedHeader, skippedChain, s.headerKey, s.signing, []byte("split"))), ErrDecrypt)
	if r.StoredSkipped() != 1 {
		t.Fatal("commitment failure consumed a skipped key")
	}
	skippedHeader.commitment = [commitmentSize]byte{}
	mustDecrypt(t, r, forge(t, skippedHeader, skippedChain, s.headerKey, s.signing, []byte("late")), "late")
}

func TestMemberCannotImpersonateSender(t *testing.T) {
	s, r := newPair(t)
	insider, err := hybridsig.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer insider.Destroy()
	forged := forge(t, senderHeader(s), s.chain, s.headerKey, insider, []byte("impersonation"))
	wantErr(t, decryptErr(r, forged), ErrBadSignature)
	mustDecrypt(t, r, encrypt(t, s, "genuine"), "genuine")
}

func TestOtherGenerationKeyRejected(t *testing.T) {
	group, owner := randomGroup(t), randomID(t)
	gen1 := newSender(t, group, owner, 1)
	gen2 := newSender(t, group, owner, 2)
	r1 := newReceiver(t, gen1, 3)

	forged := forge(t, senderHeader(gen1), gen1.chain, gen1.headerKey, gen2.signing, []byte("cross-generation"))
	wantErr(t, decryptErr(r1, forged), ErrBadSignature)

	wantErr(t, decryptErr(r1, encrypt(t, gen2, "newer")), ErrNoHeaderKey)
	r2 := newReceiver(t, gen2, 4)
	wantErr(t, decryptErr(r2, encrypt(t, gen1, "older")), ErrNoHeaderKey)

	newer := senderHeader(gen1)
	newer.generation = 2
	wantErr(t, decryptErr(r1, forge(t, newer, gen1.chain, gen1.headerKey, gen1.signing, nil)), ErrUnknownGeneration)
	older := senderHeader(gen2)
	older.generation = 1
	wantErr(t, decryptErr(r2, forge(t, older, gen2.chain, gen2.headerKey, gen2.signing, nil)), ErrOldGeneration)

	mustDecrypt(t, r1, encrypt(t, gen1, "ok"), "ok")
}

func TestRoutingMismatch(t *testing.T) {
	s, r := newPair(t)

	other := newSender(t, randomGroup(t), s.Owner(), 1)
	wantErr(t, decryptErr(r, encrypt(t, other, "other group")), ErrNoHeaderKey)

	impostor := newSender(t, s.Group(), randomID(t), 1)
	wantErr(t, decryptErr(r, encrypt(t, impostor, "other sender")), ErrNoHeaderKey)

	moved := senderHeader(s)
	moved.group = other.Group()
	wantErr(t, decryptErr(r, forge(t, moved, s.chain, s.headerKey, s.signing, nil)), ErrWrongGroup)

	dist, err := s.Distribution(1)
	if err != nil {
		t.Fatal(err)
	}
	misbound, err := NewReceiver(dist, randomID(t))
	if err != nil {
		t.Fatal(err)
	}
	defer misbound.Destroy()
	wantErr(t, decryptErr(misbound, encrypt(t, s, "bound elsewhere")), ErrWrongSender)
	mustDecrypt(t, r, encrypt(t, s, "ok"), "ok")
}

func TestReceiverCreatedMidChain(t *testing.T) {
	s := newSender(t, randomGroup(t), randomID(t), 4)
	early := [][]byte{encrypt(t, s, "e0"), encrypt(t, s, "e1"), encrypt(t, s, "e2")}
	dist, err := s.Distribution(9)
	if err != nil {
		t.Fatal(err)
	}
	info, err := ParseDistribution(dist)
	if err != nil {
		t.Fatal(err)
	}
	if info != (DistributionInfo{GroupID: s.Group(), Generation: 4, Iteration: 3, GroupEpoch: 9}) {
		t.Fatalf("ParseDistribution = %+v", info)
	}
	r, err := NewReceiver(dist, s.Owner())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	late := encrypt(t, s, "late")
	for _, env := range early {
		wantErr(t, decryptErr(r, env), ErrReplay)
	}
	mustDecrypt(t, r, late, "late")
}

func TestSenderMarshalRoundTrip(t *testing.T) {
	s, r := newPair(t)
	mustDecrypt(t, r, encrypt(t, s, "before"), "before")
	encoded, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalSender(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Destroy()
	again, err := restored.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, again) {
		t.Fatal("sender serialisation is not stable")
	}
	if restored.Iteration() != 1 || restored.Generation() != s.Generation() || !restored.CreatedAt().Equal(s.CreatedAt()) {
		t.Fatal("restored sender metadata differs")
	}
	if !restored.signing.Public().Equal(s.signing.Public()) || restored.headerKey != s.headerKey {
		t.Fatal("restored keys differ")
	}
	mustDecrypt(t, r, encrypt(t, restored, "after"), "after")

	for name, bad := range map[string][]byte{
		"trailing":  append(cloneBytes(encoded), 0),
		"truncated": encoded[:len(encoded)-1],
		"empty":     nil,
	} {
		if _, err := UnmarshalSender(bad); !errors.Is(err, ErrInvalidState) {
			t.Errorf("%s: error = %v, want ErrInvalidState", name, err)
		}
	}
	var w senderWire
	if err := strictDecMode.Unmarshal(encoded, &w); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*senderWire){
		"old version":       func(w *senderWire) { w.Version = 1 },
		"newer version":     func(w *senderWire) { w.Version = 3 },
		"zero group":        func(w *senderWire) { w.GroupID = make([]byte, 32) },
		"zero owner":        func(w *senderWire) { w.Owner = make([]byte, 32) },
		"short seed":        func(w *senderWire) { w.EdSeed = w.EdSeed[:31] },
		"no created":        func(w *senderWire) { w.Created = 0 },
		"short header key":  func(w *senderWire) { w.HeaderKey = w.HeaderKey[:31] },
		"no header key":     func(w *senderWire) { w.HeaderKey = nil },
		"version 1 no hkey": func(w *senderWire) { w.Version, w.HeaderKey = 1, nil },
	} {
		variant := w
		mutate(&variant)
		if _, err := UnmarshalSender(encodeWire(t, variant)); !errors.Is(err, ErrInvalidState) {
			t.Errorf("%s: error = %v, want ErrInvalidState", name, err)
		}
	}
}

func TestReceiverMarshalRoundTrip(t *testing.T) {
	s, r := newPair(t)
	envs := make([][]byte, 5)
	for i := range envs {
		envs[i] = encrypt(t, s, fmt.Sprint(i))
	}
	mustDecrypt(t, r, envs[4], "4")
	mustDecrypt(t, r, envs[1], "1")

	encoded, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalReceiver(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Destroy()
	again, err := restored.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, again) {
		t.Fatal("receiver serialisation is not stable")
	}
	if c, err := restored.HeaderCandidate(); err != nil || c != candidate(s) {
		t.Fatal("restored receiver lost its header key")
	}
	for _, i := range []int{0, 2, 3} {
		mustDecrypt(t, restored, envs[i], fmt.Sprint(i))
	}
	wantErr(t, decryptErr(restored, envs[1]), ErrReplay)
	mustDecrypt(t, restored, encrypt(t, s, "5"), "5")

	fresh, err := newReceiver(t, s, 1).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalReceiver(fresh); err != nil {
		t.Fatalf("receiver without skipped keys: %v", err)
	}

	var w receiverWire
	if err := stateDecMode.Unmarshal(encoded, &w); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*receiverWire){
		"old version":      func(w *receiverWire) { w.Version = 1 },
		"newer version":    func(w *receiverWire) { w.Version = 9 },
		"zero sender":      func(w *receiverWire) { w.Sender = make([]byte, 32) },
		"short chain":      func(w *receiverWire) { w.ChainKey = w.ChainKey[:31] },
		"no chain":         func(w *receiverWire) { w.ChainKey = nil },
		"short header key": func(w *receiverWire) { w.HeaderKey = w.HeaderKey[:31] },
		"bad pub":          func(w *receiverWire) { w.SigningPub = w.SigningPub[1:] },
		"skip at pos": func(w *receiverWire) {
			w.Skipped = append(w.Skipped, skippedWire{Iteration: w.Iteration, Key: make([]byte, 32), Created: 1})
		},
		"skip unsorted": func(w *receiverWire) { w.Skipped[0], w.Skipped[1] = w.Skipped[1], w.Skipped[0] },
		"skip short":    func(w *receiverWire) { w.Skipped[0].Key = w.Skipped[0].Key[:16] },
		"skip no time":  func(w *receiverWire) { w.Skipped[0].Created = 0 },
		"empty skipped": func(w *receiverWire) { w.Skipped = []skippedWire{} },
		"false frozen":  func(w *receiverWire) {},
	} {
		variant := w
		variant.Skipped = append([]skippedWire(nil), w.Skipped...)
		mutate(&variant)
		b := encodeWire(t, variant)
		switch name {
		case "empty skipped":
			b = append([]byte{b[0] + 1}, b[1:]...)
			b = append(b, 0x09, 0x80)
		case "false frozen":
			b = append([]byte{b[0] + 1}, b[1:]...)
			b = append(b, 0x0b, 0xf4)
		}
		if _, err := UnmarshalReceiver(b); !errors.Is(err, ErrInvalidState) {
			t.Errorf("%s: error = %v, want ErrInvalidState", name, err)
		}
	}
}

func TestDistributionValidation(t *testing.T) {
	s := newSender(t, randomGroup(t), randomID(t), 2)
	dist, err := s.Distribution(5)
	if err != nil {
		t.Fatal(err)
	}
	var w distributionWire
	if err := strictDecMode.Unmarshal(dist, &w); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.HeaderKey, s.headerKey[:]) {
		t.Fatal("distribution does not carry the header key")
	}
	for name, mutate := range map[string]func(*distributionWire){
		"old version":      func(w *distributionWire) { w.Version = 1 },
		"newer version":    func(w *distributionWire) { w.Version = 3 },
		"zero group":       func(w *distributionWire) { w.GroupID = make([]byte, 32) },
		"short group":      func(w *distributionWire) { w.GroupID = w.GroupID[:31] },
		"short chain":      func(w *distributionWire) { w.ChainKey = w.ChainKey[:31] },
		"short pub":        func(w *distributionWire) { w.SigningPub = w.SigningPub[:100] },
		"max iteration":    func(w *distributionWire) { w.Iteration = math.MaxUint32 },
		"short header key": func(w *distributionWire) { w.HeaderKey = w.HeaderKey[:31] },
		"no header key":    func(w *distributionWire) { w.HeaderKey = nil },
	} {
		variant := w
		mutate(&variant)
		if _, err := ParseDistribution(encodeWire(t, variant)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: error = %v, want ErrMalformed", name, err)
		}
	}
	for name, bad := range map[string][]byte{
		"trailing":  append(cloneBytes(dist), 0),
		"truncated": dist[:len(dist)-1],
		"envelope":  encrypt(t, s, "x"),
	} {
		if _, err := ParseDistribution(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: error = %v, want ErrMalformed", name, err)
		}
	}
	if _, err := NewReceiver(dist, identity.ID{}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("zero sender: error = %v", err)
	}
	if _, err := NewSender(GroupID{}, randomID(t), 1); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("zero group: error = %v", err)
	}
	if _, err := NewSender(randomGroup(t), identity.ID{}, 1); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("zero owner: error = %v", err)
	}
	other := newSender(t, s.Group(), s.Owner(), 3)
	if s.headerKey == other.headerKey || s.headerKey == ([HeaderKeySize]byte{}) {
		t.Fatal("generations do not get fresh header keys")
	}
}

func TestNeedsRotation(t *testing.T) {
	s := newSender(t, randomGroup(t), randomID(t), 1)
	created := s.CreatedAt()
	if s.NeedsRotation(created) {
		t.Fatal("new sender needs rotation")
	}
	if s.NeedsRotation(created.Add(RotationAge - time.Second)) {
		t.Fatal("rotation due before RotationAge")
	}
	if !s.NeedsRotation(created.Add(RotationAge)) {
		t.Fatal("rotation not due at RotationAge")
	}
	advanceSender(s, RotationMessages-1)
	if s.NeedsRotation(created) {
		t.Fatal("rotation due before RotationMessages")
	}
	encrypt(t, s, "last")
	if !s.NeedsRotation(created) {
		t.Fatal("rotation not due after RotationMessages")
	}
}

func TestChainExhausted(t *testing.T) {
	s := newSender(t, randomGroup(t), randomID(t), 1)
	s.iteration = math.MaxUint32 - 1
	env := encrypt(t, s, "final")
	if it := openFor(t, s, env).iteration; it != math.MaxUint32-1 {
		t.Fatalf("final envelope iteration %d", it)
	}
	_, err := s.Encrypt([]byte("x"), 1, testBinding)
	wantErr(t, err, ErrChainExhausted)
	_, err = s.Distribution(1)
	wantErr(t, err, ErrChainExhausted)
}

func TestDestroy(t *testing.T) {
	s, r := newPair(t)
	env := encrypt(t, s, "x")
	s.Destroy()
	r.Destroy()
	if _, err := s.Encrypt(nil, 1, testBinding); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
	}
	if _, err := s.Marshal(); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
	}
	if _, err := s.Distribution(0); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
	}
	if err := decryptErr(r, env); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
	}
	if _, err := r.Marshal(); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
	}
	r.Freeze()
	if r.Frozen() {
		t.Fatal("destroyed receiver was frozen")
	}
}

func TestChainKAT(t *testing.T) {
	var ck [keySize]byte
	for i := range ck {
		ck[i] = byte(i)
	}
	mk0, next := chainStep(ck)
	mk1, _ := chainStep(next)
	salt := make([]byte, SaltSize)
	for i := range salt {
		salt[i] = byte(0xa0 + i)
	}
	key, nonce, err := messageAEADKey(mk0, salt)
	if err != nil {
		t.Fatal(err)
	}
	commitment := commitMessageKey(mk0)
	for name, tc := range map[string]struct {
		got  []byte
		want string
	}{
		"MK0":        {mk0[:], "9b4c8120a4823a95f47cde17a244f4507244ee6e3957d1fab9fa29b44d3829b7"},
		"CK1":        {next[:], "4304c22c84a53755ab08ead8d97a8d429be5efa480682d7ad1da27f73e1fbe1d"},
		"MK1":        {mk1[:], "f7703c39dea9feb30cb6369304ad7b847b9aca58c1152af317aa78a91beddda1"},
		"key":        {key[:], "b906e9527f7572c6b375036b37a7b673b500b362d12b4004221327cf8b9f7462"},
		"nonce":      {nonce[:], "1ac56c6fba725dd3d476126a"},
		"commitment": {commitment[:], "e65c0dedf6b5463715ca9c0eb16766928cbf60844bce115683ce9fbc556988cb"},
	} {
		if hex.EncodeToString(tc.got) != tc.want {
			t.Errorf("%s = %x, want %s", name, tc.got, tc.want)
		}
	}
	if _, _, err := messageAEADKey(mk0, salt[:15]); err == nil {
		t.Error("short salt accepted")
	}
}

func katHeader() header {
	h := header{generation: 0x0102, iteration: 5, groupEpoch: 0x0a0b0c0d0e0f1011}
	for i := range h.group {
		h.group[i] = 0x11
		h.sender[i] = 0x22
		h.binding[i] = 0x44
		h.commitment[i] = 0x55
	}
	for i := range h.salt {
		h.salt[i] = 0x33
	}
	return h
}

func TestHeaderEncoding(t *testing.T) {
	h := katHeader()
	hb := encodeHeader(h)
	want := "02" +
		hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)) +
		hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32)) +
		"00000102" +
		"00000005" +
		"0a0b0c0d0e0f1011" +
		hex.EncodeToString(bytes.Repeat([]byte{0x44}, 32)) +
		hex.EncodeToString(bytes.Repeat([]byte{0x33}, 16)) +
		hex.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	if hex.EncodeToString(hb) != want || len(hb) != headerSize {
		t.Fatalf("header = %x\nwant     %s", hb, want)
	}
	parsed, err := parseHeader(hb)
	if err != nil || parsed != h {
		t.Fatalf("parseHeader = %+v, %v", parsed, err)
	}
	for name, bad := range map[string][]byte{
		"version 1":     append([]byte{1}, hb[1:]...),
		"short":         hb[:headerSize-1],
		"long":          append(cloneBytes(hb), 0),
		"max iteration": append(append(cloneBytes(hb[:69]), 0xff, 0xff, 0xff, 0xff), hb[73:]...),
	} {
		if _, err := parseHeader(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: error = %v, want ErrMalformed", name, err)
		}
	}
}

func TestHeaderSealKAT(t *testing.T) {
	var key [HeaderKeySize]byte
	for i := range key {
		key[i] = byte(0x80 + i)
	}
	nonce := make([]byte, HeaderNonceSize)
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
	}
	sealed, err := sealHeader(&key, nonce, encodeHeader(katHeader()))
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != encHeaderSize {
		t.Fatalf("sealed header of %d bytes, want %d", len(sealed), encHeaderSize)
	}
	if got := hex.EncodeToString(sealed); got != "f31d62e54ae1e54bea0366c2e7bf8c442356637f14558dfddbabe41d53441cd9111e325f094fbd5f13f1c36b4cb17c78e33388368e1986528cc6b5755f44b61f63e0e28560dbbc65c0781295e9a0c6ae5a138d4fe15878be4093505152e2d5ce06cf476dbd074e8247a0329233e7ef3e8533f900853c4175a9a88c80186a06a4751f7d78202a8486ce6c8557001ad7fb08cf9cb2007d9748ad89fa932283848cb038881e895835e9ea1b801c29057f037b" {
		t.Fatalf("sealed header = %s", got)
	}
	opened, ok := openHeader(&key, nonce, sealed)
	if !ok || !bytes.Equal(opened, encodeHeader(katHeader())) {
		t.Fatal("sealed header does not open")
	}
}
