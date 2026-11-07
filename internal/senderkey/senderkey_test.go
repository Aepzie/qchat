package senderkey

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/identity"
)

func TestRoundTrip(t *testing.T) {
	s, r := newPair(t)
	for i := range 5 {
		text := fmt.Sprintf("message %d", i)
		env := encrypt(t, s, text)
		if !IsGroupEnvelope(env) {
			t.Fatal("IsGroupEnvelope = false for a group envelope")
		}
		group, sender, generation, iteration, err := ParseEnvelopeHeader(env)
		if err != nil {
			t.Fatal(err)
		}
		if group != s.Group() || sender != s.Owner() || generation != 1 || iteration != uint32(i) {
			t.Fatalf("ParseEnvelopeHeader = %x %x %d %d", group, sender, generation, iteration)
		}
		mustDecrypt(t, r, env, text)
	}
	if s.Iteration() != 5 || r.Iteration() != 5 {
		t.Fatalf("iterations = %d, %d, want 5, 5", s.Iteration(), r.Iteration())
	}
	if r.GroupEpoch() != 7 || r.Generation() != 1 || r.Group() != s.Group() || r.Sender() != s.Owner() {
		t.Fatal("receiver metadata does not match the distribution")
	}
	mustDecrypt(t, r, encrypt(t, s, ""), "")
}

func TestEncryptSaltIsFresh(t *testing.T) {
	s, _ := newPair(t)
	a, b := encrypt(t, s, "same"), encrypt(t, s, "same")
	ha, _ := parseEnvelope(a)
	hb, _ := parseEnvelope(b)
	if ha.header.salt == hb.header.salt {
		t.Fatal("two envelopes share a salt")
	}
}

func TestIsGroupEnvelope(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		{0xa4, 0x01, EnvelopeVersion},
		{0xa3, 0x01, 0x02, 0x03},
		{0xa4, 0x01, 0x02, 0x02},
		{0xa4, 0x01, 0x02, 0x03},
	} {
		if IsGroupEnvelope(b) {
			t.Errorf("IsGroupEnvelope(%x) = true", b)
		}
	}
}

func TestPlaintextLimit(t *testing.T) {
	s, r := newPair(t)
	big := bytes.Repeat([]byte{'a'}, MaxPlaintextSize)
	env, err := s.Encrypt(big)
	if err != nil {
		t.Fatal(err)
	}
	mustDecrypt(t, r, env, string(big))
	_, err = s.Encrypt(append(big, 'a'))
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
	if len(r.skipped) != 0 {
		t.Fatalf("%d skipped keys remain after all messages arrived", len(r.skipped))
	}
}

func TestMaxSkip(t *testing.T) {
	s, r := newPair(t)
	advanceSender(s, MaxSkip)
	mustDecrypt(t, r, encrypt(t, s, "at limit"), "at limit")
	if len(r.skipped) != MaxSkip {
		t.Fatalf("stored %d skipped keys, want %d", len(r.skipped), MaxSkip)
	}

	advanceSender(s, MaxSkip+1)
	_, err := r.Decrypt(encrypt(t, s, "beyond"))
	wantErr(t, err, ErrTooManySkipped)
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
	if len(r.skipped) != MaxStoredSkipped {
		t.Fatalf("stored %d skipped keys, want %d", len(r.skipped), MaxStoredSkipped)
	}
	_, err := r.Decrypt(lost)
	wantErr(t, err, ErrReplay)
}

func TestReplay(t *testing.T) {
	s, r := newPair(t)
	m0, m1, m2 := encrypt(t, s, "m0"), encrypt(t, s, "m1"), encrypt(t, s, "m2")
	mustDecrypt(t, r, m2, "m2")
	mustDecrypt(t, r, m0, "m0")
	for _, env := range [][]byte{m0, m2} {
		_, err := r.Decrypt(env)
		wantErr(t, err, ErrReplay)
	}
	mustDecrypt(t, r, m1, "m1")
	_, err := r.Decrypt(m1)
	wantErr(t, err, ErrReplay)
}

func TestTamperingLeavesReceiverUsable(t *testing.T) {
	s, r := newPair(t)
	env := encrypt(t, s, "genuine")
	w := decodeEnvelopeWire(t, env)

	hw := headerWire{}
	if err := strictDecMode.Unmarshal(w.Header, &hw); err != nil {
		t.Fatal(err)
	}
	hw.Salt = cloneBytes(hw.Salt)
	hw.Salt[0] ^= 1
	tamperedHeader := w
	tamperedHeader.Header = encodeWire(t, hw)

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

	for name, variant := range map[string]envelopeWire{
		"header salt": tamperedHeader,
		"ciphertext":  tamperedCT,
		"ML-DSA sig":  tamperedSig,
		"Ed25519 sig": tamperedEdSig,
		"rotated ct":  swapped,
	} {
		_, err := r.Decrypt(encodeWire(t, variant))
		if !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: error = %v, want ErrBadSignature", name, err)
		}
	}

	for i := range env {
		bad := cloneBytes(env)
		bad[i] ^= 0x01
		if _, err := r.Decrypt(bad); err == nil {
			t.Fatalf("flipping byte %d was accepted", i)
		}
	}
	for _, cut := range []int{0, 1, len(env) / 2, len(env) - 1} {
		if _, err := r.Decrypt(env[:cut]); err == nil {
			t.Fatalf("truncation to %d bytes was accepted", cut)
		}
	}
	_, err := r.Decrypt(append(cloneBytes(env), 0x00))
	wantErr(t, err, ErrMalformed)

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
	forged := forge(t, h, wrongChain, s.signing, []byte("forged"))
	_, err := r.Decrypt(forged)
	wantErr(t, err, ErrDecrypt)

	advanceSender(s, 3)
	h = senderHeader(s)
	forged = forge(t, h, wrongChain, s.signing, []byte("forged"))
	_, err = r.Decrypt(forged)
	wantErr(t, err, ErrDecrypt)
	if r.Iteration() != 0 || len(r.skipped) != 0 {
		t.Fatal("failed decryption changed the receiver")
	}
	mustDecrypt(t, r, encrypt(t, s, "after"), "after")
	if len(r.skipped) != 3 {
		t.Fatalf("stored %d skipped keys, want 3", len(r.skipped))
	}

	skippedHeader := header{group: s.group, sender: s.owner, generation: s.generation, iteration: 1}
	forged = forge(t, skippedHeader, wrongChain, s.signing, []byte("forged"))
	_, err = r.Decrypt(forged)
	wantErr(t, err, ErrDecrypt)
	if len(r.skipped) != 3 {
		t.Fatal("failed decryption consumed a skipped key")
	}
}

func TestMemberCannotImpersonateSender(t *testing.T) {
	s, r := newPair(t)
	insider, err := hybridsig.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer insider.Destroy()
	forged := forge(t, senderHeader(s), s.chain, insider, []byte("impersonation"))
	_, err = r.Decrypt(forged)
	wantErr(t, err, ErrBadSignature)
	mustDecrypt(t, r, encrypt(t, s, "genuine"), "genuine")
}

func TestOtherGenerationKeyRejected(t *testing.T) {
	group, owner := randomGroup(t), randomID(t)
	gen1 := newSender(t, group, owner, 1)
	gen2 := newSender(t, group, owner, 2)
	r1 := newReceiver(t, gen1, 3)

	forged := forge(t, senderHeader(gen1), gen1.chain, gen2.signing, []byte("cross-generation"))
	_, err := r1.Decrypt(forged)
	wantErr(t, err, ErrBadSignature)

	_, err = r1.Decrypt(encrypt(t, gen2, "newer"))
	wantErr(t, err, ErrUnknownGeneration)

	r2 := newReceiver(t, gen2, 4)
	_, err = r2.Decrypt(encrypt(t, gen1, "older"))
	wantErr(t, err, ErrOldGeneration)

	mustDecrypt(t, r1, encrypt(t, gen1, "ok"), "ok")
}

func TestRoutingMismatch(t *testing.T) {
	s, r := newPair(t)

	other := newSender(t, randomGroup(t), s.Owner(), 1)
	_, err := r.Decrypt(encrypt(t, other, "other group"))
	wantErr(t, err, ErrWrongGroup)

	impostor := newSender(t, s.Group(), randomID(t), 1)
	_, err = r.Decrypt(encrypt(t, impostor, "other sender"))
	wantErr(t, err, ErrWrongSender)

	dist, err := s.Distribution(1)
	if err != nil {
		t.Fatal(err)
	}
	misbound, err := NewReceiver(dist, randomID(t))
	if err != nil {
		t.Fatal(err)
	}
	defer misbound.Destroy()
	_, err = misbound.Decrypt(encrypt(t, s, "bound elsewhere"))
	wantErr(t, err, ErrWrongSender)
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
		_, err := r.Decrypt(env)
		wantErr(t, err, ErrReplay)
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
	if !restored.signing.Public().Equal(s.signing.Public()) {
		t.Fatal("restored signing key differs")
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
		"version":    func(w *senderWire) { w.Version = 2 },
		"zero group": func(w *senderWire) { w.GroupID = make([]byte, 32) },
		"zero owner": func(w *senderWire) { w.Owner = make([]byte, 32) },
		"short seed": func(w *senderWire) { w.EdSeed = w.EdSeed[:31] },
		"no created": func(w *senderWire) { w.Created = 0 },
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
	for _, i := range []int{0, 2, 3} {
		mustDecrypt(t, restored, envs[i], fmt.Sprint(i))
	}
	_, err = restored.Decrypt(envs[1])
	wantErr(t, err, ErrReplay)
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
		"version":     func(w *receiverWire) { w.Version = 9 },
		"zero sender": func(w *receiverWire) { w.Sender = make([]byte, 32) },
		"short chain": func(w *receiverWire) { w.ChainKey = w.ChainKey[:31] },
		"bad pub":     func(w *receiverWire) { w.SigningPub = w.SigningPub[1:] },
		"skip at pos": func(w *receiverWire) {
			w.Skipped = append(w.Skipped, skippedWire{Iteration: w.Iteration, Key: make([]byte, 32)})
		},
		"skip unsorted": func(w *receiverWire) { w.Skipped[0], w.Skipped[1] = w.Skipped[1], w.Skipped[0] },
		"skip short":    func(w *receiverWire) { w.Skipped[0].Key = w.Skipped[0].Key[:16] },
		"empty skipped": func(w *receiverWire) { w.Skipped = []skippedWire{} },
	} {
		variant := w
		variant.Skipped = append([]skippedWire(nil), w.Skipped...)
		mutate(&variant)
		b, err := encMode.Marshal(variant)
		if err != nil {
			t.Fatal(err)
		}
		if name == "empty skipped" {
			b = append(b[:0:0], b...)
			b[0]++
			b = append(b, 0x09, 0x80)
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
	for name, mutate := range map[string]func(*distributionWire){
		"version":       func(w *distributionWire) { w.Version = 2 },
		"zero group":    func(w *distributionWire) { w.GroupID = make([]byte, 32) },
		"short group":   func(w *distributionWire) { w.GroupID = w.GroupID[:31] },
		"short chain":   func(w *distributionWire) { w.ChainKey = w.ChainKey[:31] },
		"short pub":     func(w *distributionWire) { w.SigningPub = w.SigningPub[:100] },
		"max iteration": func(w *distributionWire) { w.Iteration = math.MaxUint32 },
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
	if _, _, _, it, err := ParseEnvelopeHeader(env); err != nil || it != math.MaxUint32-1 {
		t.Fatalf("final envelope iteration %d, err %v", it, err)
	}
	_, err := s.Encrypt([]byte("x"))
	wantErr(t, err, ErrChainExhausted)
	_, err = s.Distribution(1)
	wantErr(t, err, ErrChainExhausted)
}

func TestDestroy(t *testing.T) {
	s, r := newPair(t)
	env := encrypt(t, s, "x")
	s.Destroy()
	r.Destroy()
	if _, err := s.Encrypt(nil); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
	}
	if _, err := s.Marshal(); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
	}
	if _, err := s.Distribution(0); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
	}
	if _, err := r.Decrypt(env); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
	}
	if _, err := r.Marshal(); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
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
	for name, tc := range map[string]struct {
		got  []byte
		want string
	}{
		"MK0":   {mk0[:], "9b4c8120a4823a95f47cde17a244f4507244ee6e3957d1fab9fa29b44d3829b7"},
		"CK1":   {next[:], "4304c22c84a53755ab08ead8d97a8d429be5efa480682d7ad1da27f73e1fbe1d"},
		"MK1":   {mk1[:], "f7703c39dea9feb30cb6369304ad7b847b9aca58c1152af317aa78a91beddda1"},
		"key":   {key[:], "b906e9527f7572c6b375036b37a7b673b500b362d12b4004221327cf8b9f7462"},
		"nonce": {nonce[:], "1ac56c6fba725dd3d476126a"},
	} {
		if hex.EncodeToString(tc.got) != tc.want {
			t.Errorf("%s = %x, want %s", name, tc.got, tc.want)
		}
	}
	if _, _, err := messageAEADKey(mk0, salt[:15]); err == nil {
		t.Error("short salt accepted")
	}
}

func TestHeaderEncoding(t *testing.T) {
	h := header{generation: 0x0102, iteration: 5}
	for i := range h.group {
		h.group[i] = 0x11
		h.sender[i] = 0x22
	}
	for i := range h.salt {
		h.salt[i] = 0x33
	}
	hb, err := encodeHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	want := "a6" +
		"0101" +
		"025820" + hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)) +
		"035820" + hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32)) +
		"04190102" +
		"0505" +
		"0650" + hex.EncodeToString(bytes.Repeat([]byte{0x33}, 16))
	if hex.EncodeToString(hb) != want {
		t.Fatalf("header = %x\nwant     %s", hb, want)
	}
	parsed, err := parseHeader(hb)
	if err != nil || parsed != h {
		t.Fatalf("parseHeader = %+v, %v", parsed, err)
	}
	nonCanonical := append([]byte{0xb8, 0x06}, hb[1:]...)
	if _, err := parseHeader(nonCanonical); !errors.Is(err, ErrMalformed) {
		t.Fatalf("non-canonical header: %v", err)
	}
}
