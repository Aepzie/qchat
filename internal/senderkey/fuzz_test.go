package senderkey

import (
	"bytes"
	"testing"
)

// FuzzDecrypt feeds arbitrary bytes into a receiver that already holds
// skipped keys. Decrypt must never panic, must accept nothing but the
// genuine envelopes (signatures cannot be forged), and whatever it did, the
// receiver must still decrypt the genuine next message afterwards.
func FuzzDecrypt(f *testing.F) {
	s, r := newPair(f)
	genuine := map[string]string{}
	envs := make([][]byte, 4)
	for i := range envs {
		text := string(rune('a' + i))
		envs[i] = encrypt(f, s, text)
		genuine[string(envs[i])] = text
	}
	mustDecrypt(f, r, envs[2], "c")
	check := encrypt(f, s, "check")
	base, err := r.Marshal()
	if err != nil {
		f.Fatal(err)
	}

	for _, env := range envs {
		f.Add(env)
	}
	f.Add(check)
	f.Add([]byte{})
	f.Add([]byte{0xa4, 0x01, 0x03, 0x02})
	other, _ := newPair(f)
	f.Add(encrypt(f, other, "other"))

	f.Fuzz(func(t *testing.T, input []byte) {
		group, sender, generation, iteration, parseErr := ParseEnvelopeHeader(input)
		if parseErr == nil && !IsGroupEnvelope(input) {
			t.Fatal("parsable envelope not recognised by IsGroupEnvelope")
		}
		recv, err := UnmarshalReceiver(base)
		if err != nil {
			t.Fatal(err)
		}
		defer recv.Destroy()
		plaintext, err := recv.Decrypt(input)
		if err == nil {
			want, ok := genuine[string(input)]
			if !ok && bytes.Equal(input, check) {
				want, ok = "check", true
			}
			if !ok || string(plaintext) != want {
				t.Fatalf("accepted a non-genuine envelope: %q", plaintext)
			}
			if parseErr != nil || group != s.Group() || sender != s.Owner() || generation != s.Generation() || iteration >= s.Iteration() {
				t.Fatal("ParseEnvelopeHeader disagrees with a successful Decrypt")
			}
			if bytes.Equal(input, check) {
				return
			}
		}
		mustDecrypt(t, recv, check, "check")
	})
}

// FuzzParseDistribution checks that ParseDistribution never panics, accepts
// only canonical encodings, and agrees with NewReceiver.
func FuzzParseDistribution(f *testing.F) {
	s := newSender(f, randomGroup(f), randomID(f), 3)
	dist, err := s.Distribution(11)
	if err != nil {
		f.Fatal(err)
	}
	from := randomID(f)
	f.Add(dist)
	f.Add([]byte{})
	f.Add([]byte{0xa7, 0x01, 0x01})
	f.Add(encrypt(f, s, "not a distribution"))

	f.Fuzz(func(t *testing.T, input []byte) {
		info, err := ParseDistribution(input)
		r, rerr := NewReceiver(input, from)
		if (err == nil) != (rerr == nil) {
			t.Fatalf("ParseDistribution error %v, NewReceiver error %v", err, rerr)
		}
		if err != nil {
			return
		}
		defer r.Destroy()
		var w distributionWire
		if err := strictDecMode.Unmarshal(input, &w); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encodeWire(t, w), input) {
			t.Fatal("accepted a non-canonical distribution")
		}
		if r.Group() != info.GroupID || r.Generation() != info.Generation || r.Iteration() != info.Iteration || r.GroupEpoch() != info.GroupEpoch {
			t.Fatal("receiver disagrees with ParseDistribution")
		}
		encoded, err := r.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := UnmarshalReceiver(encoded)
		if err != nil {
			t.Fatalf("receiver from an accepted distribution does not round trip: %v", err)
		}
		restored.Destroy()
	})
}
