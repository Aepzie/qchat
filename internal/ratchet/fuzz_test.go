package ratchet

import (
	"testing"
)

// FuzzDecrypt feeds arbitrary headers and ciphertexts into a live
// mid-conversation state. Decrypt must never panic, and whatever it did, the
// state must still decrypt the genuine next message afterwards.
func FuzzDecrypt(f *testing.F) {
	s := newSession(f)
	m0 := send(f, s.a, "m0")
	m1 := send(f, s.a, "m1")
	check := send(f, s.a, "check")
	deliver(f, s.b, m0)
	deliver(f, s.a, send(f, s.b, "b0"))
	nextEpoch := send(f, s.a, "next epoch")
	base := snapshot(f, s.b)

	f.Add(m1.header, m1.ciphertext)
	f.Add(nextEpoch.header, nextEpoch.ciphertext)
	f.Add(m0.header, m0.ciphertext)
	f.Add(nextEpoch.header, m1.ciphertext)
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0xa7, 0x01, 0x01}, make([]byte, 16))

	f.Fuzz(func(t *testing.T, header, ciphertext []byte) {
		b, err := Unmarshal(base)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Destroy()
		plaintext, err := b.Decrypt(header, ciphertext)
		if err == nil && string(plaintext) == check.text {
			return
		}
		deliver(t, b, check)
	})
}
