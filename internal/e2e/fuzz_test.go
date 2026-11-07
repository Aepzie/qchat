package e2e

import (
	"bytes"
	"testing"
)

// FuzzParseEnvelope checks that every accepted envelope is canonical (it
// re-encodes to exactly the input) and within the limits.
func FuzzParseEnvelope(f *testing.F) {
	for _, e := range []Envelope{validEnvelope(), {Header: []byte{1}, Ciphertext: []byte{2}}} {
		b, err := MarshalEnvelope(e)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{0xa4})
	f.Fuzz(func(t *testing.T, input []byte) {
		e, err := ParseEnvelope(input)
		if err != nil {
			return
		}
		again, err := MarshalEnvelope(e)
		if err != nil {
			t.Fatalf("accepted envelope does not marshal: %v", err)
		}
		if !bytes.Equal(again, input) {
			t.Fatal("accepted a non-canonical envelope")
		}
	})
}

// FuzzParsePlaintext checks the same for plaintexts.
func FuzzParsePlaintext(f *testing.F) {
	p, err := NewPlaintext(KindText, []byte("seed"), testNow)
	if err != nil {
		f.Fatal(err)
	}
	b, err := MarshalPlaintext(p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte{0xa4})
	f.Fuzz(func(t *testing.T, input []byte) {
		p, err := ParsePlaintext(input)
		if err != nil {
			return
		}
		again, err := MarshalPlaintext(p)
		if err != nil {
			t.Fatalf("accepted plaintext does not marshal: %v", err)
		}
		if !bytes.Equal(again, input) {
			t.Fatal("accepted a non-canonical plaintext")
		}
	})
}
