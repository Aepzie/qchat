package filexfer

import (
	"bytes"
	"testing"
)

func FuzzParseOffer(f *testing.F) {
	o, err := NewOffer("seed.txt", 3*ChunkSize, "text/plain")
	if err != nil {
		f.Fatal(err)
	}
	seed, err := MarshalOffer(o)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := ParseOffer(b)
		if err != nil {
			return
		}
		again, err := MarshalOffer(got)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted offer does not re-encode to its input: %v", err)
		}
	})
}

func FuzzParseChunk(f *testing.F) {
	seed, err := MarshalChunk(Chunk{Index: 1, Total: 3, Sealed: make([]byte, 64)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := ParseChunk(b)
		if err != nil {
			return
		}
		again, err := MarshalChunk(got)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted chunk does not re-encode to its input: %v", err)
		}
	})
}
