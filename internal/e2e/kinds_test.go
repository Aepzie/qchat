package e2e

import (
	"bytes"
	"errors"
	"testing"
)

func TestExtensionKinds(t *testing.T) {
	binary := []byte{0xff, 0x00, 0xfe}
	for _, kind := range []Kind{KindFileOffer, KindFileChunk, KindTimer} {
		if !kind.IsExtension() || kind.IsText() {
			t.Fatalf("kind %d: IsExtension %v IsText %v", kind, kind.IsExtension(), kind.IsText())
		}
		p, err := NewPlaintext(kind, binary, testNow)
		if err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
		b, err := MarshalPlaintext(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParsePlaintext(b)
		if err != nil || got.Kind != kind || !bytes.Equal(got.Body, binary) {
			t.Fatalf("kind %d round trip: %+v, %v", kind, got, err)
		}
	}
	for _, kind := range []Kind{KindText, KindGroupControl, KindSenderKey, KindGroupText, 8} {
		if kind.IsExtension() {
			t.Errorf("kind %d reported as extension", kind)
		}
	}
	if _, err := NewPlaintext(lastKind+1, binary, testNow); !errors.Is(err, ErrInvalidMessage) {
		t.Errorf("kind above lastKind: %v", err)
	}
}
