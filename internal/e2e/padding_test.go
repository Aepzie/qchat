package e2e

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/craguS/qchat/internal/padding"
)

func TestPaddedLimits(t *testing.T) {
	bucket, err := padding.BucketFor(MaxPlaintextSize)
	if err != nil || bucket != MaxPaddedPlaintextSize {
		t.Fatalf("BucketFor(MaxPlaintextSize) = %d, %v; MaxPaddedPlaintextSize = %d", bucket, err, MaxPaddedPlaintextSize)
	}
	if MaxEnvelopeSize >= 256<<10 {
		t.Fatalf("MaxEnvelopeSize %d does not fit the relay's default max_message_size", MaxEnvelopeSize)
	}
	maxBody, err := NewPlaintext(KindText, []byte(strings.Repeat("x", MaxBodySize)), testNow)
	if err != nil {
		t.Fatal(err)
	}
	padded, err := MarshalPaddedPlaintext(maxBody)
	if err != nil || len(padded) != MaxPaddedPlaintextSize {
		t.Fatalf("maximal padded plaintext %d bytes, %v", len(padded), err)
	}
	got, err := ParsePaddedPlaintext(padded)
	if err != nil || !bytes.Equal(got.Body, maxBody.Body) {
		t.Fatalf("maximal padded plaintext round trip: %v", err)
	}
}

func TestPaddedPlaintextHidesBodyLength(t *testing.T) {
	for _, kind := range []Kind{KindText, KindGroupControl, KindSenderKey, KindGroupText} {
		var sizes []int
		for _, n := range []int{1, 100, 400} {
			p, err := NewPlaintext(kind, bytes.Repeat([]byte{'a'}, n), testNow)
			if err != nil {
				t.Fatal(err)
			}
			b, err := MarshalPaddedPlaintext(p)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParsePaddedPlaintext(b)
			if err != nil || got.MsgID != p.MsgID || got.Kind != kind || !bytes.Equal(got.Body, p.Body) {
				t.Fatalf("kind %d, %d bytes: round trip %+v, %v", kind, n, got, err)
			}
			clear(b)
			if !bytes.Equal(got.Body, p.Body) {
				t.Fatal("parsed body aliases its input")
			}
			sizes = append(sizes, len(b))
		}
		if sizes[0] != padding.Buckets[0] || sizes[1] != sizes[0] || sizes[2] != sizes[0] {
			t.Fatalf("kind %d: padded sizes %v, want %d each", kind, sizes, padding.Buckets[0])
		}
	}
}

func TestParsePaddedPlaintextRejectsMalformed(t *testing.T) {
	p, err := NewPlaintext(KindText, []byte("hi"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := MarshalPlaintext(p)
	if err != nil {
		t.Fatal(err)
	}
	padded, err := MarshalPaddedPlaintext(p)
	if err != nil {
		t.Fatal(err)
	}
	modified := func(edit func([]byte) []byte) []byte {
		return edit(append([]byte(nil), padded...))
	}
	noMarker := make([]byte, padding.Buckets[0])
	copy(noMarker, plain)
	garbage, err := padding.Pad([]byte("not cbor"))
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"unpadded":       plain,
		"empty":          {},
		"no marker":      noMarker,
		"trailing byte":  modified(func(b []byte) []byte { b[len(b)-1] = 1; return b }),
		"truncated":      modified(func(b []byte) []byte { return b[:len(b)-1] }),
		"extended":       modified(func(b []byte) []byte { return append(b, 0) }),
		"too large":      make([]byte, 2*MaxPaddedPlaintextSize),
		"invalid inside": garbage,
	} {
		if _, err := ParsePaddedPlaintext(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: ParsePaddedPlaintext = %v, want ErrMalformed", name, err)
		}
	}
	if _, err := MarshalPaddedPlaintext(Plaintext{Kind: KindText}); !errors.Is(err, ErrInvalidMessage) {
		t.Errorf("MarshalPaddedPlaintext of empty body: %v", err)
	}
}

func TestOldEnvelopeVersionRejected(t *testing.T) {
	b, err := encMode.Marshal(envelopeWire{Version: Version - 1, Header: []byte("h"), Ciphertext: []byte("c")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvelope(b); !errors.Is(err, ErrMalformed) {
		t.Fatalf("version %d envelope: ParseEnvelope = %v, want ErrMalformed", Version-1, err)
	}
}
