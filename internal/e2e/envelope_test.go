package e2e

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

var testNow = time.UnixMilli(1750000000123)

func validEnvelope() Envelope {
	return Envelope{Init: []byte("init"), Header: []byte("header"), Ciphertext: []byte("ciphertext")}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	for _, e := range []Envelope{validEnvelope(), {Header: []byte{1}, Ciphertext: []byte{2}}} {
		b, err := MarshalEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseEnvelope(b)
		if err != nil {
			t.Fatalf("ParseEnvelope: %v", err)
		}
		if !bytes.Equal(got.Init, e.Init) || (got.Init == nil) != (e.Init == nil) ||
			!bytes.Equal(got.Header, e.Header) || !bytes.Equal(got.Ciphertext, e.Ciphertext) {
			t.Fatalf("round trip %+v, want %+v", got, e)
		}
		b[len(b)-1] ^= 0xff
		if again, err := ParseEnvelope(b); err == nil && bytes.Equal(again.Ciphertext, e.Ciphertext) {
			t.Fatal("parsed envelope aliases its input")
		}
	}
}

func TestMarshalEnvelopeRejectsInvalid(t *testing.T) {
	big := func(n int) []byte { return make([]byte, n) }
	for name, e := range map[string]Envelope{
		"empty init":       {Init: []byte{}, Header: []byte{1}, Ciphertext: []byte{1}},
		"init too large":   {Init: big(MaxInitSize + 1), Header: []byte{1}, Ciphertext: []byte{1}},
		"no header":        {Ciphertext: []byte{1}},
		"header too large": {Header: big(MaxHeaderSize + 1), Ciphertext: []byte{1}},
		"no ciphertext":    {Header: []byte{1}},
		"ciphertext large": {Header: []byte{1}, Ciphertext: big(MaxCiphertextSize + 1)},
	} {
		if _, err := MarshalEnvelope(e); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: MarshalEnvelope = %v, want ErrInvalidMessage", name, err)
		}
	}
	max := Envelope{Init: big(MaxInitSize), Header: big(MaxHeaderSize), Ciphertext: big(MaxCiphertextSize)}
	b, err := MarshalEnvelope(max)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxEnvelopeSize {
		t.Fatalf("maximal envelope is %d bytes, limit %d", len(b), MaxEnvelopeSize)
	}
	if _, err := ParseEnvelope(b); err != nil {
		t.Fatalf("maximal envelope rejected: %v", err)
	}
}

func TestParseEnvelopeRejectsMalformed(t *testing.T) {
	type wire map[int]any
	encode := func(v any) []byte {
		b, err := encMode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	valid := encode(wire{1: Version, 2: []byte("i"), 3: []byte("h"), 4: []byte("c")})
	if _, err := ParseEnvelope(valid); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	cases := map[string][]byte{
		"empty":            nil,
		"not a map":        {0x80},
		"version 1":        encode(wire{1: 1, 3: []byte("h"), 4: []byte("c")}),
		"version 2":        encode(wire{1: 2, 3: []byte("h"), 4: []byte("c")}),
		"missing header":   encode(wire{1: Version, 4: []byte("c")}),
		"missing cipher":   encode(wire{1: Version, 3: []byte("h")}),
		"empty header":     encode(wire{1: Version, 3: []byte{}, 4: []byte("c")}),
		"empty init":       encode(wire{1: Version, 2: []byte{}, 3: []byte("h"), 4: []byte("c")}),
		"null init":        encode(wire{1: Version, 2: nil, 3: []byte("h"), 4: []byte("c")}),
		"unknown field":    encode(wire{1: Version, 3: []byte("h"), 4: []byte("c"), 5: 1}),
		"text header":      encode(wire{1: Version, 3: "h", 4: []byte("c")}),
		"wide version":     append([]byte{0xa3, 0x01, 0x18, 0x02}, valid[len(valid)-6:]...),
		"duplicate key":    {0xa3, 0x01, 0x02, 0x03, 0x41, 'h', 0x03, 0x41, 'h'},
		"trailing data":    append(append([]byte(nil), valid...), 0x00),
		"too large":        make([]byte, MaxEnvelopeSize+1),
		"indefinite bytes": {0xa3, 0x01, 0x02, 0x03, 0x5f, 0x41, 'h', 0xff, 0x04, 0x41, 'c'},
	}
	for name, b := range cases {
		if _, err := ParseEnvelope(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: ParseEnvelope = %v, want ErrMalformed", name, err)
		}
	}
}

func TestPlaintextRoundTrip(t *testing.T) {
	p, err := NewPlaintext(KindText, []byte("héllo"), testNow.Add(456*time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewPlaintext(KindText, []byte("héllo"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if p.MsgID == q.MsgID || p.MsgID == [MsgIDSize]byte{} {
		t.Fatal("message IDs are not random")
	}
	if !p.Sent.Equal(testNow) {
		t.Fatalf("Sent = %v, want millisecond precision %v", p.Sent, testNow)
	}
	b, err := MarshalPlaintext(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePlaintext(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.MsgID != p.MsgID || !got.Sent.Equal(p.Sent) || got.Kind != KindText || string(got.Body) != "héllo" {
		t.Fatalf("round trip %+v", got)
	}
	clear(b)
	if string(got.Body) != "héllo" {
		t.Fatal("parsed body aliases its input")
	}

	maxBody, err := NewPlaintext(KindText, []byte(strings.Repeat("x", MaxBodySize)), testNow)
	if err != nil {
		t.Fatal(err)
	}
	b, err = MarshalPlaintext(maxBody)
	if err != nil || len(b) > MaxPlaintextSize {
		t.Fatalf("maximal plaintext %d bytes, %v", len(b), err)
	}
}

func TestPlaintextRejectsInvalid(t *testing.T) {
	for name, body := range map[string][]byte{
		"empty":    nil,
		"too long": []byte(strings.Repeat("x", MaxBodySize+1)),
		"bad utf8": {0xff, 0xfe},
	} {
		if _, err := NewPlaintext(KindText, body, testNow); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: NewPlaintext = %v", name, err)
		}
	}
	if _, err := NewPlaintext(Kind(5), []byte("x"), testNow); !errors.Is(err, ErrInvalidMessage) {
		t.Errorf("unknown kind: %v", err)
	}
	if _, err := MarshalPlaintext(Plaintext{Kind: KindText}); !errors.Is(err, ErrInvalidMessage) {
		t.Errorf("MarshalPlaintext of empty body: %v", err)
	}

	type wire map[int]any
	encode := func(v any) []byte {
		b, err := encMode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	id := bytes.Repeat([]byte{7}, MsgIDSize)
	if _, err := ParsePlaintext(encode(wire{1: id, 2: int64(5), 3: 1, 4: []byte("x")})); err != nil {
		t.Fatalf("valid plaintext rejected: %v", err)
	}
	for name, b := range map[string][]byte{
		"short ID":      encode(wire{1: id[:15], 2: 5, 3: 1, 4: []byte("x")}),
		"unknown kind":  encode(wire{1: id, 2: 5, 3: 5, 4: []byte("x")}),
		"zero kind":     encode(wire{1: id, 2: 5, 3: 0, 4: []byte("x")}),
		"group utf8":    encode(wire{1: id, 2: 5, 3: 4, 4: []byte{0xff}}),
		"empty body":    encode(wire{1: id, 2: 5, 3: 1, 4: []byte{}}),
		"bad utf8":      encode(wire{1: id, 2: 5, 3: 1, 4: []byte{0xff}}),
		"missing sent":  encode(wire{1: id, 3: 1, 4: []byte("x")}),
		"missing ID":    encode(wire{2: 5, 3: 1, 4: []byte("x")}),
		"unknown field": encode(wire{1: id, 2: 5, 3: 1, 4: []byte("x"), 5: 0}),
		"too large":     make([]byte, MaxPlaintextSize+1),
	} {
		if _, err := ParsePlaintext(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: ParsePlaintext = %v, want ErrMalformed", name, err)
		}
	}
}

func TestPlaintextKinds(t *testing.T) {
	binary := []byte{0xff, 0x00, 0xfe}
	for _, kind := range []Kind{KindGroupControl, KindSenderKey} {
		p, err := NewPlaintext(kind, binary, testNow)
		if err != nil {
			t.Fatalf("kind %d with binary body: %v", kind, err)
		}
		b, err := MarshalPlaintext(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParsePlaintext(b)
		if err != nil || got.Kind != kind || !bytes.Equal(got.Body, binary) {
			t.Fatalf("kind %d round trip: %+v, %v", kind, got, err)
		}
		if kind.IsText() {
			t.Errorf("kind %d reported as text", kind)
		}
	}
	if _, err := NewPlaintext(KindGroupText, binary, testNow); !errors.Is(err, ErrInvalidMessage) {
		t.Errorf("group text with invalid UTF-8: %v", err)
	}
	if p, err := NewPlaintext(KindGroupText, []byte("hi"), testNow); err != nil || !p.Kind.IsText() {
		t.Errorf("group text: %v", err)
	}
	if _, err := NewPlaintext(KindSenderKey, nil, testNow); !errors.Is(err, ErrInvalidMessage) {
		t.Errorf("empty distribution body: %v", err)
	}
}

func TestAccessKeyKind(t *testing.T) {
	key := bytes.Repeat([]byte{0xa5}, 16)
	p, err := NewPlaintext(KindAccessKey, key, testNow)
	if err != nil {
		t.Fatal(err)
	}
	padded, err := MarshalPaddedPlaintext(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePaddedPlaintext(padded)
	if err != nil || got.Kind != KindAccessKey || !bytes.Equal(got.Body, key) || got.Kind.IsText() {
		t.Fatalf("access key round trip: %+v, %v", got, err)
	}
	for _, reserved := range []Kind{0, 5, 6, 7, 9, 255} {
		if _, err := NewPlaintext(reserved, key, testNow); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("NewPlaintext(kind %d) = %v, want ErrInvalidMessage", reserved, err)
		}
		b, err := encMode.Marshal(plaintextWire{MsgID: p.MsgID[:], Sent: p.Sent.UnixMilli(), Kind: uint8(reserved), Body: key})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParsePlaintext(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParsePlaintext(kind %d) = %v, want ErrMalformed", reserved, err)
		}
	}
}

func TestClockSkewed(t *testing.T) {
	for _, c := range []struct {
		offset time.Duration
		want   bool
	}{
		{0, false},
		{ClockSkewTolerance, false},
		{-ClockSkewTolerance, false},
		{ClockSkewTolerance + time.Millisecond, true},
		{-ClockSkewTolerance - time.Millisecond, true},
	} {
		if got := ClockSkewed(testNow.Add(c.offset), testNow); got != c.want {
			t.Errorf("ClockSkewed(now%+v) = %v", c.offset, got)
		}
	}
}
