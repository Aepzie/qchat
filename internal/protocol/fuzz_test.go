package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

func seedFrames(f *testing.F) {
	frames := []Frame{
		mustFrame(f, TypeHello, 1, ClientHello()),
		mustFrame(f, TypeWelcome, 1, Welcome{Version: Version, MaxFrameSize: MaxFrameSize, PingInterval: 30}),
		mustFrame(f, TypePing, 0, Ping{Nonce: 0x0102030405060708}),
		mustFrame(f, TypePong, 42, Pong{Nonce: 1}),
		mustFrame(f, TypeError, 7, ErrorBody{Code: ErrCodeRateLimited, Message: "slow down"}),
		{Version: Version, Type: TypePing},
	}
	for _, fr := range frames {
		f.Add(mustEncode(f, fr))
	}
	for _, s := range []string{
		"", "a0", "a2 01 02 02 03", "a3 01 01 02 03 02 03", "bf 01 01 02 03 ff",
		"a3 01 01 02 03 05 00", "a2 02 03 01 01", "a3 01 01 02 03 04 5a ff ff ff ff",
	} {
		f.Add(mustHex(f, s))
	}
}

// FuzzDecode checks that Decode never panics and that every frame it accepts
// re-encodes to exactly the same bytes (canonical form) and decodes again to
// an equal frame.
func FuzzDecode(f *testing.F) {
	seedFrames(f)
	f.Fuzz(func(t *testing.T, in []byte) {
		fr, err := Decode(in)
		if err != nil {
			return
		}
		out, err := Encode(fr)
		if err != nil {
			t.Fatalf("Decode accepted %x but Encode failed: %v", in, err)
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("non-canonical input accepted: in %x, re-encoded %x", in, out)
		}
		again, err := Decode(out)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !reflect.DeepEqual(again, fr) {
			t.Fatalf("re-decode mismatch: %+v vs %+v", again, fr)
		}
	})
}

// checkBodyRoundTrip decodes body as T and, on success, requires NewFrame to
// rebuild exactly the same body bytes.
func checkBodyRoundTrip[T any](t *testing.T, typ FrameType, body []byte) {
	v, err := DecodeBody[T](rawFrame(typ, body), typ)
	if err != nil {
		return
	}
	fr, err := NewFrame(typ, 0, v)
	if err != nil {
		t.Fatalf("DecodeBody[%T] accepted %x but NewFrame failed: %v", v, body, err)
	}
	if !bytes.Equal(fr.Body, body) {
		t.Fatalf("DecodeBody[%T] accepted non-canonical %x, re-encoded %x", v, body, fr.Body)
	}
	if _, err := Encode(fr); err != nil {
		t.Fatalf("Encode of rebuilt %v frame failed: %v", typ, err)
	}
}

// FuzzDecodeBody feeds arbitrary bytes to DecodeBody for every body type,
// including deliberately mismatched and pointer types. It must never panic,
// and accepted bodies must be canonical and valid.
func FuzzDecodeBody(f *testing.F) {
	bodies := []struct {
		typ  FrameType
		body any
	}{
		{TypeHello, ClientHello()},
		{TypeWelcome, Welcome{Version: Version, MaxFrameSize: 4096, PingInterval: 15}},
		{TypePing, Ping{Nonce: 7}},
		{TypePong, Pong{Nonce: 1<<64 - 1}},
		{TypeError, ErrorBody{Code: ErrCodeBadRequest, Message: "bad frame"}},
	}
	for _, b := range bodies {
		f.Add(uint8(b.typ), mustFrame(f, b.typ, 0, b.body).Body)
	}
	f.Add(uint8(TypePing), []byte{0xf6})
	f.Add(uint8(TypeError), mustHex(f, "a2 01 01 02 61 ff"))

	f.Fuzz(func(t *testing.T, sel uint8, body []byte) {
		switch sel % 6 {
		case 0:
			checkBodyRoundTrip[Hello](t, TypeHello, body)
		case 1:
			checkBodyRoundTrip[Welcome](t, TypeWelcome, body)
		case 2:
			checkBodyRoundTrip[Ping](t, TypePing, body)
			checkBodyRoundTrip[*Ping](t, TypePing, body)
		case 3:
			checkBodyRoundTrip[Pong](t, TypePong, body)
		case 4:
			checkBodyRoundTrip[ErrorBody](t, TypeError, body)
			checkBodyRoundTrip[*ErrorBody](t, TypeError, body)
		case 5:
			if _, err := DecodeBody[Pong](rawFrame(TypePing, body), TypePing); err == nil {
				t.Fatal("Pong body accepted for Ping frame")
			}
			_, _ = DecodeBody[any](rawFrame(FrameType(sel), body), FrameType(sel))
		}
	})
}
