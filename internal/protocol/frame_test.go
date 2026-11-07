package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func mustFrame[T any](t testing.TB, typ FrameType, id uint64, body T) Frame {
	t.Helper()
	f, err := NewFrame(typ, id, body)
	if err != nil {
		t.Fatalf("NewFrame(%v, %d, %+v): %v", typ, id, body, err)
	}
	return f
}

func mustEncode(t testing.TB, f Frame) []byte {
	t.Helper()
	b, err := Encode(f)
	if err != nil {
		t.Fatalf("Encode(%+v): %v", f, err)
	}
	return b
}

// roundTrip encodes body into a frame, decodes it back and checks equality.
func roundTrip[T any](t *testing.T, typ FrameType, id uint64, body T) {
	t.Helper()
	wire := mustEncode(t, mustFrame(t, typ, id, body))
	f, err := Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.Version != Version || f.Type != typ || f.ID != id {
		t.Fatalf("header mismatch: got %+v", f)
	}
	got, err := DecodeBody[T](f, typ)
	if err != nil {
		t.Fatalf("DecodeBody: %v", err)
	}
	if !reflect.DeepEqual(got, body) {
		t.Fatalf("body mismatch: got %+v, want %+v", got, body)
	}
}

func TestRoundTrip(t *testing.T) {
	t.Run("Hello", func(t *testing.T) { roundTrip(t, TypeHello, 1, ClientHello()) })
	t.Run("HelloRange", func(t *testing.T) { roundTrip(t, TypeHello, 0, Hello{MinVersion: 1, MaxVersion: 255}) })
	t.Run("Welcome", func(t *testing.T) {
		roundTrip(t, TypeWelcome, 1, Welcome{Version: Version, MaxFrameSize: MaxFrameSize, PingInterval: 30})
	})
	t.Run("Ping", func(t *testing.T) { roundTrip(t, TypePing, 0, Ping{Nonce: 1<<64 - 1}) })
	t.Run("PingZero", func(t *testing.T) { roundTrip(t, TypePing, 0, Ping{}) })
	t.Run("Pong", func(t *testing.T) { roundTrip(t, TypePong, 1<<64-1, Pong{Nonce: 12345}) })
	t.Run("Error", func(t *testing.T) {
		roundTrip(t, TypeError, 7, ErrorBody{Code: ErrCodeRateLimited, Message: "slow down"})
	})
	t.Run("ErrorEmptyMessage", func(t *testing.T) { roundTrip(t, TypeError, 0, ErrorBody{Code: ErrCodeInternal}) })
	t.Run("ErrorMaxMessage", func(t *testing.T) {
		roundTrip(t, TypeError, 0, ErrorBody{Code: ErrCodeBadRequest, Message: strings.Repeat("~", MaxErrorMessageLen)})
	})
	t.Run("PointerBody", func(t *testing.T) { roundTrip(t, TypePing, 0, &Ping{Nonce: 9}) })
}

func TestRoundTripFrameWithoutBody(t *testing.T) {
	f := Frame{Version: Version, Type: TypePing, ID: 3}
	got, err := Decode(mustEncode(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, f) {
		t.Fatalf("got %+v, want %+v", got, f)
	}
}

// TestGolden pins the wire format. Any change to these encodings is a wire
// protocol change and requires a new Version.
func TestGolden(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
		hex   string
	}{
		{
			name:  "Ping",
			frame: mustFrame(t, TypePing, 0, Ping{Nonce: 0x0102030405060708}),
			hex:   "a3 01 01 02 03 04 4b a1 01 1b 01 02 03 04 05 06 07 08",
		},
		{
			name:  "PingWithID",
			frame: mustFrame(t, TypePing, 42, Ping{Nonce: 1}),
			hex:   "a4 01 01 02 03 03 18 2a 04 43 a1 01 01",
		},
		{
			name:  "Hello",
			frame: mustFrame(t, TypeHello, 0, ClientHello()),
			hex:   "a3 01 01 02 01 04 45 a2 01 01 02 01",
		},
		{
			name:  "Welcome",
			frame: mustFrame(t, TypeWelcome, 0, Welcome{Version: 1, MaxFrameSize: MaxFrameSize, PingInterval: 30}),
			hex:   "a3 01 01 02 02 04 4c a3 01 01 02 1a 00 10 00 00 03 18 1e",
		},
		{
			name:  "Error",
			frame: mustFrame(t, TypeError, 0, ErrorBody{Code: ErrCodeRateLimited, Message: "slow down"}),
			hex:   "a3 01 01 02 05 04 4e a2 01 03 02 69 73 6c 6f 77 20 64 6f 77 6e",
		},
		{
			name:  "NoBody",
			frame: Frame{Version: Version, Type: TypePong},
			hex:   "a2 01 01 02 04",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := mustHex(t, tc.hex)
			got := mustEncode(t, tc.frame)
			if !bytes.Equal(got, want) {
				t.Fatalf("Encode = %x, want %x", got, want)
			}
			f, err := Decode(want)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !reflect.DeepEqual(f, tc.frame) {
				t.Fatalf("Decode = %+v, want %+v", f, tc.frame)
			}
		})
	}
}

func TestDecodeRejects(t *testing.T) {
	tests := []struct {
		name string
		hex  string
		want error
	}{
		{"Empty", "", ErrMalformed},
		{"NotAMap", "01", ErrMalformed},
		{"Truncated", "a3 01 01 02 03 04 4b a1 01", ErrMalformed},
		{"VersionZero", "a2 01 00 02 03", ErrUnsupportedVersion},
		{"VersionMissing", "a1 02 03", ErrUnsupportedVersion},
		{"VersionTwo", "a2 01 02 02 03", ErrUnsupportedVersion},
		{"VersionHuge", "a2 01 19 01 00 02 03", ErrUnsupportedVersion},
		{"VersionTwoWithFutureFields", "a3 01 02 02 03 09 00", ErrUnsupportedVersion},
		{"VersionNegative", "a2 01 20 02 03", ErrMalformed},
		{"VersionAsText", "a2 01 61 31 02 03", ErrMalformed},
		{"TypeZero", "a2 01 01 02 00", ErrUnknownType},
		{"TypeMissing", "a1 01 01", ErrUnknownType},
		{"TypeUnknown", "a2 01 01 02 17", ErrUnknownType},
		{"TypeOverflow", "a2 01 01 02 19 01 03", ErrMalformed},
		{"TrailingByte", "a2 01 01 02 03 00", ErrMalformed},
		{"TrailingFrame", "a2 01 01 02 03 a2 01 01 02 03", ErrMalformed},
		{"DuplicateKey", "a3 01 01 02 03 02 03", ErrMalformed},
		{"DuplicateVersion", "a3 01 01 01 01 02 03", ErrMalformed},
		{"IndefiniteMap", "bf 01 01 02 03 ff", ErrMalformed},
		{"IndefiniteBody", "a3 01 01 02 03 04 5f 43 a1 01 01 ff", ErrMalformed},
		{"UnknownField", "a3 01 01 02 03 05 00", ErrMalformed},
		{"UnknownTextField", "a3 01 01 02 03 61 78 00", ErrMalformed},
		{"Tagged", "c1 a2 01 01 02 03", ErrMalformed},
		{"TaggedField", "a2 01 01 02 c1 03", ErrMalformed},
		{"KeysUnsorted", "a2 02 03 01 01", ErrMalformed},
		{"NonShortestInt", "a2 01 18 01 02 03", ErrMalformed},
		{"NonShortestMapLen", "b8 02 01 01 02 03", ErrMalformed},
		{"ExplicitZeroID", "a3 01 01 02 03 03 00", ErrMalformed},
		{"ExplicitEmptyBody", "a3 01 01 02 03 04 40", ErrMalformed},
		{"BodyAsText", "a3 01 01 02 03 04 61 41", ErrMalformed},
		{"BodyAsArray", "a3 01 01 02 03 04 81 01", ErrMalformed},
		{"DeepNesting", "a3 01 01 02 03 05 81 81 81 81 81 81 81 81 81 81 00", ErrMalformed},
		{"HugeDeclaredLength", "a3 01 01 02 03 04 5a ff ff ff ff", ErrMalformed},
		{"HugeDeclaredMap", "ba ff ff ff ff 01 01", ErrMalformed},
		{"FloatVersion", "a2 01 f9 3c 00 02 03", ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Decode(mustHex(t, tc.hex))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Decode = %+v, %v; want error %v", f, err, tc.want)
			}
			if !reflect.DeepEqual(f, Frame{}) {
				t.Fatalf("Decode returned non-zero frame %+v alongside error", f)
			}
		})
	}
}

func TestDecodeRejectsOversizedBeforeParsing(t *testing.T) {
	valid := mustEncode(t, mustFrame(t, TypePing, 0, Ping{Nonce: 1}))
	for _, size := range []int{MaxFrameSize + 1, 4 * MaxFrameSize} {
		// A well-formed frame followed by padding, and pure garbage: both must
		// fail with ErrFrameTooLarge, proving the size check precedes parsing.
		padded := append(append([]byte{}, valid...), make([]byte, size-len(valid))...)
		garbage := bytes.Repeat([]byte{0xff}, size)
		for name, in := range map[string][]byte{"padded": padded, "garbage": garbage} {
			if _, err := Decode(in); !errors.Is(err, ErrFrameTooLarge) {
				t.Fatalf("%s, %d bytes: got %v, want ErrFrameTooLarge", name, size, err)
			}
			allocs := testing.AllocsPerRun(10, func() { _, _ = Decode(in) })
			if allocs > 4 {
				t.Fatalf("%s: oversized input caused %v allocations", name, allocs)
			}
		}
	}
}

func TestDecodeAcceptsMaxFrameSize(t *testing.T) {
	// Body length L is encoded with a 5-byte header (0x5a + uint32) and the
	// frame overhead around it is 1+2+2+1 bytes, totalling 11 bytes.
	bodyLen := MaxFrameSize - 11
	f := Frame{Version: Version, Type: TypePing, Body: bytes.Repeat([]byte{0xab}, bodyLen)}
	wire := mustEncode(t, f)
	if len(wire) != MaxFrameSize {
		t.Fatalf("encoded size %d, want %d", len(wire), MaxFrameSize)
	}
	got, err := Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(got.Body, f.Body) {
		t.Fatal("body mismatch")
	}

	f.Body = append(f.Body, 0xab)
	if _, err := Encode(f); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("Encode of MaxFrameSize+1 frame: got %v, want ErrFrameTooLarge", err)
	}
}

func TestEncodeRejects(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
		want  error
	}{
		{"VersionZero", Frame{Type: TypePing}, ErrUnsupportedVersion},
		{"VersionTwo", Frame{Version: 2, Type: TypePing}, ErrUnsupportedVersion},
		{"TypeZero", Frame{Version: Version}, ErrUnknownType},
		{"TypeUnknown", Frame{Version: Version, Type: 23}, ErrUnknownType},
		{"BodyTooLarge", Frame{Version: Version, Type: TypePing, Body: make([]byte, MaxFrameSize+1)}, ErrFrameTooLarge},
		{"FrameTooLarge", Frame{Version: Version, Type: TypePing, Body: make([]byte, MaxFrameSize)}, ErrFrameTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if b, err := Encode(tc.frame); !errors.Is(err, tc.want) {
				t.Fatalf("Encode = %x, %v; want error %v", b, err, tc.want)
			}
		})
	}
}

func TestFrameTypeString(t *testing.T) {
	want := map[FrameType]string{
		TypeHello: "Hello", TypeWelcome: "Welcome", TypePing: "Ping",
		TypePong: "Pong", TypeError: "Error", TypeRegister: "Register", TypeRegistered: "Registered",
		TypeAuthBegin: "AuthBegin", TypeAuthChallenge: "AuthChallenge", TypeAuthProof: "AuthProof",
		TypeAuthOK: "AuthOK", TypeKeyRequest: "KeyRequest", TypeKeyResponse: "KeyResponse",
		TypeSend: "Send", TypeSendResult: "SendResult", TypeDeliver: "Deliver",
		TypePrekeyUpload: "PrekeyUpload", TypePrekeyStatus: "PrekeyStatus", TypePrekeyRequest: "PrekeyRequest",
		TypePrekeyResponse: "PrekeyResponse", TypeAck: "Ack", TypeSendMulti: "SendMulti",
		0: "FrameType(0)", 23: "FrameType(23)", 200: "FrameType(200)",
	}
	for typ, s := range want {
		if got := typ.String(); got != s {
			t.Errorf("FrameType(%d).String() = %q, want %q", uint8(typ), got, s)
		}
	}
	for typ := 0; typ < 256; typ++ {
		valid := typ >= 1 && typ <= 22
		if got := FrameType(typ).Valid(); got != valid {
			t.Errorf("FrameType(%d).Valid() = %v, want %v", typ, got, valid)
		}
	}
}
