package protocol

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// rawFrame wraps raw body bytes in a current-version frame of type t without
// any validation, as a peer could put on the wire.
func rawFrame(t FrameType, body []byte) Frame {
	return Frame{Version: Version, Type: t, Body: body}
}

// encodeLoose encodes an arbitrary value with the package encoder, bypassing
// body validation, to craft hostile bodies.
func encodeLoose(t testing.TB, v any) []byte {
	t.Helper()
	b, err := encMode.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type looseError struct {
	Code    uint16 `cbor:"1,keyasint"`
	Message string `cbor:"2,keyasint"`
}

func TestDecodeBodyWrongType(t *testing.T) {
	f := mustFrame(t, TypePing, 0, Ping{Nonce: 1})

	if _, err := DecodeBody[Pong](f, TypePong); !errors.Is(err, ErrUnexpectedType) {
		t.Fatalf("frame type mismatch: got %v, want ErrUnexpectedType", err)
	}
	if _, err := DecodeBody[Pong](f, TypePing); !errors.Is(err, ErrUnexpectedType) {
		t.Fatalf("body type mismatch: got %v, want ErrUnexpectedType", err)
	}
	if _, err := DecodeBody[Ping](f, 0); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("undefined want: got %v, want ErrUnknownType", err)
	}
	f.Version = 2
	if _, err := DecodeBody[Ping](f, TypePing); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("unsupported version: got %v, want ErrUnsupportedVersion", err)
	}
}

func TestDecodeBodyRejects(t *testing.T) {
	tests := []struct {
		name   string
		decode func() error
		want   error
	}{
		{"NoBody", func() error { _, err := DecodeBody[Ping](rawFrame(TypePing, nil), TypePing); return err }, ErrMalformed},
		{"EmptyMap", func() error {
			_, err := DecodeBody[Ping](rawFrame(TypePing, mustHex(t, "a0")), TypePing)
			return err
		}, ErrMalformed},
		{"UnknownField", func() error {
			_, err := DecodeBody[Ping](rawFrame(TypePing, mustHex(t, "a2 01 01 02 01")), TypePing)
			return err
		}, ErrMalformed},
		{"DuplicateKey", func() error {
			_, err := DecodeBody[Ping](rawFrame(TypePing, mustHex(t, "a2 01 01 01 02")), TypePing)
			return err
		}, ErrMalformed},
		{"Indefinite", func() error {
			_, err := DecodeBody[Ping](rawFrame(TypePing, mustHex(t, "bf 01 01 ff")), TypePing)
			return err
		}, ErrMalformed},
		{"Trailing", func() error {
			_, err := DecodeBody[Ping](rawFrame(TypePing, mustHex(t, "a1 01 01 00")), TypePing)
			return err
		}, ErrMalformed},
		{"NonCanonical", func() error {
			_, err := DecodeBody[Ping](rawFrame(TypePing, mustHex(t, "a1 01 18 01")), TypePing)
			return err
		}, ErrMalformed},
		{"Null", func() error {
			_, err := DecodeBody[*Ping](rawFrame(TypePing, mustHex(t, "f6")), TypePing)
			return err
		}, ErrMalformed},
		{"HelloMissingField", func() error {
			_, err := DecodeBody[Hello](rawFrame(TypeHello, mustHex(t, "a1 01 01")), TypeHello)
			return err
		}, ErrMalformed},
		{"HelloInverted", func() error {
			_, err := DecodeBody[Hello](rawFrame(TypeHello, encodeLoose(t, Hello{MinVersion: 3, MaxVersion: 2})), TypeHello)
			return err
		}, ErrMalformed},
		{"HelloZero", func() error {
			_, err := DecodeBody[Hello](rawFrame(TypeHello, encodeLoose(t, Hello{})), TypeHello)
			return err
		}, ErrMalformed},
		{"WelcomeBadVersion", func() error {
			w := Welcome{Version: 2, MaxFrameSize: 1024, PingInterval: 30}
			_, err := DecodeBody[Welcome](rawFrame(TypeWelcome, encodeLoose(t, w)), TypeWelcome)
			return err
		}, ErrUnsupportedVersion},
		{"WelcomeFrameSizeTooLarge", func() error {
			w := Welcome{Version: 1, MaxFrameSize: MaxFrameSize + 1, PingInterval: 30}
			_, err := DecodeBody[Welcome](rawFrame(TypeWelcome, encodeLoose(t, w)), TypeWelcome)
			return err
		}, ErrMalformed},
		{"WelcomeZeroPing", func() error {
			w := Welcome{Version: 1, MaxFrameSize: 1024}
			_, err := DecodeBody[Welcome](rawFrame(TypeWelcome, encodeLoose(t, w)), TypeWelcome)
			return err
		}, ErrMalformed},
		{"ErrorMessageTooLong", func() error {
			e := looseError{Code: 1, Message: strings.Repeat("a", MaxErrorMessageLen+1)}
			_, err := DecodeBody[ErrorBody](rawFrame(TypeError, encodeLoose(t, e)), TypeError)
			return err
		}, ErrMalformed},
		{"ErrorMessageNonASCII", func() error {
			e := looseError{Code: 1, Message: "héllo"}
			_, err := DecodeBody[ErrorBody](rawFrame(TypeError, encodeLoose(t, e)), TypeError)
			return err
		}, ErrMalformed},
		{"ErrorMessageControl", func() error {
			e := looseError{Code: 1, Message: "line\nbreak"}
			_, err := DecodeBody[ErrorBody](rawFrame(TypeError, encodeLoose(t, e)), TypeError)
			return err
		}, ErrMalformed},
		{"ErrorMessageInvalidUTF8", func() error {
			_, err := DecodeBody[ErrorBody](rawFrame(TypeError, mustHex(t, "a2 01 01 02 61 ff")), TypeError)
			return err
		}, ErrMalformed},
		{"ErrorCodeZero", func() error {
			_, err := DecodeBody[ErrorBody](rawFrame(TypeError, encodeLoose(t, looseError{Code: 0})), TypeError)
			return err
		}, ErrMalformed},
		{"ErrorCodeUnknown", func() error {
			_, err := DecodeBody[ErrorBody](rawFrame(TypeError, encodeLoose(t, looseError{Code: 99})), TypeError)
			return err
		}, ErrMalformed},
		{"ErrorCodeOverflow", func() error {
			_, err := DecodeBody[ErrorBody](rawFrame(TypeError, mustHex(t, "a2 01 1a 00 01 00 01 02 60")), TypeError)
			return err
		}, ErrMalformed},
		{"BodyTooLarge", func() error {
			_, err := DecodeBody[Ping](rawFrame(TypePing, make([]byte, MaxFrameSize+1)), TypePing)
			return err
		}, ErrFrameTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.decode(); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewFrameRejects(t *testing.T) {
	tests := []struct {
		name  string
		build func() error
		want  error
	}{
		{"UnknownType", func() error { _, err := NewFrame(0, 0, Ping{}); return err }, ErrUnknownType},
		{"MismatchedBody", func() error { _, err := NewFrame(TypePong, 0, Ping{}); return err }, ErrUnexpectedType},
		{"NilPointer", func() error { _, err := NewFrame[*Ping](TypePing, 0, nil); return err }, ErrMalformed},
		{"InvalidHello", func() error { _, err := NewFrame(TypeHello, 0, Hello{MinVersion: 2, MaxVersion: 1}); return err }, ErrMalformed},
		{"InvalidError", func() error {
			_, err := NewFrame(TypeError, 0, ErrorBody{Code: ErrCodeInternal, Message: "tab\there"})
			return err
		}, ErrMalformed},
		{"TooLarge", func() error { _, err := NewFrame(TypePing, 0, make([]byte, MaxFrameSize)); return err }, ErrFrameTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.build(); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNegotiate(t *testing.T) {
	tests := []struct {
		hello   Hello
		want    uint8
		wantErr error
	}{
		{Hello{MinVersion: 1, MaxVersion: 1}, 1, nil},
		{Hello{MinVersion: 1, MaxVersion: 9}, 1, nil},
		{ClientHello(), Version, nil},
		{Hello{MinVersion: 2, MaxVersion: 3}, 0, ErrUnsupportedVersion},
		{Hello{MinVersion: 255, MaxVersion: 255}, 0, ErrUnsupportedVersion},
		{Hello{MinVersion: 0, MaxVersion: 1}, 0, ErrMalformed},
		{Hello{MinVersion: 2, MaxVersion: 1}, 0, ErrMalformed},
		{Hello{}, 0, ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%d-%d", tc.hello.MinVersion, tc.hello.MaxVersion), func(t *testing.T) {
			got, err := Negotiate(tc.hello)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Negotiate = %d, %v; want error %v", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("Negotiate = %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}

func TestErrorCodeFor(t *testing.T) {
	tests := []struct {
		err  error
		want ErrorCode
	}{
		{fmt.Errorf("wrapped: %w", ErrFrameTooLarge), ErrCodeTooLarge},
		{ErrUnsupportedVersion, ErrCodeUnsupportedVersion},
		{ErrMalformed, ErrCodeBadRequest},
		{ErrUnknownType, ErrCodeBadRequest},
		{ErrUnexpectedType, ErrCodeBadRequest},
		{errors.New("disk on fire"), ErrCodeInternal},
	}
	for _, tc := range tests {
		if got := ErrorCodeFor(tc.err); got != tc.want {
			t.Errorf("ErrorCodeFor(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
	_, err := Decode(mustHex(t, "a2 01 02 02 03"))
	if got := ErrorCodeFor(err); got != ErrCodeUnsupportedVersion {
		t.Errorf("ErrorCodeFor(Decode of v2 frame) = %v", got)
	}
}

func TestErrorCodeString(t *testing.T) {
	for c := ErrorCode(0); c <= 12; c++ {
		s := c.String()
		if c.Valid() == strings.HasPrefix(s, "ErrorCode(") {
			t.Errorf("ErrorCode(%d): String %q inconsistent with Valid %v", uint16(c), s, c.Valid())
		}
	}
}
