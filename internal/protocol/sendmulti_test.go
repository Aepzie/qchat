package protocol

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// recipients returns n distinct IDs.
func recipients(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		id := filled(IDSize, byte(i))
		id[IDSize-1] = byte(i >> 8)
		out[i] = id
	}
	return out
}

func TestSendMultiRoundTrip(t *testing.T) {
	t.Run("One", func(t *testing.T) {
		roundTrip(t, TypeSendMulti, 1, SendMulti{To: recipients(1), Payload: []byte("group")})
	})
	t.Run("Several", func(t *testing.T) {
		roundTrip(t, TypeSendMulti, 2, SendMulti{To: recipients(3), Payload: []byte{1, 2, 3}})
	})
	t.Run("Pointer", func(t *testing.T) {
		roundTrip(t, TypeSendMulti, 3, &SendMulti{To: recipients(2), Payload: []byte{9}})
	})
	t.Run("MaxRecipients", func(t *testing.T) {
		roundTrip(t, TypeSendMulti, 4, SendMulti{To: recipients(MaxMultiRecipients), Payload: []byte{9}})
	})
}

// TestSendMultiMaxFits proves that a SendMulti with the most recipients, the
// largest payload and the largest frame ID still fits within MaxFrameSize,
// and that every copy fits in a Deliver.
func TestSendMultiMaxFits(t *testing.T) {
	payload := bytes.Repeat([]byte{0xcd}, MaxMultiPayloadSize)
	body := SendMulti{To: recipients(MaxMultiRecipients), Payload: payload}
	roundTrip(t, TypeSendMulti, 1<<64-1, body)
	wire := mustEncode(t, mustFrame(t, TypeSendMulti, 1<<64-1, body))
	if len(wire) > MaxFrameSize {
		t.Fatalf("maximal SendMulti frame is %d bytes, limit %d", len(wire), MaxFrameSize)
	}
	if MaxMultiPayloadSize > MaxPayloadSize {
		t.Fatalf("MaxMultiPayloadSize %d exceeds MaxPayloadSize %d", MaxMultiPayloadSize, MaxPayloadSize)
	}
	roundTrip(t, TypeDeliver, 1<<64-1, Deliver{From: recipients(1)[0], Payload: payload, QueueID: 1<<64 - 1})
}

// TestSendMultiGolden pins the wire format of SendMulti.
func TestSendMultiGolden(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
		hex   string
	}{
		{
			name:  "OneRecipient",
			frame: mustFrame(t, TypeSendMulti, 1, SendMulti{To: [][]byte{filled(IDSize, 0)}, Payload: []byte{0xaa}}),
			hex: "a4 01 01 02 16 03 01 04 58 28 a2 01 81 58 20" +
				" 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" +
				" 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f" +
				" 02 41 aa",
		},
		{
			name: "TwoRecipients",
			frame: mustFrame(t, TypeSendMulti, 0, SendMulti{
				To:      [][]byte{filled(IDSize, 0), filled(IDSize, 0x20)},
				Payload: []byte{0x01, 0x02},
			}),
			hex: "a3 01 01 02 16 04 58 4b a2 01 82 58 20" +
				" 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" +
				" 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f" +
				" 58 20" +
				" 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f" +
				" 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f" +
				" 02 42 01 02",
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
			body, err := DecodeBody[SendMulti](f, TypeSendMulti)
			if err != nil {
				t.Fatalf("DecodeBody: %v", err)
			}
			if !bytes.Equal(body.To[0], filled(IDSize, 0)) {
				t.Fatalf("first recipient %x", body.To[0])
			}
		})
	}
}

func TestSendMultiDecodeRejects(t *testing.T) {
	id := filled(IDSize, 1)
	tests := []struct {
		name string
		err  error
	}{
		{"NoRecipients", decodeErr[SendMulti](TypeSendMulti, encodeLoose(t, SendMulti{To: [][]byte{}, Payload: []byte{1}}))},
		{"NullRecipients", decodeErr[SendMulti](TypeSendMulti, mustHex(t, "a2 01 f6 02 41 01"))},
		{"MissingRecipients", decodeErr[SendMulti](TypeSendMulti, mustHex(t, "a1 02 41 01"))},
		{"MissingPayload", decodeErr[SendMulti](TypeSendMulti, mustHex(t, "a1 01 81 58 20"+strings.Repeat("01", IDSize)))},
		{"TooManyRecipients", decodeErr[SendMulti](TypeSendMulti,
			encodeLoose(t, SendMulti{To: recipients(MaxMultiRecipients + 1), Payload: []byte{1}}))},
		{"AboveDecoderLimit", decodeErr[SendMulti](TypeSendMulti,
			encodeLoose(t, SendMulti{To: recipients(maxArrayElements + 1), Payload: []byte{1}}))},
		{"Duplicate", decodeErr[SendMulti](TypeSendMulti, encodeLoose(t, SendMulti{To: [][]byte{id, id}, Payload: []byte{1}}))},
		{"DuplicateLater", decodeErr[SendMulti](TypeSendMulti,
			encodeLoose(t, SendMulti{To: append(recipients(5), recipients(5)[3]), Payload: []byte{1}}))},
		{"ShortRecipient", decodeErr[SendMulti](TypeSendMulti,
			encodeLoose(t, SendMulti{To: [][]byte{id, filled(IDSize-1, 2)}, Payload: []byte{1}}))},
		{"LongRecipient", decodeErr[SendMulti](TypeSendMulti,
			encodeLoose(t, SendMulti{To: [][]byte{filled(IDSize+1, 2)}, Payload: []byte{1}}))},
		{"EmptyRecipient", decodeErr[SendMulti](TypeSendMulti, mustHex(t, "a2 01 81 40 02 41 01"))},
		{"RecipientAsText", decodeErr[SendMulti](TypeSendMulti, mustHex(t, "a2 01 81 61 41 02 41 01"))},
		{"RecipientsNotArray", decodeErr[SendMulti](TypeSendMulti, mustHex(t, "a2 01 58 20"+strings.Repeat("01", IDSize)+" 02 41 01"))},
		{"NestedRecipient", decodeErr[SendMulti](TypeSendMulti, mustHex(t, "a2 01 81 81 58 20"+strings.Repeat("01", IDSize)+" 02 41 01"))},
		{"IndefiniteRecipients", decodeErr[SendMulti](TypeSendMulti, mustHex(t, "a2 01 9f 58 20"+strings.Repeat("01", IDSize)+" ff 02 41 01"))},
		{"NonCanonicalLength", decodeErr[SendMulti](TypeSendMulti, mustHex(t, "a2 01 98 01 58 20"+strings.Repeat("01", IDSize)+" 02 41 01"))},
		{"KeysUnsorted", decodeErr[SendMulti](TypeSendMulti, mustHex(t, "a2 02 41 01 01 81 58 20"+strings.Repeat("01", IDSize)))},
		{"UnknownField", decodeErr[SendMulti](TypeSendMulti, mustHex(t, "a3 01 81 58 20"+strings.Repeat("01", IDSize)+" 02 41 01 03 00"))},
		{"EmptyPayload", decodeErr[SendMulti](TypeSendMulti, encodeLoose(t, SendMulti{To: [][]byte{id}, Payload: []byte{}}))},
		{"PayloadTooLarge", decodeErr[SendMulti](TypeSendMulti,
			encodeLoose(t, SendMulti{To: [][]byte{id}, Payload: make([]byte, MaxMultiPayloadSize+1)}))},
		{"NoBody", decodeErr[SendMulti](TypeSendMulti, nil)},
		{"SendBody", decodeErr[SendMulti](TypeSendMulti, encodeLoose(t, Send{To: id, Payload: []byte{1}}))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, ErrMalformed) {
				t.Fatalf("got %v, want ErrMalformed", tc.err)
			}
		})
	}
}

func TestSendMultiNewFrameRejects(t *testing.T) {
	id := filled(IDSize, 1)
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"NoRecipients", buildErr(TypeSendMulti, SendMulti{Payload: []byte{1}}), ErrMalformed},
		{"TooManyRecipients", buildErr(TypeSendMulti, SendMulti{To: recipients(MaxMultiRecipients + 1), Payload: []byte{1}}), ErrMalformed},
		{"Duplicate", buildErr(TypeSendMulti, SendMulti{To: [][]byte{id, id}, Payload: []byte{1}}), ErrMalformed},
		{"ShortRecipient", buildErr(TypeSendMulti, SendMulti{To: [][]byte{id[:IDSize-1]}, Payload: []byte{1}}), ErrMalformed},
		{"NilRecipient", buildErr(TypeSendMulti, SendMulti{To: [][]byte{nil}, Payload: []byte{1}}), ErrMalformed},
		{"NoPayload", buildErr(TypeSendMulti, SendMulti{To: [][]byte{id}}), ErrMalformed},
		{"PayloadTooLarge", buildErr(TypeSendMulti, SendMulti{To: [][]byte{id}, Payload: make([]byte, MaxMultiPayloadSize+1)}), ErrMalformed},
		{"NilPointer", buildErr[*SendMulti](TypeSendMulti, nil), ErrMalformed},
		{"AsSend", buildErr(TypeSend, SendMulti{To: [][]byte{id}, Payload: []byte{1}}), ErrUnexpectedType},
		{"SendAsSendMulti", buildErr(TypeSendMulti, Send{To: id, Payload: []byte{1}}), ErrUnexpectedType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, tc.want) {
				t.Fatalf("got %v, want %v", tc.err, tc.want)
			}
		})
	}
}

func TestSendMultiWrongType(t *testing.T) {
	frame := mustFrame(t, TypeSendMulti, 0, SendMulti{To: recipients(1), Payload: []byte{1}})
	if _, err := DecodeBody[Send](frame, TypeSend); !errors.Is(err, ErrUnexpectedType) {
		t.Fatalf("SendMulti frame read as Send: %v", err)
	}
	if _, err := DecodeBody[Send](rawFrame(TypeSend, frame.Body), TypeSend); !errors.Is(err, ErrMalformed) {
		t.Fatalf("SendMulti body accepted as Send: %v", err)
	}
}
