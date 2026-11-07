package protocol

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// looseStatus encodes PrekeyStatus fields with wider types than the real
// body, to craft out-of-range values.
type looseStatus struct {
	OneTimeRemaining    uint64 `cbor:"1,keyasint"`
	SignedPrekeyExpires int64  `cbor:"2,keyasint"`
}

// looseUpload always encodes both PrekeyUpload fields, even when empty.
type looseUpload struct {
	SignedPrekey   []byte   `cbor:"1,keyasint"`
	OneTimePrekeys [][]byte `cbor:"2,keyasint"`
}

// prekeys returns n distinct prekeys of size bytes each.
func prekeys(n, size int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = bytes.Repeat([]byte{byte(i)}, size)
	}
	return out
}

func TestPrekeyRoundTrip(t *testing.T) {
	id := filled(IDSize, 0x30)
	t.Run("UploadEmpty", func(t *testing.T) { roundTrip(t, TypePrekeyUpload, 1, PrekeyUpload{}) })
	t.Run("UploadSignedOnly", func(t *testing.T) {
		roundTrip(t, TypePrekeyUpload, 1, PrekeyUpload{SignedPrekey: []byte("spk")})
	})
	t.Run("UploadOneTimeOnly", func(t *testing.T) {
		roundTrip(t, TypePrekeyUpload, 1, PrekeyUpload{OneTimePrekeys: prekeys(3, 5)})
	})
	t.Run("UploadPointer", func(t *testing.T) {
		roundTrip(t, TypePrekeyUpload, 1, &PrekeyUpload{SignedPrekey: []byte{1}, OneTimePrekeys: prekeys(1, 1)})
	})
	t.Run("Status", func(t *testing.T) {
		roundTrip(t, TypePrekeyStatus, 1, PrekeyStatus{OneTimeRemaining: 1<<32 - 1, SignedPrekeyExpires: 1<<63 - 1})
	})
	t.Run("StatusZero", func(t *testing.T) { roundTrip(t, TypePrekeyStatus, 1, PrekeyStatus{}) })
	t.Run("Request", func(t *testing.T) { roundTrip(t, TypePrekeyRequest, 2, PrekeyRequest{ID: id}) })
	t.Run("Response", func(t *testing.T) {
		roundTrip(t, TypePrekeyResponse, 2, PrekeyResponse{Bundle: []byte("b"), SignedPrekey: []byte("s")})
	})
	t.Run("ResponseOneTime", func(t *testing.T) {
		roundTrip(t, TypePrekeyResponse, 2, PrekeyResponse{
			Bundle:        bytes.Repeat([]byte{1}, MaxBundleSize),
			SignedPrekey:  bytes.Repeat([]byte{2}, MaxPrekeySize),
			OneTimePrekey: bytes.Repeat([]byte{3}, MaxPrekeySize),
		})
	})
	t.Run("Ack", func(t *testing.T) { roundTrip(t, TypeAck, 0, Ack{QueueID: 1}) })
	t.Run("AckMax", func(t *testing.T) { roundTrip(t, TypeAck, 0, &Ack{QueueID: 1<<64 - 1}) })
	t.Run("SendResultAccepted", func(t *testing.T) {
		roundTrip(t, TypeSendResult, 3, SendResult{Status: SendAccepted})
	})
	t.Run("ErrorQueueFull", func(t *testing.T) {
		roundTrip(t, TypeError, 3, ErrorBody{Code: ErrCodeQueueFull, Message: "queue full"})
	})
}

// TestPrekeyMaxUploadFits proves that an upload of the largest signed prekey
// and the largest number of maximal one-time prekeys fits in a frame and
// passes the decoder's container limits.
func TestPrekeyMaxUploadFits(t *testing.T) {
	up := PrekeyUpload{
		SignedPrekey:   bytes.Repeat([]byte{0xff}, MaxPrekeySize),
		OneTimePrekeys: prekeys(MaxOneTimePrekeysPerUpload, MaxPrekeySize),
	}
	roundTrip(t, TypePrekeyUpload, 1<<64-1, up)
	wire := mustEncode(t, mustFrame(t, TypePrekeyUpload, 1<<64-1, up))
	if len(wire) > MaxFrameSize {
		t.Fatalf("maximal PrekeyUpload frame is %d bytes, limit %d", len(wire), MaxFrameSize)
	}
}

// TestPrekeyGolden pins the wire format of the prekey and queue frames.
func TestPrekeyGolden(t *testing.T) {
	idHex := " 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" +
		" 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
	tests := []struct {
		name  string
		frame Frame
		hex   string
	}{
		{
			name:  "UploadEmpty",
			frame: mustFrame(t, TypePrekeyUpload, 1, PrekeyUpload{}),
			hex:   "a4 01 01 02 11 03 01 04 41 a0",
		},
		{
			name: "UploadFull",
			frame: mustFrame(t, TypePrekeyUpload, 2, PrekeyUpload{
				SignedPrekey:   []byte{0xaa},
				OneTimePrekeys: [][]byte{{0x01}, {0x02, 0x03}},
			}),
			hex: "a4 01 01 02 11 03 02 04 4b a2 01 41 aa 02 82 41 01 42 02 03",
		},
		{
			name:  "Status",
			frame: mustFrame(t, TypePrekeyStatus, 2, PrekeyStatus{OneTimeRemaining: 50, SignedPrekeyExpires: 1700000000}),
			hex:   "a4 01 01 02 12 03 02 04 4a a2 01 18 32 02 1a 65 53 f1 00",
		},
		{
			name:  "StatusZero",
			frame: mustFrame(t, TypePrekeyStatus, 0, PrekeyStatus{}),
			hex:   "a3 01 01 02 12 04 45 a2 01 00 02 00",
		},
		{
			name:  "Request",
			frame: mustFrame(t, TypePrekeyRequest, 3, PrekeyRequest{ID: filled(IDSize, 0)}),
			hex:   "a4 01 01 02 13 03 03 04 58 24 a1 01 58 20" + idHex,
		},
		{
			name:  "ResponseNoOneTime",
			frame: mustFrame(t, TypePrekeyResponse, 3, PrekeyResponse{Bundle: []byte{0xb1}, SignedPrekey: []byte{0xc2}}),
			hex:   "a4 01 01 02 14 03 03 04 47 a2 01 41 b1 02 41 c2",
		},
		{
			name: "ResponseOneTime",
			frame: mustFrame(t, TypePrekeyResponse, 3, PrekeyResponse{
				Bundle: []byte{0xb1}, SignedPrekey: []byte{0xc2}, OneTimePrekey: []byte{0xd3},
			}),
			hex: "a4 01 01 02 14 03 03 04 4a a3 01 41 b1 02 41 c2 03 41 d3",
		},
		{
			name:  "Ack",
			frame: mustFrame(t, TypeAck, 0, Ack{QueueID: 1}),
			hex:   "a3 01 01 02 15 04 43 a1 01 01",
		},
		{
			name:  "AckLarge",
			frame: mustFrame(t, TypeAck, 7, Ack{QueueID: 1 << 32}),
			hex:   "a4 01 01 02 15 03 07 04 4b a1 01 1b 00 00 00 01 00 00 00 00",
		},
		{
			name:  "Deliver",
			frame: mustFrame(t, TypeDeliver, 0, Deliver{From: filled(IDSize, 0), Payload: []byte{0xee}, QueueID: 1}),
			hex:   "a3 01 01 02 10 04 58 29 a3 01 58 20" + idHex + " 02 41 ee 03 01",
		},
		{
			name:  "SendResultAccepted",
			frame: mustFrame(t, TypeSendResult, 0, SendResult{Status: SendAccepted}),
			hex:   "a3 01 01 02 0f 04 43 a1 01 03",
		},
		{
			name:  "ErrorQueueFull",
			frame: mustFrame(t, TypeError, 0, ErrorBody{Code: ErrCodeQueueFull}),
			hex:   "a3 01 01 02 05 04 45 a2 01 0a 02 60",
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

func TestPrekeyDecodeBodyRejects(t *testing.T) {
	id := filled(IDSize, 1)
	idHex := strings.Repeat("01", IDSize)
	tests := []struct {
		name string
		err  error
	}{
		{"UploadNoBody", decodeErr[PrekeyUpload](TypePrekeyUpload, nil)},
		{"UploadNull", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "f6"))},
		{"UploadExplicitEmptySigned", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 01 40"))},
		{"UploadExplicitEmptyList", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 02 80"))},
		{"UploadBothExplicitEmpty", decodeErr[PrekeyUpload](TypePrekeyUpload, encodeLoose(t, looseUpload{}))},
		{"UploadNullSigned", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 01 f6"))},
		{"UploadNullList", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 02 f6"))},
		{"UploadEmptyElement", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 02 82 41 01 40"))},
		{"UploadNullElement", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 02 81 f6"))},
		{"UploadTextElement", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 02 81 61 41"))},
		{"UploadNestedElement", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 02 81 81 41 01"))},
		{"UploadListNotArray", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 02 41 01"))},
		{"UploadIndefiniteList", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 02 9f 41 01 ff"))},
		{"UploadNonCanonicalLength", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 02 98 01 41 01"))},
		{"UploadKeysUnsorted", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a2 02 81 41 01 01 41 01"))},
		{"UploadUnknownField", decodeErr[PrekeyUpload](TypePrekeyUpload, mustHex(t, "a1 03 00"))},
		{"UploadSignedTooLarge", decodeErr[PrekeyUpload](TypePrekeyUpload,
			encodeLoose(t, PrekeyUpload{SignedPrekey: make([]byte, MaxPrekeySize+1)}))},
		{"UploadElementTooLarge", decodeErr[PrekeyUpload](TypePrekeyUpload,
			encodeLoose(t, PrekeyUpload{OneTimePrekeys: [][]byte{{1}, make([]byte, MaxPrekeySize+1)}}))},
		{"UploadTooMany", decodeErr[PrekeyUpload](TypePrekeyUpload,
			encodeLoose(t, PrekeyUpload{OneTimePrekeys: prekeys(MaxOneTimePrekeysPerUpload+1, 1)}))},
		{"UploadAboveDecoderLimit", decodeErr[PrekeyUpload](TypePrekeyUpload,
			encodeLoose(t, PrekeyUpload{OneTimePrekeys: prekeys(maxArrayElements+1, 1)}))},

		{"StatusMissingExpiry", decodeErr[PrekeyStatus](TypePrekeyStatus, mustHex(t, "a1 01 00"))},
		{"StatusMissingCount", decodeErr[PrekeyStatus](TypePrekeyStatus, mustHex(t, "a1 02 00"))},
		{"StatusNegativeExpiry", decodeErr[PrekeyStatus](TypePrekeyStatus,
			encodeLoose(t, looseStatus{SignedPrekeyExpires: -1}))},
		{"StatusCountOverflow", decodeErr[PrekeyStatus](TypePrekeyStatus,
			encodeLoose(t, looseStatus{OneTimeRemaining: 1 << 32}))},
		{"StatusNonCanonical", decodeErr[PrekeyStatus](TypePrekeyStatus, mustHex(t, "a2 01 18 01 02 00"))},
		{"StatusCountNegative", decodeErr[PrekeyStatus](TypePrekeyStatus, mustHex(t, "a2 01 20 02 00"))},

		{"RequestMissing", decodeErr[PrekeyRequest](TypePrekeyRequest, mustHex(t, "a0"))},
		{"RequestShort", decodeErr[PrekeyRequest](TypePrekeyRequest,
			encodeLoose(t, PrekeyRequest{ID: filled(IDSize-1, 0)}))},
		{"RequestLong", decodeErr[PrekeyRequest](TypePrekeyRequest,
			encodeLoose(t, PrekeyRequest{ID: filled(IDSize+1, 0)}))},

		{"ResponseMissingSigned", decodeErr[PrekeyResponse](TypePrekeyResponse, mustHex(t, "a1 01 41 01"))},
		{"ResponseEmptyBundle", decodeErr[PrekeyResponse](TypePrekeyResponse, mustHex(t, "a2 01 40 02 41 01"))},
		{"ResponseEmptySigned", decodeErr[PrekeyResponse](TypePrekeyResponse, mustHex(t, "a2 01 41 01 02 40"))},
		{"ResponseExplicitEmptyOneTime", decodeErr[PrekeyResponse](TypePrekeyResponse,
			mustHex(t, "a3 01 41 01 02 41 01 03 40"))},
		{"ResponseBundleTooLarge", decodeErr[PrekeyResponse](TypePrekeyResponse,
			encodeLoose(t, PrekeyResponse{Bundle: make([]byte, MaxBundleSize+1), SignedPrekey: []byte{1}}))},
		{"ResponseSignedTooLarge", decodeErr[PrekeyResponse](TypePrekeyResponse,
			encodeLoose(t, PrekeyResponse{Bundle: []byte{1}, SignedPrekey: make([]byte, MaxPrekeySize+1)}))},
		{"ResponseOneTimeTooLarge", decodeErr[PrekeyResponse](TypePrekeyResponse,
			encodeLoose(t, PrekeyResponse{Bundle: []byte{1}, SignedPrekey: []byte{1},
				OneTimePrekey: make([]byte, MaxPrekeySize+1)}))},

		{"AckMissing", decodeErr[Ack](TypeAck, mustHex(t, "a0"))},
		{"AckZero", decodeErr[Ack](TypeAck, mustHex(t, "a1 01 00"))},
		{"AckNegative", decodeErr[Ack](TypeAck, mustHex(t, "a1 01 20"))},
		{"AckNonCanonical", decodeErr[Ack](TypeAck, mustHex(t, "a1 01 18 05"))},
		{"AckAsBytes", decodeErr[Ack](TypeAck, mustHex(t, "a1 01 41 01"))},
		{"AckNoBody", decodeErr[Ack](TypeAck, nil)},

		{"DeliverMissingQueueID", decodeErr[Deliver](TypeDeliver, mustHex(t, "a2 01 58 20"+idHex+" 02 41 01"))},
		{"DeliverZeroQueueID", decodeErr[Deliver](TypeDeliver, encodeLoose(t, Deliver{From: id, Payload: []byte{1}}))},
		{"DeliverNonCanonicalQueueID", decodeErr[Deliver](TypeDeliver,
			mustHex(t, "a3 01 58 20"+idHex+" 02 41 01 03 18 01"))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, ErrMalformed) {
				t.Fatalf("got %v, want ErrMalformed", tc.err)
			}
		})
	}
}

func TestPrekeyNewFrameRejects(t *testing.T) {
	id := filled(IDSize, 1)
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"UploadEmptySigned", buildErr(TypePrekeyUpload, PrekeyUpload{SignedPrekey: []byte{}}), ErrMalformed},
		{"UploadSignedTooLarge", buildErr(TypePrekeyUpload,
			PrekeyUpload{SignedPrekey: make([]byte, MaxPrekeySize+1)}), ErrMalformed},
		{"UploadEmptyElement", buildErr(TypePrekeyUpload, PrekeyUpload{OneTimePrekeys: [][]byte{{1}, nil}}), ErrMalformed},
		{"UploadTooMany", buildErr(TypePrekeyUpload,
			PrekeyUpload{OneTimePrekeys: prekeys(MaxOneTimePrekeysPerUpload+1, 1)}), ErrMalformed},
		{"StatusNegative", buildErr(TypePrekeyStatus, PrekeyStatus{SignedPrekeyExpires: -5}), ErrMalformed},
		{"RequestNil", buildErr(TypePrekeyRequest, PrekeyRequest{}), ErrMalformed},
		{"ResponseNoSigned", buildErr(TypePrekeyResponse, PrekeyResponse{Bundle: []byte{1}}), ErrMalformed},
		{"ResponseNoBundle", buildErr(TypePrekeyResponse, PrekeyResponse{SignedPrekey: []byte{1}}), ErrMalformed},
		{"ResponseEmptyOneTime", buildErr(TypePrekeyResponse,
			PrekeyResponse{Bundle: []byte{1}, SignedPrekey: []byte{1}, OneTimePrekey: []byte{}}), ErrMalformed},
		{"AckZero", buildErr(TypeAck, Ack{}), ErrMalformed},
		{"NilAck", buildErr[*Ack](TypeAck, nil), ErrMalformed},
		{"DeliverNoQueueID", buildErr(TypeDeliver, Deliver{From: id, Payload: []byte{1}}), ErrMalformed},
		{"RequestAsKeyRequest", buildErr(TypeKeyRequest, PrekeyRequest{ID: id}), ErrUnexpectedType},
		{"KeyRequestAsRequest", buildErr(TypePrekeyRequest, KeyRequest{ID: id}), ErrUnexpectedType},
		{"AckAsPing", buildErr(TypePing, Ack{QueueID: 1}), ErrUnexpectedType},
		{"StatusAsUpload", buildErr(TypePrekeyUpload, PrekeyStatus{}), ErrUnexpectedType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, tc.want) {
				t.Fatalf("got %v, want %v", tc.err, tc.want)
			}
		})
	}
}

// TestPrekeyDecodeBodyWrongType checks that bodies with identical wire shapes
// cannot be confused across frame types.
func TestPrekeyDecodeBodyWrongType(t *testing.T) {
	id := filled(IDSize, 1)
	if _, err := DecodeBody[KeyRequest](mustFrame(t, TypePrekeyRequest, 0, PrekeyRequest{ID: id}),
		TypePrekeyRequest); !errors.Is(err, ErrUnexpectedType) {
		t.Fatalf("KeyRequest from PrekeyRequest frame: got %v", err)
	}
	if _, err := DecodeBody[PrekeyRequest](mustFrame(t, TypeKeyRequest, 0, KeyRequest{ID: id}),
		TypePrekeyRequest); !errors.Is(err, ErrUnexpectedType) {
		t.Fatalf("PrekeyRequest from KeyRequest frame: got %v", err)
	}
	if _, err := DecodeBody[Ping](mustFrame(t, TypeAck, 0, Ack{QueueID: 1}), TypeAck); !errors.Is(err, ErrUnexpectedType) {
		t.Fatalf("Ping from Ack frame: got %v", err)
	}
}
