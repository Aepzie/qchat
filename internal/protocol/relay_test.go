package protocol

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// filled returns n bytes counting up from start.
func filled(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// decodeErr decodes body as the body of a frame of type typ and returns only
// the error.
func decodeErr[T any](typ FrameType, body []byte) error {
	_, err := DecodeBody[T](rawFrame(typ, body), typ)
	return err
}

// buildErr builds a frame of type typ from body and returns only the error.
func buildErr[T any](typ FrameType, body T) error {
	_, err := NewFrame(typ, 0, body)
	return err
}

// looseRegister always encodes Invite, even when it is empty.
type looseRegister struct {
	Bundle []byte `cbor:"1,keyasint"`
	Invite string `cbor:"2,keyasint"`
}

type looseSendResult struct {
	Status uint64 `cbor:"1,keyasint"`
}

func TestRelayRoundTrip(t *testing.T) {
	id := filled(IDSize, 0x10)
	peer := filled(IDSize, 0x80)
	t.Run("Register", func(t *testing.T) {
		roundTrip(t, TypeRegister, 1, Register{Bundle: []byte{1, 2, 3}, Invite: "ABCDEFGH234567"})
	})
	t.Run("RegisterNoInvite", func(t *testing.T) { roundTrip(t, TypeRegister, 2, Register{Bundle: []byte{9}}) })
	t.Run("RegisterMax", func(t *testing.T) {
		roundTrip(t, TypeRegister, 3, Register{
			Bundle: bytes.Repeat([]byte{0xee}, MaxBundleSize),
			Invite: strings.Repeat("~", MaxInviteLen),
		})
	})
	t.Run("Registered", func(t *testing.T) { roundTrip(t, TypeRegistered, 1, Registered{}) })
	t.Run("RegisteredPointer", func(t *testing.T) { roundTrip(t, TypeRegistered, 1, &Registered{}) })
	t.Run("AuthBegin", func(t *testing.T) { roundTrip(t, TypeAuthBegin, 4, AuthBegin{ID: id}) })
	t.Run("AuthChallenge", func(t *testing.T) {
		roundTrip(t, TypeAuthChallenge, 4, AuthChallenge{Nonce: filled(NonceSize, 0x40)})
	})
	t.Run("AuthProof", func(t *testing.T) { roundTrip(t, TypeAuthProof, 5, AuthProof{Sig: []byte{0x5a}}) })
	t.Run("AuthProofMax", func(t *testing.T) {
		roundTrip(t, TypeAuthProof, 5, AuthProof{Sig: bytes.Repeat([]byte{0x5a}, MaxSignatureSize)})
	})
	t.Run("AuthOK", func(t *testing.T) { roundTrip(t, TypeAuthOK, 5, AuthOK{}) })
	t.Run("KeyRequest", func(t *testing.T) { roundTrip(t, TypeKeyRequest, 6, KeyRequest{ID: peer}) })
	t.Run("KeyResponse", func(t *testing.T) { roundTrip(t, TypeKeyResponse, 6, KeyResponse{Bundle: []byte("bundle")}) })
	t.Run("KeyResponseMax", func(t *testing.T) {
		roundTrip(t, TypeKeyResponse, 6, KeyResponse{Bundle: bytes.Repeat([]byte{1}, MaxBundleSize)})
	})
	t.Run("Send", func(t *testing.T) { roundTrip(t, TypeSend, 7, Send{To: peer, Payload: []byte("ciphertext")}) })
	t.Run("SendResultDelivered", func(t *testing.T) {
		roundTrip(t, TypeSendResult, 7, SendResult{Status: SendDelivered})
	})
	t.Run("SendResultOffline", func(t *testing.T) {
		roundTrip(t, TypeSendResult, 7, SendResult{Status: SendRecipientOffline})
	})
	t.Run("Deliver", func(t *testing.T) { roundTrip(t, TypeDeliver, 0, Deliver{From: id, Payload: []byte{0}}) })
	t.Run("DeliverPointer", func(t *testing.T) {
		roundTrip(t, TypeDeliver, 0, &Deliver{From: id, Payload: []byte{1, 2}})
	})
}

// TestRelayMaxPayloadFits proves that a maximal payload with the largest
// possible frame ID still fits within MaxFrameSize.
func TestRelayMaxPayloadFits(t *testing.T) {
	payload := bytes.Repeat([]byte{0xcd}, MaxPayloadSize)
	id := filled(IDSize, 0)
	t.Run("Send", func(t *testing.T) { roundTrip(t, TypeSend, 1<<64-1, Send{To: id, Payload: payload}) })
	t.Run("Deliver", func(t *testing.T) { roundTrip(t, TypeDeliver, 1<<64-1, Deliver{From: id, Payload: payload}) })
	wire := mustEncode(t, mustFrame(t, TypeSend, 1<<64-1, Send{To: id, Payload: payload}))
	if len(wire) > MaxFrameSize {
		t.Fatalf("maximal Send frame is %d bytes, limit %d", len(wire), MaxFrameSize)
	}
}

// TestRelayGolden pins the wire format of the identity and messaging frames.
func TestRelayGolden(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
		hex   string
	}{
		{
			name:  "AuthBegin",
			frame: mustFrame(t, TypeAuthBegin, 1, AuthBegin{ID: filled(IDSize, 0)}),
			hex: "a4 01 01 02 08 03 01 04 58 24 a1 01 58 20" +
				" 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" +
				" 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
		},
		{
			name:  "SendResultOffline",
			frame: mustFrame(t, TypeSendResult, 5, SendResult{Status: SendRecipientOffline}),
			hex:   "a4 01 01 02 0f 03 05 04 43 a1 01 02",
		},
		{
			name:  "SendResultDelivered",
			frame: mustFrame(t, TypeSendResult, 0, SendResult{Status: SendDelivered}),
			hex:   "a3 01 01 02 0f 04 43 a1 01 01",
		},
		{
			name:  "Registered",
			frame: mustFrame(t, TypeRegistered, 9, Registered{}),
			hex:   "a4 01 01 02 07 03 09 04 41 a0",
		},
		{
			name:  "AuthOK",
			frame: mustFrame(t, TypeAuthOK, 0, AuthOK{}),
			hex:   "a3 01 01 02 0b 04 41 a0",
		},
		{
			name:  "RegisterNoInvite",
			frame: mustFrame(t, TypeRegister, 0, Register{Bundle: []byte{0xaa}}),
			hex:   "a3 01 01 02 06 04 44 a1 01 41 aa",
		},
		{
			name:  "RegisterInvite",
			frame: mustFrame(t, TypeRegister, 0, Register{Bundle: []byte{0xaa}, Invite: "AB"}),
			hex:   "a3 01 01 02 06 04 48 a2 01 41 aa 02 62 41 42",
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

func TestRelayDecodeBodyRejects(t *testing.T) {
	id := filled(IDSize, 1)
	short := filled(IDSize-1, 1)
	long := filled(IDSize+1, 1)
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"RegisterMissingBundle", decodeErr[Register](TypeRegister, mustHex(t, "a0")), ErrMalformed},
		{"RegisterEmptyBundle", decodeErr[Register](TypeRegister, encodeLoose(t, Register{Bundle: []byte{}})), ErrMalformed},
		{"RegisterBundleTooLarge", decodeErr[Register](TypeRegister,
			encodeLoose(t, Register{Bundle: make([]byte, MaxBundleSize+1)})), ErrMalformed},
		{"RegisterBundleAsText", decodeErr[Register](TypeRegister, mustHex(t, "a1 01 61 41")), ErrMalformed},
		{"RegisterInviteTooLong", decodeErr[Register](TypeRegister,
			encodeLoose(t, Register{Bundle: []byte{1}, Invite: strings.Repeat("a", MaxInviteLen+1)})), ErrMalformed},
		{"RegisterInviteNonASCII", decodeErr[Register](TypeRegister,
			encodeLoose(t, Register{Bundle: []byte{1}, Invite: "invéte"})), ErrMalformed},
		{"RegisterInviteControl", decodeErr[Register](TypeRegister,
			encodeLoose(t, Register{Bundle: []byte{1}, Invite: "in\tvite"})), ErrMalformed},
		{"RegisterInviteInvalidUTF8", decodeErr[Register](TypeRegister, mustHex(t, "a2 01 41 01 02 61 ff")), ErrMalformed},
		{"RegisterInviteExplicitEmpty", decodeErr[Register](TypeRegister,
			encodeLoose(t, looseRegister{Bundle: []byte{1}})), ErrMalformed},
		{"RegisterInviteAsBytes", decodeErr[Register](TypeRegister, mustHex(t, "a2 01 41 01 02 41 41")), ErrMalformed},
		{"RegisterUnknownField", decodeErr[Register](TypeRegister, mustHex(t, "a2 01 41 01 03 00")), ErrMalformed},

		{"RegisteredNoBody", decodeErr[Registered](TypeRegistered, nil), ErrMalformed},
		{"RegisteredNull", decodeErr[Registered](TypeRegistered, mustHex(t, "f6")), ErrMalformed},
		{"RegisteredNullPointer", decodeErr[*Registered](TypeRegistered, mustHex(t, "f6")), ErrMalformed},
		{"RegisteredField", decodeErr[Registered](TypeRegistered, mustHex(t, "a1 01 00")), ErrMalformed},
		{"RegisteredNonCanonicalMap", decodeErr[Registered](TypeRegistered, mustHex(t, "b8 00")), ErrMalformed},
		{"RegisteredIndefinite", decodeErr[Registered](TypeRegistered, mustHex(t, "bf ff")), ErrMalformed},
		{"RegisteredTrailing", decodeErr[Registered](TypeRegistered, mustHex(t, "a0 00")), ErrMalformed},
		{"RegisteredArray", decodeErr[Registered](TypeRegistered, mustHex(t, "80")), ErrMalformed},
		{"AuthOKField", decodeErr[AuthOK](TypeAuthOK, mustHex(t, "a1 01 40")), ErrMalformed},
		{"AuthOKNoBody", decodeErr[AuthOK](TypeAuthOK, nil), ErrMalformed},

		{"AuthBeginMissing", decodeErr[AuthBegin](TypeAuthBegin, mustHex(t, "a0")), ErrMalformed},
		{"AuthBeginEmpty", decodeErr[AuthBegin](TypeAuthBegin, mustHex(t, "a1 01 40")), ErrMalformed},
		{"AuthBeginNull", decodeErr[AuthBegin](TypeAuthBegin, mustHex(t, "a1 01 f6")), ErrMalformed},
		{"AuthBeginShort", decodeErr[AuthBegin](TypeAuthBegin, encodeLoose(t, AuthBegin{ID: short})), ErrMalformed},
		{"AuthBeginLong", decodeErr[AuthBegin](TypeAuthBegin, encodeLoose(t, AuthBegin{ID: long})), ErrMalformed},
		{"AuthBeginArray", decodeErr[AuthBegin](TypeAuthBegin, mustHex(t, "a1 01 81 01")), ErrMalformed},
		{"AuthChallengeShort", decodeErr[AuthChallenge](TypeAuthChallenge,
			encodeLoose(t, AuthChallenge{Nonce: filled(NonceSize-1, 0)})), ErrMalformed},
		{"AuthChallengeLong", decodeErr[AuthChallenge](TypeAuthChallenge,
			encodeLoose(t, AuthChallenge{Nonce: filled(NonceSize+1, 0)})), ErrMalformed},
		{"AuthProofEmpty", decodeErr[AuthProof](TypeAuthProof, mustHex(t, "a1 01 40")), ErrMalformed},
		{"AuthProofTooLarge", decodeErr[AuthProof](TypeAuthProof,
			encodeLoose(t, AuthProof{Sig: make([]byte, MaxSignatureSize+1)})), ErrMalformed},
		{"KeyRequestShort", decodeErr[KeyRequest](TypeKeyRequest, encodeLoose(t, KeyRequest{ID: short})), ErrMalformed},
		{"KeyRequestLong", decodeErr[KeyRequest](TypeKeyRequest, encodeLoose(t, KeyRequest{ID: long})), ErrMalformed},
		{"KeyResponseEmpty", decodeErr[KeyResponse](TypeKeyResponse, mustHex(t, "a1 01 40")), ErrMalformed},
		{"KeyResponseTooLarge", decodeErr[KeyResponse](TypeKeyResponse,
			encodeLoose(t, KeyResponse{Bundle: make([]byte, MaxBundleSize+1)})), ErrMalformed},

		{"SendShortTo", decodeErr[Send](TypeSend, encodeLoose(t, Send{To: short, Payload: []byte{1}})), ErrMalformed},
		{"SendLongTo", decodeErr[Send](TypeSend, encodeLoose(t, Send{To: long, Payload: []byte{1}})), ErrMalformed},
		{"SendEmptyPayload", decodeErr[Send](TypeSend, encodeLoose(t, Send{To: id, Payload: []byte{}})), ErrMalformed},
		{"SendMissingPayload", decodeErr[Send](TypeSend, mustHex(t, "a1 01 58 20"+strings.Repeat("01", IDSize))), ErrMalformed},
		{"SendPayloadTooLarge", decodeErr[Send](TypeSend,
			encodeLoose(t, Send{To: id, Payload: make([]byte, MaxPayloadSize+1)})), ErrMalformed},
		{"SendKeysUnsorted", decodeErr[Send](TypeSend,
			mustHex(t, "a2 02 41 01 01 58 20"+strings.Repeat("01", IDSize))), ErrMalformed},
		{"DeliverShortFrom", decodeErr[Deliver](TypeDeliver,
			encodeLoose(t, Deliver{From: short, Payload: []byte{1}})), ErrMalformed},
		{"DeliverEmptyPayload", decodeErr[Deliver](TypeDeliver, encodeLoose(t, Deliver{From: id})), ErrMalformed},
		{"DeliverPayloadTooLarge", decodeErr[Deliver](TypeDeliver,
			encodeLoose(t, Deliver{From: id, Payload: make([]byte, MaxPayloadSize+1)})), ErrMalformed},

		{"SendResultZero", decodeErr[SendResult](TypeSendResult, encodeLoose(t, looseSendResult{Status: 0})), ErrMalformed},
		{"SendResultUnknown", decodeErr[SendResult](TypeSendResult, encodeLoose(t, looseSendResult{Status: 3})), ErrMalformed},
		{"SendResultOverflow", decodeErr[SendResult](TypeSendResult, encodeLoose(t, looseSendResult{Status: 257})), ErrMalformed},
		{"SendResultMissing", decodeErr[SendResult](TypeSendResult, mustHex(t, "a0")), ErrMalformed},
		{"SendResultNonCanonical", decodeErr[SendResult](TypeSendResult, mustHex(t, "a1 01 18 01")), ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, tc.want) {
				t.Fatalf("got %v, want %v", tc.err, tc.want)
			}
		})
	}
}

func TestRelayNewFrameRejects(t *testing.T) {
	id := filled(IDSize, 1)
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"RegisterNoBundle", buildErr(TypeRegister, Register{Invite: "abc"}), ErrMalformed},
		{"RegisterBundleTooLarge", buildErr(TypeRegister, Register{Bundle: make([]byte, MaxBundleSize+1)}), ErrMalformed},
		{"RegisterInviteTooLong", buildErr(TypeRegister,
			Register{Bundle: []byte{1}, Invite: strings.Repeat("a", MaxInviteLen+1)}), ErrMalformed},
		{"RegisterInviteNonASCII", buildErr(TypeRegister, Register{Bundle: []byte{1}, Invite: "ü"}), ErrMalformed},
		{"RegisterInviteDEL", buildErr(TypeRegister, Register{Bundle: []byte{1}, Invite: "a\x7f"}), ErrMalformed},
		{"AuthBeginNil", buildErr(TypeAuthBegin, AuthBegin{}), ErrMalformed},
		{"AuthBeginShort", buildErr(TypeAuthBegin, AuthBegin{ID: id[:IDSize-1]}), ErrMalformed},
		{"AuthChallengeLong", buildErr(TypeAuthChallenge, AuthChallenge{Nonce: make([]byte, NonceSize+1)}), ErrMalformed},
		{"AuthProofEmpty", buildErr(TypeAuthProof, AuthProof{}), ErrMalformed},
		{"KeyRequestLong", buildErr(TypeKeyRequest, KeyRequest{ID: make([]byte, IDSize+1)}), ErrMalformed},
		{"KeyResponseEmpty", buildErr(TypeKeyResponse, KeyResponse{}), ErrMalformed},
		{"SendNoPayload", buildErr(TypeSend, Send{To: id}), ErrMalformed},
		{"SendNoRecipient", buildErr(TypeSend, Send{Payload: []byte{1}}), ErrMalformed},
		{"DeliverPayloadTooLarge", buildErr(TypeDeliver,
			Deliver{From: id, Payload: make([]byte, MaxPayloadSize+1)}), ErrMalformed},
		{"SendResultZero", buildErr(TypeSendResult, SendResult{}), ErrMalformed},
		{"SendResultUnknown", buildErr(TypeSendResult, SendResult{Status: 3}), ErrMalformed},
		{"NilRegistered", buildErr[*Registered](TypeRegistered, nil), ErrMalformed},
		{"RegisteredAsAuthOK", buildErr(TypeAuthOK, Registered{}), ErrUnexpectedType},
		{"AuthOKAsRegistered", buildErr(TypeRegistered, AuthOK{}), ErrUnexpectedType},
		{"AuthBeginAsKeyRequest", buildErr(TypeKeyRequest, AuthBegin{ID: id}), ErrUnexpectedType},
		{"SendAsDeliver", buildErr(TypeDeliver, Send{To: id, Payload: []byte{1}}), ErrUnexpectedType},
		{"KeyResponseAsRegister", buildErr(TypeRegister, KeyResponse{Bundle: []byte{1}}), ErrUnexpectedType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, tc.want) {
				t.Fatalf("got %v, want %v", tc.err, tc.want)
			}
		})
	}
}

// TestRelayDecodeBodyWrongType checks that bodies with identical wire shapes
// cannot be confused: the frame type alone decides how a body is read.
func TestRelayDecodeBodyWrongType(t *testing.T) {
	id := filled(IDSize, 1)
	tests := []struct {
		name string
		err  error
	}{
		{"KeyRequestFromAuthBegin", func() error {
			_, err := DecodeBody[KeyRequest](mustFrame(t, TypeAuthBegin, 0, AuthBegin{ID: id}), TypeAuthBegin)
			return err
		}()},
		{"AuthBeginFromKeyRequestFrame", func() error {
			_, err := DecodeBody[AuthBegin](mustFrame(t, TypeKeyRequest, 0, KeyRequest{ID: id}), TypeAuthBegin)
			return err
		}()},
		{"DeliverFromSend", func() error {
			_, err := DecodeBody[Deliver](mustFrame(t, TypeSend, 0, Send{To: id, Payload: []byte{1}}), TypeSend)
			return err
		}()},
		{"AuthOKFromRegistered", func() error {
			_, err := DecodeBody[AuthOK](mustFrame(t, TypeRegistered, 0, Registered{}), TypeRegistered)
			return err
		}()},
		{"KeyResponseFromRegister", func() error {
			_, err := DecodeBody[KeyResponse](mustFrame(t, TypeRegister, 0, Register{Bundle: []byte{1}}), TypeRegister)
			return err
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, ErrUnexpectedType) {
				t.Fatalf("got %v, want ErrUnexpectedType", tc.err)
			}
		})
	}
}

func TestSendStatusString(t *testing.T) {
	want := map[SendStatus]string{
		SendDelivered: "Delivered", SendRecipientOffline: "RecipientOffline",
		0: "SendStatus(0)", 3: "SendStatus(3)", 255: "SendStatus(255)",
	}
	for s, name := range want {
		if got := s.String(); got != name {
			t.Errorf("SendStatus(%d).String() = %q, want %q", uint8(s), got, name)
		}
	}
	for s := 0; s < 256; s++ {
		valid := s == 1 || s == 2
		if got := SendStatus(s).Valid(); got != valid {
			t.Errorf("SendStatus(%d).Valid() = %v, want %v", s, got, valid)
		}
	}
}

func TestRelayErrorCodeString(t *testing.T) {
	want := map[ErrorCode]string{
		ErrCodeUnauthorized: "Unauthorized", ErrCodeNotFound: "NotFound",
		ErrCodeRegistrationDenied: "RegistrationDenied", ErrCodeConflict: "Conflict",
		10: "ErrorCode(10)",
	}
	for c, name := range want {
		if got := c.String(); got != name {
			t.Errorf("ErrorCode(%d).String() = %q, want %q", uint16(c), got, name)
		}
		if got, valid := c.Valid(), c != 10; got != valid {
			t.Errorf("ErrorCode(%d).Valid() = %v, want %v", uint16(c), got, valid)
		}
	}
	roundTrip(t, TypeError, 3, ErrorBody{Code: ErrCodeConflict, Message: "bundle differs"})
}
