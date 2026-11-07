package protocol

import (
	"bytes"
	"reflect"
	"strings"
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
	frames = append(frames, relaySeedFrames(f)...)
	for _, fr := range frames {
		f.Add(mustEncode(f, fr))
	}
	for _, s := range []string{
		"", "a0", "a2 01 02 02 03", "a3 01 01 02 03 02 03", "bf 01 01 02 03 ff",
		"a3 01 01 02 03 05 00", "a2 02 03 01 01", "a3 01 01 02 03 04 5a ff ff ff ff",
		"a2 01 01 02 11", "a3 01 01 02 07 04 41 a0", "a3 01 01 02 07 04 40",
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

// relaySeedFrames returns one valid frame of every identity, authentication
// and messaging type.
func relaySeedFrames(f *testing.F) []Frame {
	id := bytes.Repeat([]byte{0x11}, IDSize)
	return []Frame{
		mustFrame(f, TypeRegister, 1, Register{Bundle: []byte("bundle"), Invite: "INVITE234567"}),
		mustFrame(f, TypeRegister, 1, Register{Bundle: []byte{0x01}}),
		mustFrame(f, TypeRegistered, 1, Registered{}),
		mustFrame(f, TypeAuthBegin, 2, AuthBegin{ID: id}),
		mustFrame(f, TypeAuthChallenge, 2, AuthChallenge{Nonce: bytes.Repeat([]byte{0x22}, NonceSize)}),
		mustFrame(f, TypeAuthProof, 3, AuthProof{Sig: []byte("signature")}),
		mustFrame(f, TypeAuthOK, 3, AuthOK{}),
		mustFrame(f, TypeKeyRequest, 4, KeyRequest{ID: id}),
		mustFrame(f, TypeKeyResponse, 4, KeyResponse{Bundle: []byte("bundle")}),
		mustFrame(f, TypeSend, 5, Send{To: id, Payload: []byte("ciphertext")}),
		mustFrame(f, TypeSendResult, 5, SendResult{Status: SendDelivered}),
		mustFrame(f, TypeSendResult, 6, SendResult{Status: SendRecipientOffline}),
		mustFrame(f, TypeDeliver, 0, Deliver{From: id, Payload: []byte("ciphertext"), QueueID: 1}),
		mustFrame(f, TypeSendResult, 7, SendResult{Status: SendAccepted}),
		mustFrame(f, TypePrekeyUpload, 8, PrekeyUpload{}),
		mustFrame(f, TypePrekeyUpload, 8, PrekeyUpload{SignedPrekey: []byte("spk"), OneTimePrekeys: [][]byte{{1}, {2, 3}}}),
		mustFrame(f, TypePrekeyStatus, 8, PrekeyStatus{OneTimeRemaining: 50, SignedPrekeyExpires: 1700000000}),
		mustFrame(f, TypePrekeyRequest, 9, PrekeyRequest{ID: id}),
		mustFrame(f, TypePrekeyResponse, 9, PrekeyResponse{Bundle: []byte("b"), SignedPrekey: []byte("s")}),
		mustFrame(f, TypePrekeyResponse, 9, PrekeyResponse{Bundle: []byte("b"), SignedPrekey: []byte("s"), OneTimePrekey: []byte("o")}),
		mustFrame(f, TypeAck, 0, Ack{QueueID: 1 << 40}),
		mustFrame(f, TypeSendMulti, 10, SendMulti{To: [][]byte{id}, Payload: []byte("group")}),
		mustFrame(f, TypeSendMulti, 10, SendMulti{To: [][]byte{id, bytes.Repeat([]byte{0x33}, IDSize)}, Payload: []byte{1}}),
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
	for _, fr := range relaySeedFrames(f) {
		f.Add(uint8(fr.Type), fr.Body)
	}
	f.Add(uint8(TypePing), []byte{0xf6})
	f.Add(uint8(TypeError), mustHex(f, "a2 01 01 02 61 ff"))
	f.Add(uint8(TypeRegistered), []byte{0xf6})
	f.Add(uint8(TypeRegister), mustHex(f, "a2 01 41 01 02 60"))
	f.Add(uint8(TypeSendResult), mustHex(f, "a1 01 04"))
	f.Add(uint8(TypePrekeyUpload), mustHex(f, "a1 02 80"))
	f.Add(uint8(TypePrekeyUpload), mustHex(f, "a1 02 81 40"))
	f.Add(uint8(TypeAck), mustHex(f, "a1 01 00"))
	f.Add(uint8(TypeSendMulti), mustHex(f, "a2 01 80 02 41 01"))
	f.Add(uint8(TypeSendMulti), mustHex(f, "a2 01 82 58 20"+strings.Repeat("11", IDSize)+" 58 20"+strings.Repeat("11", IDSize)+" 02 41 01"))
	f.Add(uint8(TypeSendMulti), mustHex(f, "a2 01 81 41 01 02 41 01"))
	f.Add(uint8(0), mustFrame(f, TypePing, 0, Ping{Nonce: 7}).Body)

	f.Fuzz(func(t *testing.T, sel uint8, body []byte) {
		switch FrameType(sel % 23) {
		case TypeHello:
			checkBodyRoundTrip[Hello](t, TypeHello, body)
		case TypeWelcome:
			checkBodyRoundTrip[Welcome](t, TypeWelcome, body)
		case TypePing:
			checkBodyRoundTrip[Ping](t, TypePing, body)
			checkBodyRoundTrip[*Ping](t, TypePing, body)
		case TypePong:
			checkBodyRoundTrip[Pong](t, TypePong, body)
		case TypeError:
			checkBodyRoundTrip[ErrorBody](t, TypeError, body)
			checkBodyRoundTrip[*ErrorBody](t, TypeError, body)
		case TypeRegister:
			checkBodyRoundTrip[Register](t, TypeRegister, body)
			checkBodyRoundTrip[*Register](t, TypeRegister, body)
		case TypeRegistered:
			checkBodyRoundTrip[Registered](t, TypeRegistered, body)
			checkBodyRoundTrip[*Registered](t, TypeRegistered, body)
		case TypeAuthBegin:
			checkBodyRoundTrip[AuthBegin](t, TypeAuthBegin, body)
			if _, err := DecodeBody[KeyRequest](rawFrame(TypeAuthBegin, body), TypeAuthBegin); err == nil {
				t.Fatal("KeyRequest body accepted for AuthBegin frame")
			}
		case TypeAuthChallenge:
			checkBodyRoundTrip[AuthChallenge](t, TypeAuthChallenge, body)
		case TypeAuthProof:
			checkBodyRoundTrip[AuthProof](t, TypeAuthProof, body)
		case TypeAuthOK:
			checkBodyRoundTrip[AuthOK](t, TypeAuthOK, body)
		case TypeKeyRequest:
			checkBodyRoundTrip[KeyRequest](t, TypeKeyRequest, body)
		case TypeKeyResponse:
			checkBodyRoundTrip[KeyResponse](t, TypeKeyResponse, body)
		case TypeSend:
			checkBodyRoundTrip[Send](t, TypeSend, body)
			if _, err := DecodeBody[Deliver](rawFrame(TypeSend, body), TypeSend); err == nil {
				t.Fatal("Deliver body accepted for Send frame")
			}
		case TypeSendResult:
			checkBodyRoundTrip[SendResult](t, TypeSendResult, body)
		case TypeDeliver:
			checkBodyRoundTrip[Deliver](t, TypeDeliver, body)
			checkBodyRoundTrip[*Deliver](t, TypeDeliver, body)
		case TypePrekeyUpload:
			checkBodyRoundTrip[PrekeyUpload](t, TypePrekeyUpload, body)
			checkBodyRoundTrip[*PrekeyUpload](t, TypePrekeyUpload, body)
		case TypePrekeyStatus:
			checkBodyRoundTrip[PrekeyStatus](t, TypePrekeyStatus, body)
		case TypePrekeyRequest:
			checkBodyRoundTrip[PrekeyRequest](t, TypePrekeyRequest, body)
			if _, err := DecodeBody[KeyRequest](rawFrame(TypePrekeyRequest, body), TypePrekeyRequest); err == nil {
				t.Fatal("KeyRequest body accepted for PrekeyRequest frame")
			}
		case TypePrekeyResponse:
			checkBodyRoundTrip[PrekeyResponse](t, TypePrekeyResponse, body)
		case TypeAck:
			checkBodyRoundTrip[Ack](t, TypeAck, body)
			checkBodyRoundTrip[*Ack](t, TypeAck, body)
		case TypeSendMulti:
			checkBodyRoundTrip[SendMulti](t, TypeSendMulti, body)
			checkBodyRoundTrip[*SendMulti](t, TypeSendMulti, body)
			if _, err := DecodeBody[Send](rawFrame(TypeSendMulti, body), TypeSendMulti); err == nil {
				t.Fatal("Send body accepted for SendMulti frame")
			}
		default:
			if _, err := DecodeBody[Pong](rawFrame(TypePing, body), TypePing); err == nil {
				t.Fatal("Pong body accepted for Ping frame")
			}
			_, _ = DecodeBody[any](rawFrame(FrameType(sel), body), FrameType(sel))
		}
	})
}
