package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

// sealedEntries returns n entries with distinct IDs and proofs.
func sealedEntries(n int) []SealedRecipient {
	ids := recipients(n)
	out := make([]SealedRecipient, n)
	for i, id := range ids {
		proof := bytes.Repeat([]byte{0x5a}, AccessVerifierSize)
		proof[0] = byte(i)
		out[i] = SealedRecipient{To: id, AccessProof: proof}
	}
	return out
}

func TestSealedRoundTrip(t *testing.T) {
	id, proof := filled(IDSize, 1), filled(AccessVerifierSize, 0x40)
	roundTrip(t, TypeSetAccessKey, 1, SetAccessKey{Verifier: proof})
	roundTrip(t, TypeSetAccessKey, 2, SetAccessKey{Verifier: proof, AllowUnidentified: true})
	roundTrip(t, TypeAccessKeySet, 2, AccessKeySet{})
	roundTrip(t, TypeSealedSend, 3, SealedSend{To: id, AccessProof: proof, Payload: []byte("sealed")})
	roundTrip(t, TypeSealedSend, 3, &SealedSend{To: id, AccessProof: proof, Payload: []byte{1}})
	roundTrip(t, TypeSealedSendMulti, 4, SealedSendMulti{Entries: sealedEntries(1), Payload: []byte("group")})
	roundTrip(t, TypeSealedSendMulti, 5, SealedSendMulti{Entries: sealedEntries(MaxMultiRecipients), Payload: []byte{9}})
}

// TestSealedMaxFits proves that the largest sealed requests, with the
// largest frame ID, fit within MaxFrameSize.
func TestSealedMaxFits(t *testing.T) {
	if MaxSealedMultiPayloadSize > MaxPayloadSize {
		t.Fatalf("MaxSealedMultiPayloadSize %d exceeds MaxPayloadSize %d", MaxSealedMultiPayloadSize, MaxPayloadSize)
	}
	multi := SealedSendMulti{Entries: sealedEntries(MaxMultiRecipients), Payload: bytes.Repeat([]byte{0xcd}, MaxSealedMultiPayloadSize)}
	single := SealedSend{To: filled(IDSize, 1), AccessProof: filled(AccessVerifierSize, 2), Payload: bytes.Repeat([]byte{0xcd}, MaxPayloadSize)}
	for _, frame := range []Frame{
		mustFrame(t, TypeSealedSendMulti, 1<<64-1, multi),
		mustFrame(t, TypeSealedSend, 1<<64-1, single),
	} {
		wire := mustEncode(t, frame)
		if len(wire) > MaxFrameSize {
			t.Fatalf("maximal %v frame is %d bytes, limit %d", frame.Type, len(wire), MaxFrameSize)
		}
		if _, err := Decode(wire); err != nil {
			t.Fatalf("Decode maximal %v: %v", frame.Type, err)
		}
	}
	roundTrip(t, TypeSealedSendMulti, 1<<64-1, multi)
}

// TestSealedGolden pins the wire format of the sealed sender frames.
func TestSealedGolden(t *testing.T) {
	id := hex.EncodeToString(filled(IDSize, 0))
	proof := hex.EncodeToString(filled(AccessVerifierSize, 0x20))
	tests := []struct {
		name  string
		frame Frame
		hex   string
	}{
		{
			name:  "SetAccessKey",
			frame: mustFrame(t, TypeSetAccessKey, 1, SetAccessKey{Verifier: filled(AccessVerifierSize, 0x20)}),
			hex:   "a4 01 01 02 18 18 03 01 04 58 24 a1 01 58 20" + proof,
		},
		{
			name:  "SetAccessKeyUnidentified",
			frame: mustFrame(t, TypeSetAccessKey, 1, SetAccessKey{Verifier: filled(AccessVerifierSize, 0x20), AllowUnidentified: true}),
			hex:   "a4 01 01 02 18 18 03 01 04 58 26 a2 01 58 20" + proof + "02 f5",
		},
		{
			name:  "AccessKeySet",
			frame: mustFrame(t, TypeAccessKeySet, 1, AccessKeySet{}),
			hex:   "a4 01 01 02 18 19 03 01 04 41 a0",
		},
		{
			name:  "SealedSend",
			frame: mustFrame(t, TypeSealedSend, 0, SealedSend{To: filled(IDSize, 0), AccessProof: filled(AccessVerifierSize, 0x20), Payload: []byte{0xaa}}),
			hex:   "a3 01 01 02 18 1a 04 58 4a a3 01 58 20" + id + "02 58 20" + proof + "03 41 aa",
		},
		{
			name: "SealedSendMulti",
			frame: mustFrame(t, TypeSealedSendMulti, 2, SealedSendMulti{
				Entries: []SealedRecipient{{To: filled(IDSize, 0), AccessProof: filled(AccessVerifierSize, 0x20)}},
				Payload: []byte{0x01},
			}),
			hex: "a4 01 01 02 18 1b 03 02 04 58 4d a2 01 81 a2 01 58 20" + id + "02 58 20" + proof + "02 41 01",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := mustHex(t, tc.hex)
			if got := mustEncode(t, tc.frame); !bytes.Equal(got, want) {
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

func TestSealedDecodeRejects(t *testing.T) {
	id, proof := filled(IDSize, 1), filled(AccessVerifierSize, 0x40)
	proofHex := hex.EncodeToString(proof)
	idHex := hex.EncodeToString(id)
	duplicate := sealedEntries(2)
	duplicate[1].To = duplicate[0].To
	shortProof := sealedEntries(1)
	shortProof[0].AccessProof = proof[:31]
	tests := []struct {
		name string
		err  error
	}{
		{"VerifierShort", decodeErr[SetAccessKey](TypeSetAccessKey, encodeLoose(t, SetAccessKey{Verifier: proof[:31]}))},
		{"VerifierMissing", decodeErr[SetAccessKey](TypeSetAccessKey, mustHex(t, "a0"))},
		{"ExplicitFalse", decodeErr[SetAccessKey](TypeSetAccessKey, mustHex(t, "a2 01 58 20"+proofHex+"02 f4"))},
		{"AllowNotBool", decodeErr[SetAccessKey](TypeSetAccessKey, mustHex(t, "a2 01 58 20"+proofHex+"02 01"))},
		{"AccessKeySetField", decodeErr[AccessKeySet](TypeAccessKeySet, mustHex(t, "a1 01 01"))},
		{"SendShortTo", decodeErr[SealedSend](TypeSealedSend, encodeLoose(t, SealedSend{To: id[:31], AccessProof: proof, Payload: []byte{1}}))},
		{"SendShortProof", decodeErr[SealedSend](TypeSealedSend, encodeLoose(t, SealedSend{To: id, AccessProof: proof[:1], Payload: []byte{1}}))},
		{"SendMissingProof", decodeErr[SealedSend](TypeSealedSend, mustHex(t, "a2 01 58 20"+idHex+"03 41 01"))},
		{"SendEmptyPayload", decodeErr[SealedSend](TypeSealedSend, encodeLoose(t, SealedSend{To: id, AccessProof: proof, Payload: []byte{}}))},
		{"SendHugePayload", decodeErr[SealedSend](TypeSealedSend, encodeLoose(t, SealedSend{To: id, AccessProof: proof, Payload: make([]byte, MaxPayloadSize+1)}))},
		{"SendExtraField", decodeErr[SealedSend](TypeSealedSend, mustHex(t, "a4 01 58 20"+idHex+"02 58 20"+proofHex+"03 41 01 04 00"))},
		{"MultiNoEntries", decodeErr[SealedSendMulti](TypeSealedSendMulti, encodeLoose(t, SealedSendMulti{Entries: []SealedRecipient{}, Payload: []byte{1}}))},
		{"MultiNullEntries", decodeErr[SealedSendMulti](TypeSealedSendMulti, mustHex(t, "a2 01 f6 02 41 01"))},
		{"MultiTooMany", decodeErr[SealedSendMulti](TypeSealedSendMulti, encodeLoose(t, SealedSendMulti{Entries: sealedEntries(MaxMultiRecipients + 1), Payload: []byte{1}}))},
		{"MultiDuplicate", decodeErr[SealedSendMulti](TypeSealedSendMulti, encodeLoose(t, SealedSendMulti{Entries: duplicate, Payload: []byte{1}}))},
		{"MultiShortProof", decodeErr[SealedSendMulti](TypeSealedSendMulti, encodeLoose(t, SealedSendMulti{Entries: shortProof, Payload: []byte{1}}))},
		{"MultiEntryExtraField", decodeErr[SealedSendMulti](TypeSealedSendMulti, mustHex(t, "a2 01 81 a3 01 58 20"+idHex+"02 58 20"+proofHex+"03 00 02 41 01"))},
		{"MultiEntryMissingProof", decodeErr[SealedSendMulti](TypeSealedSendMulti, mustHex(t, "a2 01 81 a1 01 58 20"+idHex+"02 41 01"))},
		{"MultiHugePayload", decodeErr[SealedSendMulti](TypeSealedSendMulti, encodeLoose(t, SealedSendMulti{Entries: sealedEntries(1), Payload: make([]byte, MaxSealedMultiPayloadSize+1)}))},
		{"MultiMissingPayload", decodeErr[SealedSendMulti](TypeSealedSendMulti, mustHex(t, "a1 01 81 a2 01 58 20"+idHex+"02 58 20"+proofHex))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", tc.err)
			}
		})
	}
}

func TestSealedBuildRejects(t *testing.T) {
	id, proof := filled(IDSize, 1), filled(AccessVerifierSize, 0x40)
	if err := buildErr(TypeSealedSendMulti, SealedSend{To: id, AccessProof: proof, Payload: []byte{1}}); !errors.Is(err, ErrUnexpectedType) {
		t.Fatalf("SealedSend body for SealedSendMulti: %v", err)
	}
	if err := buildErr(TypeSend, SealedSend{To: id, AccessProof: proof, Payload: []byte{1}}); !errors.Is(err, ErrUnexpectedType) {
		t.Fatalf("SealedSend body for Send: %v", err)
	}
	if err := buildErr(TypeSetAccessKey, SetAccessKey{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty SetAccessKey: %v", err)
	}
	if _, err := DecodeBody[Send](mustFrame(t, TypeSealedSend, 0, SealedSend{To: id, AccessProof: proof, Payload: []byte{1}}), TypeSealedSend); err == nil {
		t.Fatal("Send decoded a SealedSend body")
	}
}

func TestDeliverIsSealed(t *testing.T) {
	sealed := Deliver{From: make([]byte, IDSize), Payload: []byte{1}, QueueID: 1}
	if !sealed.IsSealed() {
		t.Fatal("zero From is not sealed")
	}
	roundTrip(t, TypeDeliver, 0, sealed)
	from := make([]byte, IDSize)
	from[IDSize-1] = 1
	if (Deliver{From: from, Payload: []byte{1}, QueueID: 1}).IsSealed() {
		t.Fatal("non-zero From is sealed")
	}
	if (Deliver{From: nil}).IsSealed() {
		t.Fatal("missing From is sealed")
	}
}
