package e2e

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/identity"
)

var testNow = time.UnixMilli(1750000000123)

type party struct {
	identity *identity.Identity
	bundle   *identity.Bundle
}

func newParty(t testing.TB) party {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Destroy)
	raw, err := id.Bundle(1, testNow)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := identity.ParseBundleForID(raw, id.ID())
	if err != nil {
		t.Fatal(err)
	}
	return party{identity: id, bundle: bundle}
}

// directory returns a lookup function that knows exactly the given parties.
func directory(parties ...party) func(identity.ID) (*identity.Bundle, error) {
	return func(id identity.ID) (*identity.Bundle, error) {
		for _, p := range parties {
			if p.bundle.ID == id {
				return p.bundle, nil
			}
		}
		return nil, errors.New("not found")
	}
}

// craft returns a well-formed Inner from sender to recipient.
func craft(from, to identity.ID) inner {
	return inner{
		Version: Version,
		From:    from[:],
		To:      to[:],
		MsgID:   bytes.Repeat([]byte{7}, MsgIDSize),
		Sent:    testNow.UnixMilli(),
		Kind:    uint8(KindText),
		Body:    []byte("crafted"),
	}
}

func TestRoundTrip(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	payload, msgID, err := Seal(alice.identity, bob.bundle, KindText, []byte("hello, bob ✓"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > MaxPayloadSize {
		t.Fatalf("payload of %d bytes exceeds MaxPayloadSize", len(payload))
	}
	msg, err := Open(bob.identity, alice.identity.ID(), payload, directory(alice), testNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if msg.From != alice.identity.ID() || msg.To != bob.identity.ID() || msg.MsgID != msgID ||
		!msg.Sent.Equal(testNow) || msg.Kind != KindText || string(msg.Body) != "hello, bob ✓" || msg.ClockSkew {
		t.Errorf("message = %+v", msg)
	}

	_, other, err := Seal(alice.identity, bob.bundle, KindText, []byte("again"), testNow)
	if err != nil || other == msgID {
		t.Errorf("message IDs are not random: %v", err)
	}
}

func TestMaximalBody(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	body := []byte(strings.Repeat("€", MaxBodySize/3) + strings.Repeat("a", MaxBodySize%3))
	payload, _, err := Seal(alice.identity, bob.bundle, KindText, body, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > MaxPayloadSize {
		t.Fatalf("maximal payload %d exceeds MaxPayloadSize %d", len(payload), MaxPayloadSize)
	}
	msg, err := Open(bob.identity, alice.identity.ID(), payload, directory(alice), testNow)
	if err != nil || !bytes.Equal(msg.Body, body) {
		t.Fatalf("maximal body: %v", err)
	}
}

func TestSealRejects(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	forged := *bob.bundle
	forged.ID = alice.bundle.ID
	cases := []struct {
		name string
		to   *identity.Bundle
		kind Kind
		body []byte
	}{
		{"oversize body", bob.bundle, KindText, make([]byte, MaxBodySize+1)},
		{"empty body", bob.bundle, KindText, nil},
		{"invalid UTF-8", bob.bundle, KindText, []byte{0xff, 0xfe}},
		{"unknown kind", bob.bundle, 2, []byte("x")},
		{"nil recipient", nil, KindText, []byte("x")},
		{"bundle ID disagrees with key", &forged, KindText, []byte("x")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Seal(alice.identity, tc.to, tc.kind, tc.body, testNow); !errors.Is(err, ErrInvalidMessage) {
				t.Errorf("err = %v, want ErrInvalidMessage", err)
			}
		})
	}
}

func TestOpenErrors(t *testing.T) {
	alice, bob, carol, mallory := newParty(t), newParty(t), newParty(t), newParty(t)
	aliceID, bobID, carolID := alice.identity.ID(), bob.identity.ID(), carol.identity.ID()
	everyone := directory(alice, bob, carol, mallory)

	valid, _, err := Seal(alice.identity, bob.bundle, KindText, []byte("hi"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	toCarol, _, err := Seal(alice.identity, carol.bundle, KindText, []byte("hi"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)/2] ^= 1

	mustSeal := func(signer party, in inner, info []byte) []byte {
		t.Helper()
		payload, err := sealInner(signer.identity, in, bob.bundle.KEMKey, info)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}

	// Sealed for Alice->Bob, but the signed Inner names Carol as recipient.
	notForMe := mustSeal(alice, craft(aliceID, carolID), messageInfo(aliceID, bobID))
	// Sealed under Alice->Bob, but the signed Inner claims Carol as sender.
	senderMismatch := mustSeal(carol, craft(carolID, bobID), messageInfo(aliceID, bobID))
	// Mallory claims to be Alice and signs with her own key.
	forgedSig := mustSeal(mallory, craft(aliceID, bobID), messageInfo(aliceID, bobID))
	// Valid HPKE box around a plaintext that is not an Inner.
	notCBOR := sealRaw(t, bob, messageInfo(aliceID, bobID), []byte("not cbor"))
	wrongKind := craft(aliceID, bobID)
	wrongKind.Kind = 9
	badUTF8 := craft(aliceID, bobID)
	badUTF8.Body = []byte{0xc3}
	shortMsgID := craft(aliceID, bobID)
	shortMsgID.MsgID = shortMsgID.MsgID[1:]
	newerVersion := craft(aliceID, bobID)
	newerVersion.Version = 2

	cases := []struct {
		name      string
		relayFrom identity.ID
		payload   []byte
		lookup    func(identity.ID) (*identity.Bundle, error)
		want      error
	}{
		{"tampered payload", aliceID, tampered, everyone, ErrDecrypt},
		{"truncated payload", aliceID, valid[:100], everyone, ErrDecrypt},
		{"sealed to another recipient", aliceID, toCarol, everyone, ErrDecrypt},
		{"relay misreports sender", carolID, valid, everyone, ErrDecrypt},
		{"oversize payload", aliceID, make([]byte, MaxPayloadSize+1), everyone, ErrMalformed},
		{"signed recipient is someone else", aliceID, notForMe, everyone, ErrNotForMe},
		{"signed sender differs from relay sender", aliceID, senderMismatch, everyone, ErrSenderMismatch},
		{"signature by another key with matching From", aliceID, forgedSig, everyone, ErrBadSignature},
		{"unknown sender", aliceID, valid, directory(bob, carol), ErrUnknownSender},
		{"lookup returns wrong bundle", aliceID, valid, func(identity.ID) (*identity.Bundle, error) { return mallory.bundle, nil }, ErrUnknownSender},
		{"lookup returns nil", aliceID, valid, func(identity.ID) (*identity.Bundle, error) { return nil, nil }, ErrUnknownSender},
		{"plaintext not CBOR", aliceID, notCBOR, everyone, ErrMalformed},
		{"unknown kind", aliceID, mustSeal(alice, wrongKind, messageInfo(aliceID, bobID)), everyone, ErrMalformed},
		{"invalid UTF-8", aliceID, mustSeal(alice, badUTF8, messageInfo(aliceID, bobID)), everyone, ErrMalformed},
		{"short message ID", aliceID, mustSeal(alice, shortMsgID, messageInfo(aliceID, bobID)), everyone, ErrMalformed},
		{"newer version", aliceID, mustSeal(alice, newerVersion, messageInfo(aliceID, bobID)), everyone, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := Open(bob.identity, tc.relayFrom, tc.payload, tc.lookup, testNow)
			if !errors.Is(err, tc.want) || msg != nil {
				t.Errorf("Open = %v, %v; want nil, %v", msg, err, tc.want)
			}
		})
	}

	if _, err := Open(bob.identity, aliceID, valid, everyone, testNow); err != nil {
		t.Errorf("valid payload rejected after the error cases: %v", err)
	}
}

func sealRaw(t *testing.T, to party, info, plaintext []byte) []byte {
	t.Helper()
	payload, err := sealbox.Seal(to.bundle.KEMKey, info, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestClockSkew(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	payload, _, err := Seal(alice.identity, bob.bundle, KindText, []byte("tick"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		offset time.Duration
		skew   bool
	}{
		{0, false},
		{ClockSkewTolerance, false},
		{-ClockSkewTolerance, false},
		{ClockSkewTolerance + time.Millisecond, true},
		{-ClockSkewTolerance - time.Millisecond, true},
		{25 * time.Hour, true},
	}
	for _, tc := range cases {
		msg, err := Open(bob.identity, alice.identity.ID(), payload, directory(alice), testNow.Add(tc.offset))
		if err != nil {
			t.Fatal(err)
		}
		if msg.ClockSkew != tc.skew {
			t.Errorf("offset %v: ClockSkew = %v, want %v", tc.offset, msg.ClockSkew, tc.skew)
		}
	}
}

func TestOpenAfterDestroy(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	payload, _, err := Seal(alice.identity, bob.bundle, KindText, []byte("x"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	bob.identity.Destroy()
	if _, err := Open(bob.identity, alice.identity.ID(), payload, directory(alice), testNow); !errors.Is(err, identity.ErrDestroyed) {
		t.Errorf("err = %v, want ErrDestroyed", err)
	}
}
