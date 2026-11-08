package senderkey

import (
	"bytes"
	"errors"
	"testing"

	"github.com/craguS/qchat/internal/padding"
)

func TestMaxPaddedPlaintextSize(t *testing.T) {
	bucket, err := padding.BucketFor(MaxPlaintextSize)
	if err != nil || bucket != MaxPaddedPlaintextSize {
		t.Fatalf("BucketFor(MaxPlaintextSize) = %d, %v; MaxPaddedPlaintextSize = %d", bucket, err, MaxPaddedPlaintextSize)
	}
	if maxEnvelopeSize >= 256<<10 {
		t.Fatalf("maxEnvelopeSize %d does not fit the relay's default max_message_size", maxEnvelopeSize)
	}
}

func TestEnvelopeSizeHidesPlaintextLength(t *testing.T) {
	s, r := newPair(t)
	var sizes []int
	for _, n := range []int{1, 100, 400, padding.Buckets[0] - 1} {
		text := string(bytes.Repeat([]byte{'a'}, n))
		env := encrypt(t, s, text)
		mustDecrypt(t, r, env, text)
		sizes = append(sizes, len(env))
	}
	for _, size := range sizes[1:] {
		if size != sizes[0] {
			t.Fatalf("envelope sizes %v differ within one bucket", sizes)
		}
	}
	next := encrypt(t, s, string(bytes.Repeat([]byte{'a'}, padding.Buckets[0])))
	if len(next)-sizes[0] != padding.Buckets[1]-padding.Buckets[0] {
		t.Fatalf("envelope of the second bucket is %d bytes, first bucket %d", len(next), sizes[0])
	}

	big := bytes.Repeat([]byte{'a'}, MaxPlaintextSize)
	env, err := s.Encrypt(big, testEpoch, testBinding)
	if err != nil {
		t.Fatal(err)
	}
	if len(env) > maxEnvelopeSize {
		t.Fatalf("maximal envelope is %d bytes, limit %d", len(env), maxEnvelopeSize)
	}
	mustDecrypt(t, r, env, string(big))
}

func TestMalformedPaddingRejected(t *testing.T) {
	s, r := newPair(t)
	noMarker := make([]byte, padding.Buckets[0])
	copy(noMarker, "no marker")
	trailing := make([]byte, padding.Buckets[0])
	trailing[0] = 0x80
	trailing[len(trailing)-1] = 1
	for name, sealed := range map[string][]byte{
		"no marker":      noMarker,
		"trailing bytes": trailing,
	} {
		forged := forgeSealed(t, senderHeader(s), s.chain, s.headerKey, s.signing, sealed)
		if err := decryptErr(r, forged); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: error = %v, want ErrDecrypt", name, err)
		}
	}
	for _, size := range []int{1, 100, padding.Buckets[0] + 1} {
		forged := forgeSealed(t, senderHeader(s), s.chain, s.headerKey, s.signing, make([]byte, size))
		wantErr(t, decryptErr(r, forged), ErrMalformed)
		_, _, err := OpenHeader(forged, []HeaderCandidate{candidate(s)})
		wantErr(t, err, ErrMalformed)
	}
	if r.Iteration() != 0 || r.StoredSkipped() != 0 {
		t.Fatal("rejected padding changed the receiver")
	}
	mustDecrypt(t, r, encrypt(t, s, "genuine"), "genuine")
}

func TestIsPaddedCiphertextSize(t *testing.T) {
	const tag = 16
	for _, bucket := range padding.Buckets {
		want := bucket <= MaxPaddedPlaintextSize
		if got := isPaddedCiphertextSize(bucket + tag); got != want {
			t.Errorf("isPaddedCiphertextSize(%d + tag) = %v", bucket, got)
		}
		if isPaddedCiphertextSize(bucket+tag-1) || isPaddedCiphertextSize(bucket+tag+1) {
			t.Errorf("isPaddedCiphertextSize accepts a size next to bucket %d", bucket)
		}
	}
	for _, n := range []int{-1, 0, 1, tag, tag + 1} {
		if isPaddedCiphertextSize(n) {
			t.Errorf("isPaddedCiphertextSize(%d) = true", n)
		}
	}
}
