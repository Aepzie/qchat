package ratchet

import (
	"bytes"
	"crypto/sha256"
	"math"

	"github.com/Aepzie/qchat/internal/crypto/sealbox"
	"github.com/fxamacker/cbor/v2"
)

// HeaderVersion is the only header version this package produces and accepts.
// Version 1 headers (without Salt) are rejected.
const HeaderVersion = 2

// TargetSize is the size of [Header.Target], a SHA-256 digest.
const TargetSize = sha256.Size

// SaltSize is the size of [Header.Salt].
const SaltSize = 16

// Header is the cleartext header sent with every ratchet message, encoded as
// canonical CBOR with integer keys. It is not encrypted (header encryption is
// a non-goal of Phase 3) but it is fully authenticated: its exact encoding is
// part of the AEAD associated data.
type Header struct {
	// Version is HeaderVersion.
	Version uint8 `cbor:"1,keyasint"`
	// Epoch numbers the sender's KEM epochs in this direction, starting at 1.
	Epoch uint32 `cbor:"2,keyasint"`
	// RatchetPub is the sender's current own ratchet public key
	// (sealbox.PublicKeySize bytes), which the recipient will encapsulate to
	// when it next starts an epoch.
	RatchetPub []byte `cbor:"3,keyasint"`
	// Target is SHA-256 of the recipient public key this epoch encapsulated
	// to. It tells the recipient which of its private keys to use.
	Target []byte `cbor:"4,keyasint"`
	// KEMCT is the epoch's encapsulation (sealbox.EncapsulatedKeySize bytes).
	// Every message of an epoch repeats it, so whichever message of the epoch
	// arrives first can start the epoch at the recipient.
	KEMCT []byte `cbor:"5,keyasint"`
	// PN is the number of messages the sender sent in its previous epoch.
	PN uint32 `cbor:"6,keyasint"`
	// N is the index of this message within its epoch, starting at 0. The
	// value math.MaxUint32 is never produced and is rejected, so that the
	// receiver's next-index counter cannot wrap.
	N uint32 `cbor:"7,keyasint"`
	// Salt is SaltSize fresh random bytes chosen for every message. It is the
	// HKDF salt of the message's AEAD key and nonce, so that a sender whose
	// state was rolled back, and which therefore uses a message key a second
	// time, still never reuses a key and nonce pair.
	Salt []byte `cbor:"8,keyasint"`
	// RecvEpoch is the sender's receiving epoch: the newest epoch of the
	// recipient's direction from which the sender has decrypted a message,
	// or 0. The recipient starts its next sending epoch only once the peer
	// has acknowledged the current one this way, so its epochs never get
	// more than one ahead of what the peer can decrypt.
	RecvEpoch uint32 `cbor:"9,keyasint"`
}

// encodeHeader returns the canonical encoding of h.
func encodeHeader(h Header) ([]byte, error) {
	return encMode.Marshal(h)
}

// ParseHeader decodes and validates an encoded header. It accepts only the
// canonical encoding produced by this package, so that the bytes covered by
// the AEAD are the only representation of a given header. All failures wrap
// [ErrMalformedHeader]. ParseHeader does not parse RatchetPub as a key; that
// costlier check happens only once a message has authenticated.
func ParseHeader(encoded []byte) (Header, error) {
	var h Header
	if len(encoded) > maxHeaderSize {
		return Header{}, ErrMalformedHeader
	}
	if err := headerDecMode.Unmarshal(encoded, &h); err != nil {
		return Header{}, ErrMalformedHeader
	}
	switch {
	case h.Version != HeaderVersion,
		h.Epoch == 0,
		h.N == math.MaxUint32,
		len(h.RatchetPub) != sealbox.PublicKeySize,
		len(h.Target) != TargetSize,
		len(h.KEMCT) != sealbox.EncapsulatedKeySize,
		len(h.Salt) != SaltSize:
		return Header{}, ErrMalformedHeader
	}
	canonical, err := encodeHeader(h)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Header{}, ErrMalformedHeader
	}
	return h, nil
}

// maxHeaderSize bounds the input ParseHeader will look at. A valid header is
// about 2.4 KiB; anything much larger is rejected before decoding.
const maxHeaderSize = 4096

var (
	// encMode produces Core Deterministic CBOR: shortest integer and length
	// encodings, sorted map keys, no indefinite-length items and no tags.
	encMode cbor.EncMode

	// headerDecMode is the strict decoder for headers, with limits mirroring
	// internal/protocol: no duplicate or unknown keys, no indefinite lengths,
	// no tags, small nesting and collection limits.
	headerDecMode cbor.DecMode

	// stateDecMode is the strict decoder for serialised states. It differs
	// from headerDecMode only in allowing arrays long enough for the stored
	// skipped message keys.
	stateDecMode cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.IndefLength = cbor.IndefLengthForbidden
	encOpts.TagsMd = cbor.TagsForbidden

	var err error
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic("ratchet: invalid CBOR encoding options: " + err.Error())
	}

	decOpts := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		BignumTag:         cbor.BignumTagForbidden,
		NaN:               cbor.NaNDecodeForbidden,
		Inf:               cbor.InfDecodeForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		MaxNestedLevels:   4,
		MaxArrayElements:  16,
		MaxMapPairs:       16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}
	headerDecMode, err = decOpts.DecMode()
	if err != nil {
		panic("ratchet: invalid CBOR header decoding options: " + err.Error())
	}

	decOpts.MaxArrayElements = MaxStoredSkipped + 24
	decOpts.MaxMapPairs = 32
	stateDecMode, err = decOpts.DecMode()
	if err != nil {
		panic("ratchet: invalid CBOR state decoding options: " + err.Error())
	}
}

// targetOf returns the Target value identifying pub.
func targetOf(pub *sealbox.PublicKey) [TargetSize]byte {
	return sha256.Sum256(pub.Bytes())
}
