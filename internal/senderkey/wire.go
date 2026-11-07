package senderkey

import (
	"bytes"
	"errors"
	"math"
	"time"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/identity"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/chacha20poly1305"
)

// GroupID names a group. It is chosen at random by the group's creator.
type GroupID = [32]byte

// Format versions and protocol parameters.
const (
	// EnvelopeVersion is the top-level version of a group envelope. The
	// pairwise envelope of internal/e2e uses version 2, so the value alone
	// tells the two apart.
	EnvelopeVersion = 3

	// HeaderVersion is the only group message header version this package
	// produces and accepts.
	HeaderVersion = 1

	// DistributionVersion is the only distribution message version this
	// package produces and accepts.
	DistributionVersion = 1

	// SaltSize is the size of the per-message header salt.
	SaltSize = 16

	// MaxPlaintextSize is the largest plaintext Encrypt accepts and,
	// correspondingly, bounds the ciphertext Decrypt looks at.
	MaxPlaintextSize = 64 * 1024

	// MaxSkip is the largest number of message keys a single decryption may
	// skip over. It bounds the HMAC work a hostile or broken iteration
	// counter can cause.
	MaxSkip = 1000

	// MaxStoredSkipped is the largest number of skipped message keys a
	// receiver keeps. When more accumulate, the oldest are deleted and their
	// messages are lost; this bounds both memory and how many past message
	// keys a stolen receiving state exposes.
	MaxStoredSkipped = 1000

	// RotationMessages is the number of messages after which a sender should
	// start a new generation.
	RotationMessages = 1000

	// RotationAge is the age after which a sender should start a new
	// generation.
	RotationAge = 7 * 24 * time.Hour

	// MessageContext is the hybridsig context of envelope signatures. It
	// keeps group message signatures apart from every other use of hybrid
	// signatures in qchat.
	MessageContext = "qchat/v1/group-message"
)

// Errors returned by this package. Callers should compare with [errors.Is].
// None of them reveals anything secret: they depend only on public envelope
// fields, on the signature, or on whether the AEAD tag verified.
var (
	// ErrMalformed reports input that is not the canonical encoding of a
	// valid envelope, header or distribution message.
	ErrMalformed = errors.New("senderkey: malformed message")

	// ErrBadSignature reports an envelope whose signature does not verify
	// under the receiver's signing key for that generation.
	ErrBadSignature = errors.New("senderkey: bad signature")

	// ErrWrongGroup reports an envelope for another group.
	ErrWrongGroup = errors.New("senderkey: envelope belongs to another group")

	// ErrWrongSender reports an envelope from another sender.
	ErrWrongSender = errors.New("senderkey: envelope from another sender")

	// ErrOldGeneration reports an envelope of an older generation than the
	// receiver's.
	ErrOldGeneration = errors.New("senderkey: envelope of an old generation")

	// ErrUnknownGeneration reports an envelope of a newer generation than
	// the receiver's: its distribution message has not been received yet.
	ErrUnknownGeneration = errors.New("senderkey: envelope of an unknown generation")

	// ErrTooManySkipped reports an envelope whose iteration is more than
	// MaxSkip ahead of the receiver's chain.
	ErrTooManySkipped = errors.New("senderkey: too many skipped messages")

	// ErrReplay reports an envelope whose message key is no longer held: it
	// was already decrypted, its skipped key was evicted, or it precedes the
	// iteration at which the receiver was created.
	ErrReplay = errors.New("senderkey: message key already used or unavailable")

	// ErrDecrypt reports that a correctly signed envelope failed AEAD
	// authentication.
	ErrDecrypt = errors.New("senderkey: message authentication failed")

	// ErrPlaintextTooLarge reports a plaintext longer than MaxPlaintextSize.
	ErrPlaintextTooLarge = errors.New("senderkey: plaintext too large")

	// ErrChainExhausted reports a sender whose iteration counter cannot
	// advance any further; it must start a new generation.
	ErrChainExhausted = errors.New("senderkey: sender chain exhausted")

	// ErrInvalidState reports a serialised sender or receiver state that is
	// not canonical or violates an invariant.
	ErrInvalidState = errors.New("senderkey: invalid serialised state")

	// ErrDestroyed reports use of a sender or receiver after Destroy.
	ErrDestroyed = errors.New("senderkey: state has been destroyed")

	// ErrInvalidArgument reports a zero group or member ID passed to a
	// constructor.
	ErrInvalidArgument = errors.New("senderkey: invalid argument")
)

// Size bounds applied before decoding, so hostile input cannot make the
// decoder do work proportional to an unbounded length.
const (
	maxHeaderSize       = 128
	maxEnvelopeSize     = MaxPlaintextSize + chacha20poly1305.Overhead + hybridsig.SignatureSize + maxHeaderSize + 32
	maxDistributionSize = hybridsig.PublicKeySize + 128
)

// headerWire is the group message header: canonical CBOR with integer keys.
// Its exact encoding is the AEAD associated data and the first part of the
// signed payload.
type headerWire struct {
	Version    uint8  `cbor:"1,keyasint"`
	GroupID    []byte `cbor:"2,keyasint"`
	Sender     []byte `cbor:"3,keyasint"`
	Generation uint32 `cbor:"4,keyasint"`
	Iteration  uint32 `cbor:"5,keyasint"`
	Salt       []byte `cbor:"6,keyasint"`
}

// envelopeWire is the group envelope. Header holds the canonical header
// encoding as a byte string, so the receiver verifies and authenticates
// exactly the bytes the sender signed.
type envelopeWire struct {
	Version    uint8  `cbor:"1,keyasint"`
	Header     []byte `cbor:"2,keyasint"`
	Ciphertext []byte `cbor:"3,keyasint"`
	Sig        []byte `cbor:"4,keyasint"`
}

// distributionWire is the sender key distribution message.
type distributionWire struct {
	Version    uint8  `cbor:"1,keyasint"`
	GroupID    []byte `cbor:"2,keyasint"`
	Generation uint32 `cbor:"3,keyasint"`
	Iteration  uint32 `cbor:"4,keyasint"`
	ChainKey   []byte `cbor:"5,keyasint"`
	SigningPub []byte `cbor:"6,keyasint"`
	GroupEpoch uint64 `cbor:"7,keyasint"`
}

// header is a validated group message header.
type header struct {
	group      GroupID
	sender     identity.ID
	generation uint32
	iteration  uint32
	salt       [SaltSize]byte
}

// envelope is a validated group envelope with its parsed header.
type envelope struct {
	headerBytes []byte
	ciphertext  []byte
	sig         []byte
	header      header
}

// encodeHeader returns the canonical encoding of h.
func encodeHeader(h header) ([]byte, error) {
	return encMode.Marshal(headerWire{
		Version:    HeaderVersion,
		GroupID:    h.group[:],
		Sender:     h.sender[:],
		Generation: h.generation,
		Iteration:  h.iteration,
		Salt:       h.salt[:],
	})
}

// parseHeader decodes and validates a header, accepting only its canonical
// encoding so that the signed and authenticated bytes are the only
// representation of a given header. The iteration math.MaxUint32 is never
// produced and is rejected, so a receiver's next-iteration counter cannot
// wrap.
func parseHeader(encoded []byte) (header, error) {
	if len(encoded) > maxHeaderSize {
		return header{}, ErrMalformed
	}
	var w headerWire
	if err := strictDecMode.Unmarshal(encoded, &w); err != nil {
		return header{}, ErrMalformed
	}
	switch {
	case w.Version != HeaderVersion,
		len(w.GroupID) != len(GroupID{}),
		len(w.Sender) != identity.IDSize,
		len(w.Salt) != SaltSize,
		w.Iteration == math.MaxUint32:
		return header{}, ErrMalformed
	}
	canonical, err := encMode.Marshal(w)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return header{}, ErrMalformed
	}
	var h header
	copy(h.group[:], w.GroupID)
	copy(h.sender[:], w.Sender)
	h.generation = w.Generation
	h.iteration = w.Iteration
	copy(h.salt[:], w.Salt)
	return h, nil
}

// encodeEnvelope returns the canonical encoding of an envelope.
func encodeEnvelope(headerBytes, ciphertext, sig []byte) ([]byte, error) {
	return encMode.Marshal(envelopeWire{
		Version:    EnvelopeVersion,
		Header:     headerBytes,
		Ciphertext: ciphertext,
		Sig:        sig,
	})
}

// parseEnvelope decodes and validates an envelope and its header. It checks
// only shape and size; the signature is left to the receiver.
func parseEnvelope(encoded []byte) (envelope, error) {
	if len(encoded) > maxEnvelopeSize {
		return envelope{}, ErrMalformed
	}
	var w envelopeWire
	if err := strictDecMode.Unmarshal(encoded, &w); err != nil {
		return envelope{}, ErrMalformed
	}
	switch {
	case w.Version != EnvelopeVersion,
		len(w.Sig) != hybridsig.SignatureSize,
		len(w.Ciphertext) < chacha20poly1305.Overhead,
		len(w.Ciphertext) > MaxPlaintextSize+chacha20poly1305.Overhead:
		return envelope{}, ErrMalformed
	}
	h, err := parseHeader(w.Header)
	if err != nil {
		return envelope{}, err
	}
	canonical, err := encMode.Marshal(w)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return envelope{}, ErrMalformed
	}
	return envelope{headerBytes: w.Header, ciphertext: w.Ciphertext, sig: w.Sig, header: h}, nil
}

// envelopePrefix is how every canonical group envelope starts: a map of four
// pairs (0xa4) whose first key is 1 (0x01) with value EnvelopeVersion,
// followed by key 2 (0x02).
var envelopePrefix = []byte{0xa4, 0x01, EnvelopeVersion, 0x02}

// IsGroupEnvelope reports whether b has the shape of a group envelope, as
// opposed to a pairwise envelope of internal/e2e (whose version is 2). It
// only inspects the first bytes and is meant for routing; a true result does
// not mean that b is well-formed.
func IsGroupEnvelope(b []byte) bool {
	return bytes.HasPrefix(b, envelopePrefix)
}

// ParseEnvelopeHeader returns the routing fields of a group envelope without
// any keys, so the caller can find the [Receiver] for it. The fields are not
// authenticated until [Receiver.Decrypt] succeeds. All failures are
// [ErrMalformed].
func ParseEnvelopeHeader(encoded []byte) (group GroupID, sender identity.ID, generation, iteration uint32, err error) {
	env, err := parseEnvelope(encoded)
	if err != nil {
		return group, sender, 0, 0, err
	}
	h := env.header
	return h.group, h.sender, h.generation, h.iteration, nil
}

// DistributionInfo is the public metadata of a distribution message.
type DistributionInfo struct {
	// GroupID is the group the sender key belongs to.
	GroupID GroupID
	// Generation is the sender's key generation.
	Generation uint32
	// Iteration is the chain index the distributed chain key is at: the
	// first message the recipient will be able to decrypt.
	Iteration uint32
	// GroupEpoch is the group epoch the sender was at when it distributed
	// the key. Callers use it to reject generations that predate a removal.
	GroupEpoch uint64
}

// distribution is a validated distribution message.
type distribution struct {
	info       DistributionInfo
	chain      [keySize]byte
	signingPub *hybridsig.PublicKey
}

// ParseDistribution validates a distribution message and returns its public
// metadata. It accepts only the canonical encoding. All failures are
// [ErrMalformed].
func ParseDistribution(encoded []byte) (DistributionInfo, error) {
	d, err := parseDistribution(encoded)
	if err != nil {
		return DistributionInfo{}, err
	}
	clear(d.chain[:])
	return d.info, nil
}

// parseDistribution decodes and fully validates a distribution message,
// including the signing public key. A zero group ID is rejected because
// group IDs are random and the zero value marks "no group" elsewhere. The
// iteration math.MaxUint32 is rejected because no header can carry it.
func parseDistribution(encoded []byte) (distribution, error) {
	if len(encoded) > maxDistributionSize {
		return distribution{}, ErrMalformed
	}
	var w distributionWire
	if err := strictDecMode.Unmarshal(encoded, &w); err != nil {
		return distribution{}, ErrMalformed
	}
	defer clear(w.ChainKey)
	switch {
	case w.Version != DistributionVersion,
		len(w.GroupID) != len(GroupID{}),
		len(w.ChainKey) != keySize,
		len(w.SigningPub) != hybridsig.PublicKeySize,
		w.Iteration == math.MaxUint32:
		return distribution{}, ErrMalformed
	}
	var d distribution
	copy(d.info.GroupID[:], w.GroupID)
	if d.info.GroupID == (GroupID{}) {
		return distribution{}, ErrMalformed
	}
	canonical, err := encMode.Marshal(w)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		return distribution{}, ErrMalformed
	}
	clear(canonical)
	pub, err := hybridsig.ParsePublicKey(w.SigningPub)
	if err != nil {
		return distribution{}, ErrMalformed
	}
	d.info.Generation = w.Generation
	d.info.Iteration = w.Iteration
	d.info.GroupEpoch = w.GroupEpoch
	copy(d.chain[:], w.ChainKey)
	d.signingPub = pub
	return d, nil
}

var (
	// encMode produces Core Deterministic CBOR: shortest integer and length
	// encodings, sorted map keys, no indefinite-length items and no tags.
	encMode cbor.EncMode

	// strictDecMode decodes envelopes, headers and distribution messages: no
	// duplicate or unknown keys, no indefinite lengths, no tags, small
	// nesting and collection limits.
	strictDecMode cbor.DecMode

	// stateDecMode decodes serialised states. It differs from strictDecMode
	// only in allowing arrays long enough for the stored skipped keys.
	stateDecMode cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.IndefLength = cbor.IndefLengthForbidden
	encOpts.TagsMd = cbor.TagsForbidden

	var err error
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic("senderkey: invalid CBOR encoding options: " + err.Error())
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
	strictDecMode, err = decOpts.DecMode()
	if err != nil {
		panic("senderkey: invalid CBOR decoding options: " + err.Error())
	}

	decOpts.MaxArrayElements = MaxStoredSkipped + 16
	stateDecMode, err = decOpts.DecMode()
	if err != nil {
		panic("senderkey: invalid CBOR state decoding options: " + err.Error())
	}
}
