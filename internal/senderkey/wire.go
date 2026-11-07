package senderkey

import (
	"bytes"
	"encoding/binary"
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
	EnvelopeVersion = 4

	// HeaderVersion is the only group message header version this package
	// produces and accepts.
	HeaderVersion = 2

	// DistributionVersion is the only distribution message version this
	// package produces and accepts.
	DistributionVersion = 2

	// SaltSize is the size of the per-message header salt.
	SaltSize = 16

	// HeaderKeySize is the size of a generation's header key.
	HeaderKeySize = 32

	// HeaderNonceSize is the size of the random XChaCha20-Poly1305 nonce of
	// the encrypted header.
	HeaderNonceSize = chacha20poly1305.NonceSizeX

	// StateBindingSize is the size of the group state binding carried in
	// every header.
	StateBindingSize = 32

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
// fields, on whether a header key opened the header, on the signature, or on
// whether the commitment and the AEAD tag verified.
var (
	// ErrMalformed reports input that is not the canonical encoding of a
	// valid envelope, header or distribution message.
	ErrMalformed = errors.New("senderkey: malformed message")

	// ErrNoHeaderKey reports an envelope whose header opens under none of
	// the header keys tried: it belongs to a group, sender or generation
	// whose distribution the caller does not hold, or it is not genuine.
	ErrNoHeaderKey = errors.New("senderkey: no known header key opens the envelope")

	// ErrBadSignature reports an envelope whose signature does not verify
	// under the receiver's signing key for that generation.
	ErrBadSignature = errors.New("senderkey: bad signature")

	// ErrWrongGroup reports an envelope whose header, although it opened
	// under the receiver's header key, names another group. Only a holder of
	// that header key can produce one.
	ErrWrongGroup = errors.New("senderkey: envelope belongs to another group")

	// ErrWrongSender reports an envelope whose header names another sender
	// than the receiver's.
	ErrWrongSender = errors.New("senderkey: envelope from another sender")

	// ErrOldGeneration reports an envelope whose header names an older
	// generation than the receiver's.
	ErrOldGeneration = errors.New("senderkey: envelope of an old generation")

	// ErrUnknownGeneration reports an envelope whose header names a newer
	// generation than the receiver's.
	ErrUnknownGeneration = errors.New("senderkey: envelope of an unknown generation")

	// ErrFrozen reports an envelope at or beyond the chain position of a
	// frozen receiver: its generation has been superseded, so only messages
	// whose skipped keys are still stored can be decrypted.
	ErrFrozen = errors.New("senderkey: generation is frozen")

	// ErrTooManySkipped reports an envelope whose iteration is more than
	// MaxSkip ahead of the receiver's chain.
	ErrTooManySkipped = errors.New("senderkey: too many skipped messages")

	// ErrReplay reports an envelope whose message key is no longer held: it
	// was already decrypted, its skipped key was evicted or pruned, or it
	// precedes the iteration at which the receiver was created.
	ErrReplay = errors.New("senderkey: message key already used or unavailable")

	// ErrDecrypt reports that a correctly signed envelope failed the key
	// commitment check or AEAD authentication.
	ErrDecrypt = errors.New("senderkey: message authentication failed")

	// ErrPlaintextTooLarge reports a plaintext longer than MaxPlaintextSize.
	ErrPlaintextTooLarge = errors.New("senderkey: plaintext too large")

	// ErrChainExhausted reports a sender whose iteration counter cannot
	// advance any further; it must start a new generation.
	ErrChainExhausted = errors.New("senderkey: sender chain exhausted")

	// ErrInvalidState reports a serialised sender or receiver state that is
	// not canonical, is of another format version, or violates an invariant.
	ErrInvalidState = errors.New("senderkey: invalid serialised state")

	// ErrDestroyed reports use of a sender or receiver after Destroy.
	ErrDestroyed = errors.New("senderkey: state has been destroyed")

	// ErrInvalidArgument reports a zero group or member ID passed to a
	// constructor.
	ErrInvalidArgument = errors.New("senderkey: invalid argument")
)

// Sizes of the fixed-length header and its encryption.
const (
	// headerSize is the length of an encoded header:
	//
	//	Version(1) || GroupID(32) || Sender(32) || Generation(4) ||
	//	Iteration(4) || GroupEpoch(8) || StateBinding(32) || Salt(16) ||
	//	Commitment(32)
	//
	// with integers in big-endian order.
	headerSize = 1 + len(GroupID{}) + identity.IDSize + 4 + 4 + 8 + StateBindingSize + SaltSize + commitmentSize

	// encHeaderSize is the length of an encrypted header.
	encHeaderSize = headerSize + chacha20poly1305.Overhead
)

// Size bounds applied before decoding, so hostile input cannot make the
// decoder do work proportional to an unbounded length.
const (
	maxEnvelopeSize     = MaxPlaintextSize + chacha20poly1305.Overhead + hybridsig.SignatureSize + HeaderNonceSize + encHeaderSize + 32
	maxDistributionSize = hybridsig.PublicKeySize + HeaderKeySize + 128
)

// envelopeWire is the group envelope. Apart from the version, every field is
// random-looking or of a length that depends only on the plaintext length.
type envelopeWire struct {
	Version     uint8  `cbor:"1,keyasint"`
	HeaderNonce []byte `cbor:"2,keyasint"`
	EncHeader   []byte `cbor:"3,keyasint"`
	Ciphertext  []byte `cbor:"4,keyasint"`
	Sig         []byte `cbor:"5,keyasint"`
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
	HeaderKey  []byte `cbor:"8,keyasint"`
}

// Header is the decrypted header of a group envelope. It is authenticated
// only once [Receiver.Decrypt] has verified the signature; the result of
// [OpenHeader] is good for routing and nothing else.
type Header struct {
	// Group is the group the message was sent to.
	Group GroupID
	// Sender is the member that sent the message.
	Sender identity.ID
	// Generation is the sender key generation of the message.
	Generation uint32
	// Iteration is the chain index of the message.
	Iteration uint32
	// GroupEpoch is the group epoch the sender was at when it sent the
	// message.
	GroupEpoch uint64
	// StateBinding is the binding of the sender's group state when it sent
	// the message. Receivers compare it with their own state's binding to
	// detect a fork.
	StateBinding [StateBindingSize]byte
}

// header is a validated group message header.
type header struct {
	group      GroupID
	sender     identity.ID
	generation uint32
	iteration  uint32
	groupEpoch uint64
	binding    [StateBindingSize]byte
	salt       [SaltSize]byte
	commitment [commitmentSize]byte
}

// public returns the fields of h the caller may see.
func (h header) public() Header {
	return Header{
		Group:        h.group,
		Sender:       h.sender,
		Generation:   h.generation,
		Iteration:    h.iteration,
		GroupEpoch:   h.groupEpoch,
		StateBinding: h.binding,
	}
}

// envelope is a group envelope whose shape and sizes have been checked. Its
// header is still encrypted.
type envelope struct {
	nonce      []byte
	encHeader  []byte
	ciphertext []byte
	sig        []byte
}

// encodeHeader returns the fixed-length encoding of h. A fixed length keeps
// the size of the encrypted header independent of the generation, iteration
// and epoch, which a variable-length integer encoding would reveal.
func encodeHeader(h header) []byte {
	b := make([]byte, 0, headerSize)
	b = append(b, HeaderVersion)
	b = append(b, h.group[:]...)
	b = append(b, h.sender[:]...)
	b = binary.BigEndian.AppendUint32(b, h.generation)
	b = binary.BigEndian.AppendUint32(b, h.iteration)
	b = binary.BigEndian.AppendUint64(b, h.groupEpoch)
	b = append(b, h.binding[:]...)
	b = append(b, h.salt[:]...)
	return append(b, h.commitment[:]...)
}

// parseHeader decodes and validates a header. Every input of headerSize
// bytes with the right version encodes exactly one header and vice versa, so
// the encoding is canonical by construction. The iteration math.MaxUint32 is
// never produced and is rejected, so a receiver's next-iteration counter
// cannot wrap.
func parseHeader(encoded []byte) (header, error) {
	if len(encoded) != headerSize || encoded[0] != HeaderVersion {
		return header{}, ErrMalformed
	}
	var h header
	rest := encoded[1:]
	rest = rest[copy(h.group[:], rest):]
	rest = rest[copy(h.sender[:], rest):]
	h.generation = binary.BigEndian.Uint32(rest)
	h.iteration = binary.BigEndian.Uint32(rest[4:])
	h.groupEpoch = binary.BigEndian.Uint64(rest[8:])
	rest = rest[16:]
	rest = rest[copy(h.binding[:], rest):]
	rest = rest[copy(h.salt[:], rest):]
	copy(h.commitment[:], rest)
	if h.iteration == math.MaxUint32 {
		return header{}, ErrMalformed
	}
	return h, nil
}

// encodeEnvelope returns the canonical encoding of an envelope.
func encodeEnvelope(env envelope) ([]byte, error) {
	return encMode.Marshal(envelopeWire{
		Version:     EnvelopeVersion,
		HeaderNonce: env.nonce,
		EncHeader:   env.encHeader,
		Ciphertext:  env.ciphertext,
		Sig:         env.sig,
	})
}

// parseEnvelope decodes an envelope and checks its shape and sizes. It
// accepts only the canonical encoding and uses no key.
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
		len(w.HeaderNonce) != HeaderNonceSize,
		len(w.EncHeader) != encHeaderSize,
		len(w.Sig) != hybridsig.SignatureSize,
		len(w.Ciphertext) < chacha20poly1305.Overhead,
		len(w.Ciphertext) > MaxPlaintextSize+chacha20poly1305.Overhead:
		return envelope{}, ErrMalformed
	}
	canonical, err := encMode.Marshal(w)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return envelope{}, ErrMalformed
	}
	return envelope{nonce: w.HeaderNonce, encHeader: w.EncHeader, ciphertext: w.Ciphertext, sig: w.Sig}, nil
}

// envelopePrefix is how every canonical group envelope starts: a map of five
// pairs (0xa5) whose first key is 1 (0x01) with value EnvelopeVersion,
// followed by key 2 (0x02) and the head of a 24-byte byte string (0x58 0x18).
var envelopePrefix = []byte{0xa5, 0x01, EnvelopeVersion, 0x02, 0x58, HeaderNonceSize}

// IsGroupEnvelope reports whether b has the shape of a group envelope, as
// opposed to a pairwise envelope of internal/e2e (whose version is 2). It
// inspects only the first bytes, which are identical for every group
// envelope, so it reveals nothing beyond "this is a group message". It is
// meant for routing; a true result does not mean that b is well-formed.
// Envelopes of earlier group formats are not recognised.
func IsGroupEnvelope(b []byte) bool {
	return bytes.HasPrefix(b, envelopePrefix)
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
	headerKey  [HeaderKeySize]byte
	signingPub *hybridsig.PublicKey
}

// destroy clears the secrets of d.
func (d *distribution) destroy() {
	clear(d.chain[:])
	clear(d.headerKey[:])
}

// ParseDistribution validates a distribution message and returns its public
// metadata. It accepts only the canonical encoding. All failures are
// [ErrMalformed].
func ParseDistribution(encoded []byte) (DistributionInfo, error) {
	d, err := parseDistribution(encoded)
	if err != nil {
		return DistributionInfo{}, err
	}
	d.destroy()
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
	defer clear(w.HeaderKey)
	switch {
	case w.Version != DistributionVersion,
		len(w.GroupID) != len(GroupID{}),
		len(w.ChainKey) != keySize,
		len(w.HeaderKey) != HeaderKeySize,
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
	copy(d.headerKey[:], w.HeaderKey)
	d.signingPub = pub
	return d, nil
}

var (
	// encMode produces Core Deterministic CBOR: shortest integer and length
	// encodings, sorted map keys, no indefinite-length items and no tags.
	encMode cbor.EncMode

	// strictDecMode decodes envelopes, distribution messages and sender
	// states: no duplicate or unknown keys, no indefinite lengths, no tags,
	// small nesting and collection limits.
	strictDecMode cbor.DecMode

	// stateDecMode decodes receiver states. It differs from strictDecMode
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
