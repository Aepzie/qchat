package handshake

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/prekey"
)

// Protocol constants.
const (
	// InitVersion is the format version of the Init header.
	InitVersion = 1

	// ContextSessionInit labels the sender's signature over an Init header.
	ContextSessionInit = "qchat/v1/session-init"

	// transcriptLabel starts the transcript string T.
	transcriptLabel = "qchat/v1/session"

	// SessionKeySize is the size of SK.
	SessionKeySize = 32

	// MaxInitSize is the largest encoded Init header [Accept] processes:
	// a maximal sender bundle, three encapsulations, one signature and
	// generous room for the CBOR framing and key IDs. Larger input is
	// rejected before it is decoded.
	MaxInitSize = identity.MaxBundleSize + 3*sealbox.EncapsulatedKeySize + hybridsig.SignatureSize + 64
)

// Errors returned by this package. Callers compare with [errors.Is].
var (
	// ErrMalformed reports an Init header that is not exactly in the
	// canonical version 1 format, has fields of the wrong size or an
	// inconsistent one-time prekey (OPKID and EncOPK must be both present
	// or both absent), or carries a sender bundle that does not parse.
	ErrMalformed = errors.New("handshake: malformed init")

	// ErrWrongSender reports an Init whose sender bundle is valid but
	// belongs to a different identity than the relay-reported sender.
	ErrWrongSender = errors.New("handshake: init sender differs from relay-reported sender")

	// ErrBadSignature reports an Init whose signature does not verify under
	// the sender's signing key for this recipient. An Init addressed to
	// another recipient fails this way, since the recipient ID is part of
	// the signed message.
	ErrBadSignature = errors.New("handshake: init signature does not verify")

	// ErrUnknownPrekey reports an Init naming a prekey the recipient does
	// not hold (never had, or already deleted). For a one-time prekey this
	// is the normal outcome of a replayed or duplicated session start.
	ErrUnknownPrekey = errors.New("handshake: unknown or deleted prekey")

	// ErrInvalidArgument reports an argument outside its documented range.
	ErrInvalidArgument = errors.New("handshake: invalid argument")
)

// Signer is the part of a private identity that [Initiate] needs. The
// method signs under the fixed label [ContextSessionInit], so no caller can
// make the identity sign Init bytes under another label, or arbitrary bytes
// under this one. *identity.Identity is intended to implement it.
type Signer interface {
	ID() identity.ID
	SignSessionInit(tbs []byte) ([]byte, error)
}

// Decapsulator is the part of a private identity that [Accept] needs:
// decapsulation with the identity's long-term KEM key under the given info
// string, as sealbox.Decapsulate. *identity.Identity is intended to
// implement it.
type Decapsulator interface {
	ID() identity.ID
	Decapsulate(enc, info []byte) ([sealbox.SharedSecretSize]byte, error)
}

// Bundle is a verified prekey bundle of a peer, as returned by
// [ParseBundle]. OneTime is nil when the relay had no one-time prekey left.
type Bundle struct {
	Identity     *identity.Bundle
	SignedPrekey *prekey.SignedPrekey
	OneTime      *prekey.OneTimePrekey
}

// ParseBundle verifies a relay-provided prekey bundle of the identity want:
// identityBundle with identity.ParseBundleForID (so the relay cannot
// substitute keys), the signed prekey against it at now (owner, signature,
// validity period) and, if opk is non-empty, the one-time prekey. Errors are
// those of identity.ParseBundleForID, prekey.ParseSignedPrekey and
// prekey.ParseOneTimePrekey.
func ParseBundle(want identity.ID, identityBundle, spk, opk []byte, now time.Time) (*Bundle, error) {
	owner, err := identity.ParseBundleForID(identityBundle, want)
	if err != nil {
		return nil, fmt.Errorf("handshake: identity bundle: %w", err)
	}
	signed, err := prekey.ParseSignedPrekey(spk, owner, now)
	if err != nil {
		return nil, fmt.Errorf("handshake: signed prekey: %w", err)
	}
	bundle := &Bundle{Identity: owner, SignedPrekey: signed}
	if len(opk) == 0 {
		return bundle, nil
	}
	if bundle.OneTime, err = prekey.ParseOneTimePrekey(opk, owner); err != nil {
		return nil, fmt.Errorf("handshake: one-time prekey: %w", err)
	}
	return bundle, nil
}

// Initiation is the initiator's result of a session start.
type Initiation struct {
	// SK is the session key, input to the ratchet. The caller should
	// clear it once the ratchet state has been derived.
	SK [SessionKeySize]byte

	// Init is the encoded, signed Init header. It is sent with every
	// message until the initiator has received a message on this session.
	Init []byte

	// PeerInitialPub is the peer's signed prekey public key, the target of
	// the initiator's first ratchet epoch.
	PeerInitialPub *sealbox.PublicKey

	// SPKID and OPKID name the prekeys used; OPKID is 0 when none.
	SPKID, OPKID uint32
}

// Accepted is the recipient's result of a session start.
type Accepted struct {
	// SK is the session key. It is NOT yet confirmed: see the package
	// documentation.
	SK [SessionKeySize]byte

	// Sender is the verified identity bundle of the initiator, taken from
	// the Init header. Its ID equals the relay-reported sender.
	Sender *identity.Bundle

	// SPKID and OPKID name the recipient's prekeys that were used; OPKID is
	// 0 when none. After the first message of this session has been
	// decrypted, the caller MUST delete the one-time private key OPKID.
	SPKID, OPKID uint32
}

// initTBS holds fields 1 to 7 of an Init header.
type initTBS struct {
	Version      uint8  `cbor:"1,keyasint"`
	SenderBundle []byte `cbor:"2,keyasint"`
	SPKID        uint32 `cbor:"3,keyasint"`
	OPKID        uint32 `cbor:"4,keyasint"`
	EncIK        []byte `cbor:"5,keyasint"`
	EncSPK       []byte `cbor:"6,keyasint"`
	EncOPK       []byte `cbor:"7,keyasint,omitempty"`
}

// initWire is the complete encoded Init header, fields 1 to 8.
type initWire struct {
	Version      uint8  `cbor:"1,keyasint"`
	SenderBundle []byte `cbor:"2,keyasint"`
	SPKID        uint32 `cbor:"3,keyasint"`
	OPKID        uint32 `cbor:"4,keyasint"`
	EncIK        []byte `cbor:"5,keyasint"`
	EncSPK       []byte `cbor:"6,keyasint"`
	EncOPK       []byte `cbor:"7,keyasint,omitempty"`
	Sig          []byte `cbor:"8,keyasint"`
}

func (w *initWire) tbs() initTBS {
	return initTBS{
		Version: w.Version, SenderBundle: w.SenderBundle, SPKID: w.SPKID, OPKID: w.OPKID,
		EncIK: w.EncIK, EncSPK: w.EncSPK, EncOPK: w.EncOPK,
	}
}

// signedMessage returns CBOR(fields 1..7) || recipient, the message the
// Init signature covers.
func (w *initWire) signedMessage(recipient identity.ID) ([]byte, error) {
	tbs, err := encMode.Marshal(w.tbs())
	if err != nil {
		return nil, err
	}
	return append(tbs, recipient[:]...), nil
}

// Initiate starts a session from self to peer. selfBundle is self's own
// encoded identity bundle, exactly as registered with the relay; it is sent
// in the Init header so that the recipient can verify the signature without
// a lookup, and it must belong to self.
//
// peer must come from [ParseBundle]; Initiate trusts its contents.
func Initiate(self Signer, selfBundle []byte, peer *Bundle) (*Initiation, error) {
	if self == nil || peer == nil || peer.Identity == nil || peer.Identity.KEMKey == nil ||
		peer.SignedPrekey == nil || peer.SignedPrekey.Pub == nil || (peer.OneTime != nil && peer.OneTime.Pub == nil) {
		return nil, fmt.Errorf("%w: incomplete arguments", ErrInvalidArgument)
	}
	selfID, peerID := self.ID(), peer.Identity.ID
	if selfID == peerID {
		return nil, fmt.Errorf("%w: cannot start a session with oneself", ErrInvalidArgument)
	}
	if _, err := identity.ParseBundleForID(selfBundle, selfID); err != nil {
		return nil, fmt.Errorf("%w: own bundle: %w", ErrInvalidArgument, err)
	}
	if peer.SignedPrekey.Owner != peerID || (peer.OneTime != nil && peer.OneTime.Owner != peerID) {
		return nil, fmt.Errorf("%w: prekeys of another identity", ErrInvalidArgument)
	}

	spkID := peer.SignedPrekey.KeyID
	var opkID uint32
	if peer.OneTime != nil {
		opkID = peer.OneTime.KeyID
	}
	t := transcript(selfID, peerID, spkID, opkID)

	targets := []*sealbox.PublicKey{peer.Identity.KEMKey, peer.SignedPrekey.Pub}
	if peer.OneTime != nil {
		targets = append(targets, peer.OneTime.Pub)
	}
	encs := make([][]byte, 0, len(targets))
	secrets := make([][sealbox.SharedSecretSize]byte, 0, len(targets))
	defer func() {
		for i := range secrets {
			clear(secrets[i][:])
		}
	}()
	for _, target := range targets {
		enc, secret, err := sealbox.Encapsulate(target, t)
		if err != nil {
			return nil, fmt.Errorf("handshake: encapsulating: %w", err)
		}
		encs = append(encs, enc)
		secrets = append(secrets, secret)
	}

	wire := initWire{
		Version:      InitVersion,
		SenderBundle: bytes.Clone(selfBundle),
		SPKID:        spkID,
		OPKID:        opkID,
		EncIK:        encs[0],
		EncSPK:       encs[1],
	}
	if opkID != 0 {
		wire.EncOPK = encs[2]
	}
	msg, err := wire.signedMessage(peerID)
	if err != nil {
		return nil, fmt.Errorf("handshake: encoding init: %w", err)
	}
	if wire.Sig, err = self.SignSessionInit(msg); err != nil {
		return nil, fmt.Errorf("handshake: signing init: %w", err)
	}
	encoded, err := encMode.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("handshake: encoding init: %w", err)
	}
	sk, err := deriveSK(t, secrets, encs)
	if err != nil {
		return nil, err
	}
	return &Initiation{SK: sk, Init: encoded, PeerInitialPub: peer.SignedPrekey.Pub, SPKID: spkID, OPKID: opkID}, nil
}

// Accept processes an Init header received from the relay on behalf of the
// relay-authenticated sender relayFrom and derives the session key.
//
// spk and opk look up the recipient's own private prekeys by key ID. They
// must return an error (or a nil key) for an ID that is unknown, and opk
// must also do so for a one-time prekey that has already been deleted;
// that is what rejects a replayed session start. opk is not called when
// the Init names no one-time prekey.
//
// The checks run cheapest and least revealing first: size; exact canonical
// encoding and field sizes; the sender bundle parses and its ID equals
// relayFrom ([ErrWrongSender]); the signature over fields 1 to 7 and
// self's ID verifies ([ErrBadSignature]). Only then are the prekeys looked
// up ([ErrUnknownPrekey]) and decapsulated, so unauthenticated input can
// neither probe which prekeys exist nor cost private-key operations.
//
// Accept does not delete anything. The caller MUST delete the one-time
// private key OPKID itself, after (and only after) the first message of
// the session has been decrypted with a key derived from SK; see the
// package documentation.
func Accept(self Decapsulator, relayFrom identity.ID, init []byte,
	spk func(uint32) (*sealbox.PrivateKey, error), opk func(uint32) (*sealbox.PrivateKey, error),
) (*Accepted, error) {
	if self == nil || spk == nil || opk == nil {
		return nil, fmt.Errorf("%w: nil argument", ErrInvalidArgument)
	}
	if len(init) == 0 || len(init) > MaxInitSize {
		return nil, fmt.Errorf("%w: size %d out of range", ErrMalformed, len(init))
	}
	var wire initWire
	if err := decodeCanonical(init, &wire); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := wire.check(); err != nil {
		return nil, err
	}
	selfID := self.ID()
	sender, err := identity.ParseBundleForID(wire.SenderBundle, relayFrom)
	if errors.Is(err, identity.ErrIDMismatch) {
		return nil, ErrWrongSender
	}
	if err != nil {
		return nil, fmt.Errorf("%w: sender bundle: %w", ErrMalformed, err)
	}
	if sender.ID == selfID {
		return nil, fmt.Errorf("%w: init from oneself", ErrMalformed)
	}
	msg, err := wire.signedMessage(selfID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := sender.SigningKey.Verify(ContextSessionInit, msg, wire.Sig); err != nil {
		return nil, ErrBadSignature
	}

	spkPriv, err := lookup(spk, wire.SPKID, "signed")
	if err != nil {
		return nil, err
	}
	var opkPriv *sealbox.PrivateKey
	if wire.OPKID != 0 {
		if opkPriv, err = lookup(opk, wire.OPKID, "one-time"); err != nil {
			return nil, err
		}
	}

	t := transcript(sender.ID, selfID, wire.SPKID, wire.OPKID)
	encs := [][]byte{wire.EncIK, wire.EncSPK}
	secrets := make([][sealbox.SharedSecretSize]byte, 0, 3)
	defer func() {
		for i := range secrets {
			clear(secrets[i][:])
		}
	}()
	ssIK, err := self.Decapsulate(wire.EncIK, t)
	if err != nil {
		return nil, fmt.Errorf("handshake: decapsulating identity encapsulation: %w", err)
	}
	secrets = append(secrets, ssIK)
	clear(ssIK[:])
	ssSPK, err := sealbox.Decapsulate(spkPriv, wire.EncSPK, t)
	if err != nil {
		return nil, fmt.Errorf("handshake: decapsulating signed prekey encapsulation: %w", err)
	}
	secrets = append(secrets, ssSPK)
	clear(ssSPK[:])
	if opkPriv != nil {
		ssOPK, err := sealbox.Decapsulate(opkPriv, wire.EncOPK, t)
		if err != nil {
			return nil, fmt.Errorf("handshake: decapsulating one-time prekey encapsulation: %w", err)
		}
		secrets = append(secrets, ssOPK)
		clear(ssOPK[:])
		encs = append(encs, wire.EncOPK)
	}
	sk, err := deriveSK(t, secrets, encs)
	if err != nil {
		return nil, err
	}
	return &Accepted{SK: sk, Sender: sender, SPKID: wire.SPKID, OPKID: wire.OPKID}, nil
}

// check validates field sizes and the consistency of the one-time prekey
// fields of a decoded Init, before any expensive work.
func (w *initWire) check() error {
	if w.Version != InitVersion {
		return fmt.Errorf("%w: version %d", ErrMalformed, w.Version)
	}
	if len(w.SenderBundle) == 0 || len(w.SenderBundle) > identity.MaxBundleSize ||
		len(w.EncIK) != sealbox.EncapsulatedKeySize || len(w.EncSPK) != sealbox.EncapsulatedKeySize ||
		len(w.Sig) != hybridsig.SignatureSize {
		return fmt.Errorf("%w: field of wrong size", ErrMalformed)
	}
	if w.SPKID == 0 {
		return fmt.Errorf("%w: zero signed prekey ID", ErrMalformed)
	}
	if w.OPKID == 0 && w.EncOPK != nil {
		return fmt.Errorf("%w: one-time encapsulation without one-time prekey", ErrMalformed)
	}
	if w.OPKID != 0 && len(w.EncOPK) != sealbox.EncapsulatedKeySize {
		return fmt.Errorf("%w: missing or wrong-size one-time encapsulation", ErrMalformed)
	}
	return nil
}

// lookup calls a prekey lookup function and normalises its failures to
// [ErrUnknownPrekey].
func lookup(find func(uint32) (*sealbox.PrivateKey, error), keyID uint32, kind string) (*sealbox.PrivateKey, error) {
	priv, err := find(keyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s prekey %d: %w", ErrUnknownPrekey, kind, keyID, err)
	}
	if priv == nil {
		return nil, fmt.Errorf("%w: %s prekey %d", ErrUnknownPrekey, kind, keyID)
	}
	return priv, nil
}

// transcript returns T = "qchat/v1/session" || initiator || recipient ||
// u32(spkID) || u32(opkID), with big-endian key IDs. It is the HPKE info of
// all three encapsulations and the prefix of the HKDF info, binding every
// shared secret to both identities and both prekey choices.
func transcript(initiator, recipient identity.ID, spkID, opkID uint32) []byte {
	t := make([]byte, 0, len(transcriptLabel)+2*identity.IDSize+8)
	t = append(t, transcriptLabel...)
	t = append(t, initiator[:]...)
	t = append(t, recipient[:]...)
	t = binary.BigEndian.AppendUint32(t, spkID)
	t = binary.BigEndian.AppendUint32(t, opkID)
	return t
}

// deriveSK is the key combiner:
//
//	SK = HKDF-SHA256(salt = 32 zero bytes, ikm = ss_1 || ... || ss_n,
//	                 info = T || SHA-256(enc_1 || ... || enc_n))
//
// with n = 2 (identity and signed prekey) or 3 (plus one-time prekey), in
// that order. Concatenating the secrets means SK is secret as long as any
// one of them is; hashing the encapsulations into info binds SK to the
// exact ciphertexts (each secret alone is already bound to T by HPKE).
func deriveSK(t []byte, secrets [][sealbox.SharedSecretSize]byte, encs [][]byte) ([SessionKeySize]byte, error) {
	var sk [SessionKeySize]byte
	if len(secrets) < 2 || len(secrets) > 3 || len(secrets) != len(encs) {
		return sk, fmt.Errorf("%w: %d secrets, %d encapsulations", ErrInvalidArgument, len(secrets), len(encs))
	}
	ikm := make([]byte, 0, 3*sealbox.SharedSecretSize)
	defer func() { clear(ikm) }()
	encHash := sha256.New()
	for i := range secrets {
		ikm = append(ikm, secrets[i][:]...)
		encHash.Write(encs[i])
	}
	info := encHash.Sum(bytes.Clone(t))
	var salt [sha256.Size]byte
	key, err := hkdf.Key(sha256.New, ikm, salt[:], string(info), SessionKeySize)
	if err != nil {
		return sk, fmt.Errorf("handshake: deriving session key: %w", err)
	}
	copy(sk[:], key)
	clear(key)
	return sk, nil
}

// Winner resolves simultaneous session starts: when both sides started a
// session before receiving anything from the other, the session initiated
// by the lexicographically smaller ID (byte-wise on the raw 32 bytes) is
// kept. The side whose own unconfirmed session loses discards it when it
// receives the winning Init. Both sides compute the same answer from the
// same pair of IDs, so they converge without further messages.
func Winner(a, b identity.ID) identity.ID {
	if bytes.Compare(a[:], b[:]) <= 0 {
		return a
	}
	return b
}
