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
	// InitVersion is the format version of the Init header. Version 1
	// (without Created) is no longer accepted.
	InitVersion = 2

	// ContextSessionInit labels the sender's signature over an Init header.
	ContextSessionInit = "qchat/v1/session-init"

	// transcriptLabel starts the transcript string T.
	transcriptLabel = "qchat/v1/session"

	// SessionKeySize is the size of SK.
	SessionKeySize = 32

	// ReplayKeySize is the size of the value returned by [ReplayKey].
	ReplayKeySize = sha256.Size

	// MaxInitSize is the largest encoded Init header [Accept] processes:
	// a maximal sender bundle, three encapsulations, one signature and
	// generous room for the CBOR framing, key IDs and creation time. Larger
	// input is rejected before it is decoded.
	MaxInitSize = identity.MaxBundleSize + 3*sealbox.EncapsulatedKeySize + hybridsig.SignatureSize + 64
)

// Signed prekey lifetime policy of the design document ("Prekeys"). The
// handshake itself enforces only [MaxInitAge] and [MaxInitClockSkew]; the
// other constants are for the caller that generates, rotates and deletes
// its own signed prekeys.
const (
	// SignedPrekeyRotation is how often a new signed prekey is generated
	// and uploaded.
	SignedPrekeyRotation = 7 * 24 * time.Hour

	// SignedPrekeyLifetime is the validity period of a signed prekey:
	// Expires = Created + SignedPrekeyLifetime. It exceeds the rotation
	// interval so that a peer holding a slightly old bundle can still start
	// a session.
	SignedPrekeyLifetime = 9 * 24 * time.Hour

	// UndeliveredTTL is the relay's default undelivered_ttl: the longest a
	// queued message, and with it a first message carrying an Init, waits
	// for delivery.
	UndeliveredTTL = 7 * 24 * time.Hour

	// SignedPrekeyRetention is how long after its creation the private key
	// of a signed prekey is kept: until Expires + UndeliveredTTL (16 days
	// after creation), so that a first message queued just before expiry
	// can still be read. Then it must be deleted, together with the replay
	// set kept for it.
	SignedPrekeyRetention = SignedPrekeyLifetime + UndeliveredTTL

	// MaxInitAge is the oldest Init [AcceptAt] accepts, measured from its
	// signed Created time. An Init that old names a signed prekey whose
	// private key has been deleted under the policy above, so the bound
	// costs honest senders nothing, but it still holds if a deletion was
	// missed or delayed.
	MaxInitAge = SignedPrekeyRetention

	// MaxInitClockSkew is how far in the future an Init's Created time may
	// lie, to tolerate clock differences between sender and recipient.
	MaxInitClockSkew = 5 * time.Minute
)

// Errors returned by this package. Callers compare with [errors.Is].
var (
	// ErrMalformed reports an Init header that is not exactly in the
	// canonical current format, has fields of the wrong size or an
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

	// ErrStaleInit reports an Init whose Created time is more than
	// [MaxInitAge] in the past or more than [MaxInitClockSkew] in the
	// future. It is the normal outcome of a replayed old session start.
	ErrStaleInit = errors.New("handshake: init too old or from the future")

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

// PrekeyLookup returns one of the recipient's own prekeys by key ID: its
// private key and raw, the exact public encoding that was uploaded to the
// relay (prekey.SignedPrekey.Raw or prekey.OneTimePrekey.Raw). raw enters
// the session key derivation, so it must be byte for byte what peers were
// served. A lookup must return an error (or a nil key) for an ID that is
// unknown or whose private key has been deleted.
type PrekeyLookup func(keyID uint32) (priv *sealbox.PrivateKey, raw []byte, err error)

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
//
// When the caller has a pinned bundle for want, it should compare the
// serial of the returned Identity with it (or parse identityBundle itself
// with identity.ParseBundleForIDMinSerial) before using the bundle.
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

	// Created is the signed creation time of Init, with second precision.
	// The peer rejects Init once it is older than [MaxInitAge]; a session
	// still unconfirmed by then must be started again.
	Created time.Time
}

// Accepted is the recipient's result of a session start.
type Accepted struct {
	// SK is the session key. It is NOT yet confirmed: see the package
	// documentation.
	SK [SessionKeySize]byte

	// Sender is the verified identity bundle of the initiator, taken from
	// the Init header. Its ID equals the relay-reported sender, but its
	// serial has NOT been compared with anything: an Init may carry an
	// older, validly signed bundle of the same identity (for instance one
	// whose KEM key was rotated out). If the caller has a pinned bundle for
	// the sender, it MUST reject the Init unless Sender.Serial is at least
	// the pinned serial, with the semantics of
	// identity.ParseBundleForIDMinSerial(Sender.Raw, Sender.ID, pinnedSerial),
	// and must never replace a pinned bundle by one with a lower serial.
	Sender *identity.Bundle

	// SPKID and OPKID name the recipient's prekeys that were used; OPKID is
	// 0 when none. After the first message of this session has been
	// decrypted, the caller MUST delete the one-time private key OPKID.
	SPKID, OPKID uint32

	// Created is the signed creation time of the Init, with second
	// precision.
	Created time.Time

	// ReplayKey equals [ReplayKey] of the Init. The caller records it in
	// its replay set for SPKID; see the package documentation.
	ReplayKey [ReplayKeySize]byte
}

// initTBS holds every field of an Init header except the signature: fields
// 1 to 7 and 9.
type initTBS struct {
	Version      uint8  `cbor:"1,keyasint"`
	SenderBundle []byte `cbor:"2,keyasint"`
	SPKID        uint32 `cbor:"3,keyasint"`
	OPKID        uint32 `cbor:"4,keyasint"`
	EncIK        []byte `cbor:"5,keyasint"`
	EncSPK       []byte `cbor:"6,keyasint"`
	EncOPK       []byte `cbor:"7,keyasint,omitempty"`
	Created      int64  `cbor:"9,keyasint"`
}

// initWire is the complete encoded Init header, fields 1 to 9.
type initWire struct {
	Version      uint8  `cbor:"1,keyasint"`
	SenderBundle []byte `cbor:"2,keyasint"`
	SPKID        uint32 `cbor:"3,keyasint"`
	OPKID        uint32 `cbor:"4,keyasint"`
	EncIK        []byte `cbor:"5,keyasint"`
	EncSPK       []byte `cbor:"6,keyasint"`
	EncOPK       []byte `cbor:"7,keyasint,omitempty"`
	Sig          []byte `cbor:"8,keyasint"`
	Created      int64  `cbor:"9,keyasint"`
}

func (w *initWire) tbs() initTBS {
	return initTBS{
		Version: w.Version, SenderBundle: w.SenderBundle, SPKID: w.SPKID, OPKID: w.OPKID,
		EncIK: w.EncIK, EncSPK: w.EncSPK, EncOPK: w.EncOPK, Created: w.Created,
	}
}

// signedMessage returns CBOR(all fields but Sig) || recipient, the message
// the Init signature covers.
func (w *initWire) signedMessage(recipient identity.ID) ([]byte, error) {
	tbs, err := encMode.Marshal(w.tbs())
	if err != nil {
		return nil, err
	}
	return append(tbs, recipient[:]...), nil
}

// replayKey returns SHA-256(EncIK || EncSPK || EncOPK), with EncOPK empty
// when absent. Every encapsulation has a fixed size, so the concatenation
// is unambiguous.
func (w *initWire) replayKey() [ReplayKeySize]byte {
	h := sha256.New()
	h.Write(w.EncIK)
	h.Write(w.EncSPK)
	h.Write(w.EncOPK)
	var key [ReplayKeySize]byte
	h.Sum(key[:0])
	return key
}

// ReplayKey returns the replay-set key of an encoded Init header:
// SHA-256(EncIK || EncSPK || EncOPK), with EncOPK empty when the Init names
// no one-time prekey. Two Inits with the same encapsulations yield the same
// session key, so this identifies a session start independently of the
// (randomised) signature. It checks only that init is a well-formed Init in
// the current format ([ErrMalformed] otherwise), not its signature; use
// [Accepted.ReplayKey] for an authenticated value.
func ReplayKey(init []byte) ([ReplayKeySize]byte, error) {
	wire, err := parseInit(init)
	if err != nil {
		return [ReplayKeySize]byte{}, err
	}
	return wire.replayKey(), nil
}

// Initiate is [InitiateAt] at the current time.
func Initiate(self Signer, selfBundle []byte, peer *Bundle) (*Initiation, error) {
	return InitiateAt(self, selfBundle, peer, time.Now())
}

// InitiateAt starts a session from self to peer, with now as the signed
// creation time of the Init. selfBundle is self's own encoded identity
// bundle, exactly as registered with the relay; it is sent in the Init
// header so that the recipient can verify the signature without a lookup,
// and it must belong to self.
//
// peer must come from [ParseBundle]; InitiateAt trusts its contents.
func InitiateAt(self Signer, selfBundle []byte, peer *Bundle, now time.Time) (*Initiation, error) {
	if self == nil || peer == nil || peer.Identity == nil || peer.Identity.KEMKey == nil ||
		peer.SignedPrekey == nil || peer.SignedPrekey.Pub == nil || len(peer.SignedPrekey.Raw) == 0 ||
		(peer.OneTime != nil && (peer.OneTime.Pub == nil || len(peer.OneTime.Raw) == 0)) {
		return nil, fmt.Errorf("%w: incomplete arguments", ErrInvalidArgument)
	}
	created := now.Unix()
	if created <= 0 {
		return nil, fmt.Errorf("%w: time before 1970", ErrInvalidArgument)
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
	var opkRaw []byte
	if peer.OneTime != nil {
		opkID, opkRaw = peer.OneTime.KeyID, peer.OneTime.Raw
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
		clear(secret[:])
	}

	wire := initWire{
		Version:      InitVersion,
		SenderBundle: bytes.Clone(selfBundle),
		SPKID:        spkID,
		OPKID:        opkID,
		EncIK:        encs[0],
		EncSPK:       encs[1],
		Created:      created,
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
	sk, err := deriveSK(t, secrets, encs, transcriptHashes(wire.SenderBundle, peer.SignedPrekey.Raw, opkRaw))
	if err != nil {
		return nil, err
	}
	return &Initiation{
		SK: sk, Init: encoded, PeerInitialPub: peer.SignedPrekey.Pub,
		SPKID: spkID, OPKID: opkID, Created: time.Unix(created, 0),
	}, nil
}

// Accept is [AcceptAt] at the current time.
func Accept(self Decapsulator, relayFrom identity.ID, init []byte, spk, opk PrekeyLookup) (*Accepted, error) {
	return AcceptAt(self, relayFrom, init, spk, opk, time.Now())
}

// AcceptAt processes an Init header received from the relay on behalf of
// the relay-authenticated sender relayFrom at time now, and derives the
// session key.
//
// spk and opk look up the recipient's own prekeys by key ID (see
// [PrekeyLookup]); opk must fail for a one-time prekey that has already
// been deleted, which is what rejects a replayed session start that used
// one. opk is not called when the Init names no one-time prekey.
//
// The checks run cheapest and least revealing first: size; exact canonical
// encoding and field sizes; Created within [MaxInitAge] before and
// [MaxInitClockSkew] after now ([ErrStaleInit]); the sender bundle parses
// and its ID equals relayFrom ([ErrWrongSender]); the signature over all
// other fields and self's ID verifies ([ErrBadSignature]). Only then are
// the prekeys looked up ([ErrUnknownPrekey]) and decapsulated, so
// unauthenticated input can neither probe which prekeys exist nor cost
// private-key operations.
//
// AcceptAt neither deletes anything nor consults a replay set, and it does
// not compare the sender bundle's serial with a pinned one (see
// [Accepted.Sender]). The caller MUST check [Accepted.ReplayKey] against
// its replay set for SPKID and delete the one-time private key OPKID, both
// after (and only after) the first message of the session has been
// decrypted with a key derived from SK; see the package documentation.
func AcceptAt(self Decapsulator, relayFrom identity.ID, init []byte, spk, opk PrekeyLookup, now time.Time) (*Accepted, error) {
	if self == nil || spk == nil || opk == nil {
		return nil, fmt.Errorf("%w: nil argument", ErrInvalidArgument)
	}
	wire, err := parseInit(init)
	if err != nil {
		return nil, err
	}
	created := time.Unix(wire.Created, 0)
	if now.Sub(created) > MaxInitAge || created.Sub(now) > MaxInitClockSkew {
		return nil, ErrStaleInit
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

	spkPriv, spkRaw, err := lookup(spk, wire.SPKID, "signed")
	if err != nil {
		return nil, err
	}
	var opkPriv *sealbox.PrivateKey
	var opkRaw []byte
	if wire.OPKID != 0 {
		if opkPriv, opkRaw, err = lookup(opk, wire.OPKID, "one-time"); err != nil {
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
	sk, err := deriveSK(t, secrets, encs, transcriptHashes(wire.SenderBundle, spkRaw, opkRaw))
	if err != nil {
		return nil, err
	}
	return &Accepted{
		SK: sk, Sender: sender, SPKID: wire.SPKID, OPKID: wire.OPKID,
		Created: created, ReplayKey: wire.replayKey(),
	}, nil
}

// parseInit checks the size of an encoded Init, decodes it strictly and
// canonically and validates its fields. Every failure wraps [ErrMalformed].
func parseInit(init []byte) (*initWire, error) {
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
	return &wire, nil
}

// check validates the version, field sizes, creation time and the
// consistency of the one-time prekey fields of a decoded Init, before any
// expensive work.
func (w *initWire) check() error {
	if w.Version != InitVersion {
		return fmt.Errorf("%w: version %d", ErrMalformed, w.Version)
	}
	if len(w.SenderBundle) == 0 || len(w.SenderBundle) > identity.MaxBundleSize ||
		len(w.EncIK) != sealbox.EncapsulatedKeySize || len(w.EncSPK) != sealbox.EncapsulatedKeySize ||
		len(w.Sig) != hybridsig.SignatureSize {
		return fmt.Errorf("%w: field of wrong size", ErrMalformed)
	}
	if w.Created <= 0 {
		return fmt.Errorf("%w: creation time not positive", ErrMalformed)
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

// lookup calls a prekey lookup function and normalises its failures,
// including a nil key or an empty public encoding, to [ErrUnknownPrekey].
func lookup(find PrekeyLookup, keyID uint32, kind string) (*sealbox.PrivateKey, []byte, error) {
	priv, raw, err := find(keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s prekey %d: %w", ErrUnknownPrekey, kind, keyID, err)
	}
	if priv == nil || len(raw) == 0 {
		return nil, nil, fmt.Errorf("%w: %s prekey %d", ErrUnknownPrekey, kind, keyID)
	}
	return priv, raw, nil
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

// transcriptHashes returns SHA-256(senderBundle) || SHA-256(spkRaw) ||
// SHA-256(opkRaw), the hashes of the exact public objects the session start
// used. opkRaw is empty when there is no one-time prekey, which hashes the
// empty string.
func transcriptHashes(senderBundle, spkRaw, opkRaw []byte) []byte {
	out := make([]byte, 0, 3*sha256.Size)
	for _, part := range [][]byte{senderBundle, spkRaw, opkRaw} {
		sum := sha256.Sum256(part)
		out = append(out, sum[:]...)
	}
	return out
}

// deriveSK is the key combiner:
//
//	SK = HKDF-SHA256(salt = 32 zero bytes, ikm = ss_1 || ... || ss_n,
//	                 info = T || SHA-256(enc_1 || ... || enc_n) || objects)
//
// with n = 2 (identity and signed prekey) or 3 (plus one-time prekey), in
// that order, and objects = [transcriptHashes]. Concatenating the secrets
// means SK is secret as long as any one of them is; hashing the
// encapsulations and the public objects into info binds SK to the exact
// ciphertexts, the sender bundle and the prekey encodings (each secret
// alone is already bound to T by HPKE).
func deriveSK(t []byte, secrets [][sealbox.SharedSecretSize]byte, encs [][]byte, objects []byte) ([SessionKeySize]byte, error) {
	var sk [SessionKeySize]byte
	if len(secrets) < 2 || len(secrets) > 3 || len(secrets) != len(encs) || len(objects) != 3*sha256.Size {
		return sk, fmt.Errorf("%w: %d secrets, %d encapsulations, %d object hash bytes",
			ErrInvalidArgument, len(secrets), len(encs), len(objects))
	}
	ikm := make([]byte, 0, 3*sealbox.SharedSecretSize)
	defer func() { clear(ikm[:cap(ikm)]) }()
	encHash := sha256.New()
	for i := range secrets {
		ikm = append(ikm, secrets[i][:]...)
		encHash.Write(encs[i])
	}
	info := encHash.Sum(bytes.Clone(t))
	info = append(info, objects...)
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
// receives the winning Init, but only if that Init passed [AcceptAt], is
// not in the replay set, and its first message decrypted. Both sides
// compute the same answer from the same pair of IDs, so they converge
// without further messages.
func Winner(a, b identity.ID) identity.ID {
	if bytes.Compare(a[:], b[:]) <= 0 {
		return a
	}
	return b
}
