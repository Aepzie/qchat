package senderkey

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/identity"
)

// SenderStateVersion is the version of the serialised [Sender] format.
const SenderStateVersion = 1

// Sender is a member's own sending state for one sender key generation of
// one group. It is safe for concurrent use.
type Sender struct {
	mu         sync.Mutex
	group      GroupID
	owner      identity.ID
	generation uint32
	// iteration is the chain index of the next message; chain is the chain
	// key at that index.
	iteration uint32
	chain     [keySize]byte
	signing   *hybridsig.PrivateKey
	created   time.Time
	destroyed bool
}

// NewSender starts a new sender key generation for owner in group: a chain
// key drawn from crypto/rand and a fresh hybrid signing key pair. Each
// generation must have its own signing key, so that a member who saw an
// older generation's distribution (for example a removed member) learns
// nothing that lets it sign for the new one.
func NewSender(group GroupID, owner identity.ID, generation uint32) (*Sender, error) {
	if group == (GroupID{}) || owner.IsZero() {
		return nil, ErrInvalidArgument
	}
	signing, err := hybridsig.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("senderkey: generating signing key: %w", err)
	}
	s := &Sender{
		group:      group,
		owner:      owner,
		generation: generation,
		signing:    signing,
		created:    time.Unix(time.Now().Unix(), 0),
	}
	if _, err := rand.Read(s.chain[:]); err != nil {
		signing.Destroy()
		return nil, fmt.Errorf("senderkey: reading randomness: %w", err)
	}
	return s, nil
}

// Group returns the group of s.
func (s *Sender) Group() GroupID { return s.group }

// Owner returns the member that owns s.
func (s *Sender) Owner() identity.ID { return s.owner }

// Generation returns the generation number of s.
func (s *Sender) Generation() uint32 { return s.generation }

// CreatedAt returns when the generation was created, to second precision.
func (s *Sender) CreatedAt() time.Time { return s.created }

// Iteration returns the chain index the next message will use, which is
// also the number of messages sent so far in this generation.
func (s *Sender) Iteration() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.iteration
}

// NeedsRotation reports whether the owner should replace s with a new
// generation: after RotationMessages messages or once RotationAge has passed
// since creation. A chain key alone gives forward secrecy but no
// post-compromise security, so rotation bounds how much a leaked chain key
// exposes.
func (s *Sender) NeedsRotation(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.iteration >= RotationMessages || !now.Before(s.created.Add(RotationAge))
}

// Distribution returns the canonical distribution message for the current
// chain position, to be sent over the pairwise channel to each recipient.
// groupEpoch is the group epoch the owner is at. A recipient can decrypt the
// messages from the current iteration on, but none before it.
//
// The result contains the chain key: it must only travel encrypted and
// should be cleared by the caller after use.
func (s *Sender) Distribution(groupEpoch uint64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return nil, ErrDestroyed
	}
	if s.iteration == math.MaxUint32 {
		return nil, ErrChainExhausted
	}
	return encMode.Marshal(distributionWire{
		Version:    DistributionVersion,
		GroupID:    s.group[:],
		Generation: s.generation,
		Iteration:  s.iteration,
		ChainKey:   s.chain[:],
		SigningPub: s.signing.Public().Bytes(),
		GroupEpoch: groupEpoch,
	})
}

// Encrypt seals plaintext as one group envelope and advances the chain. Each
// envelope has a fresh random salt, and its header and ciphertext are signed
// with the generation's signing key. The chain advances only once the
// envelope is complete, so a failure never consumes a message key; the
// caller must persist s before sending the envelope.
func (s *Sender) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPlaintextSize {
		return nil, ErrPlaintextTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return nil, ErrDestroyed
	}
	if s.iteration == math.MaxUint32 {
		return nil, ErrChainExhausted
	}
	h := header{group: s.group, sender: s.owner, generation: s.generation, iteration: s.iteration}
	if _, err := rand.Read(h.salt[:]); err != nil {
		return nil, fmt.Errorf("senderkey: reading randomness: %w", err)
	}
	headerBytes, err := encodeHeader(h)
	if err != nil {
		return nil, fmt.Errorf("senderkey: encoding header: %w", err)
	}
	mk, next := chainStep(s.chain)
	defer clear(mk[:])
	defer clear(next[:])
	ciphertext, err := sealMessage(mk, h.salt[:], plaintext, headerBytes)
	if err != nil {
		return nil, err
	}
	sig, err := s.signing.Sign(MessageContext, signedPayload(headerBytes, ciphertext))
	if err != nil {
		return nil, fmt.Errorf("senderkey: signing envelope: %w", err)
	}
	encoded, err := encodeEnvelope(headerBytes, ciphertext, sig)
	if err != nil {
		return nil, fmt.Errorf("senderkey: encoding envelope: %w", err)
	}
	s.chain = next
	s.iteration++
	return encoded, nil
}

// Destroy overwrites the chain key and the signing key and makes every later
// operation fail with [ErrDestroyed]. Like [hybridsig.PrivateKey.Destroy] it
// is best effort.
func (s *Sender) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return
	}
	clear(s.chain[:])
	s.signing.Destroy()
	s.destroyed = true
}

// senderWire is the serialised form of a [Sender].
type senderWire struct {
	Version    uint8  `cbor:"1,keyasint"`
	GroupID    []byte `cbor:"2,keyasint"`
	Owner      []byte `cbor:"3,keyasint"`
	Generation uint32 `cbor:"4,keyasint"`
	Iteration  uint32 `cbor:"5,keyasint"`
	ChainKey   []byte `cbor:"6,keyasint"`
	EdSeed     []byte `cbor:"7,keyasint"`
	MLDSASeed  []byte `cbor:"8,keyasint"`
	Created    int64  `cbor:"9,keyasint"`
}

// Marshal serialises s, including its chain key and signing key seeds. The
// result is as sensitive as the sender key itself: the caller must encrypt it
// before storing it and should clear it after use. Older serialisations must
// be overwritten once a newer one is written, or they would bring back chain
// keys that forward secrecy requires to be gone.
func (s *Sender) Marshal() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return nil, ErrDestroyed
	}
	edSeed, mldsaSeed := s.signing.Seeds()
	defer clear(edSeed)
	defer clear(mldsaSeed)
	return encMode.Marshal(senderWire{
		Version:    SenderStateVersion,
		GroupID:    s.group[:],
		Owner:      s.owner[:],
		Generation: s.generation,
		Iteration:  s.iteration,
		ChainKey:   s.chain[:],
		EdSeed:     edSeed,
		MLDSASeed:  mldsaSeed,
		Created:    s.created.Unix(),
	})
}

// UnmarshalSender restores a sender serialised by [Sender.Marshal]. It
// accepts only the canonical encoding and checks every invariant, so a
// corrupted serialisation is rejected with [ErrInvalidState].
func UnmarshalSender(encoded []byte) (*Sender, error) {
	var w senderWire
	if err := strictDecMode.Unmarshal(encoded, &w); err != nil {
		return nil, ErrInvalidState
	}
	defer clear(w.ChainKey)
	defer clear(w.EdSeed)
	defer clear(w.MLDSASeed)
	switch {
	case w.Version != SenderStateVersion,
		len(w.GroupID) != len(GroupID{}),
		len(w.Owner) != identity.IDSize,
		len(w.ChainKey) != keySize,
		len(w.EdSeed) != hybridsig.SeedSize,
		len(w.MLDSASeed) != hybridsig.SeedSize,
		w.Created <= 0:
		return nil, ErrInvalidState
	}
	canonical, err := encMode.Marshal(w)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		return nil, ErrInvalidState
	}
	clear(canonical)
	s := &Sender{
		generation: w.Generation,
		iteration:  w.Iteration,
		created:    time.Unix(w.Created, 0),
	}
	copy(s.group[:], w.GroupID)
	copy(s.owner[:], w.Owner)
	if s.group == (GroupID{}) || s.owner.IsZero() {
		return nil, ErrInvalidState
	}
	signing, err := hybridsig.NewPrivateKeyFromSeeds(w.EdSeed, w.MLDSASeed)
	if err != nil {
		return nil, ErrInvalidState
	}
	s.signing = signing
	copy(s.chain[:], w.ChainKey)
	return s, nil
}
