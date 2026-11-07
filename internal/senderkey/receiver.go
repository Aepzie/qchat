package senderkey

import (
	"bytes"
	"cmp"
	"slices"
	"sync"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/identity"
)

// ReceiverStateVersion is the version of the serialised [Receiver] format.
const ReceiverStateVersion = 1

// skippedKey is the message key of a message that has not arrived yet.
type skippedKey struct {
	iteration uint32
	key       [keySize]byte
}

// Receiver is the receiving state for one sender key generation of one
// member of one group. It is safe for concurrent use.
type Receiver struct {
	mu         sync.Mutex
	group      GroupID
	sender     identity.ID
	generation uint32
	groupEpoch uint64
	// iteration is the next chain index not yet derived; chain is the chain
	// key at that index.
	iteration uint32
	chain     [keySize]byte
	pub       *hybridsig.PublicKey
	// skipped holds the message keys of skipped iterations, sorted by
	// iteration. Every entry is below iteration.
	skipped   []skippedKey
	destroyed bool
}

// NewReceiver creates the receiving state for a distribution message that
// arrived over the pairwise channel from from. The distribution message
// carries no owner field: the sender is bound by the pairwise channel, which
// authenticates from, and every envelope this receiver accepts must name
// that sender in its signed header. Callers must pass the authenticated peer
// of the pairwise session, never a value taken from the message itself.
func NewReceiver(distribution []byte, from identity.ID) (*Receiver, error) {
	if from.IsZero() {
		return nil, ErrInvalidArgument
	}
	d, err := parseDistribution(distribution)
	if err != nil {
		return nil, err
	}
	defer clear(d.chain[:])
	return &Receiver{
		group:      d.info.GroupID,
		sender:     from,
		generation: d.info.Generation,
		groupEpoch: d.info.GroupEpoch,
		iteration:  d.info.Iteration,
		chain:      d.chain,
		pub:        d.signingPub,
	}, nil
}

// Group returns the group of r.
func (r *Receiver) Group() GroupID { return r.group }

// Sender returns the member whose messages r decrypts.
func (r *Receiver) Sender() identity.ID { return r.sender }

// Generation returns the sender key generation of r.
func (r *Receiver) Generation() uint32 { return r.generation }

// GroupEpoch returns the group epoch announced in the distribution message.
func (r *Receiver) GroupEpoch() uint64 { return r.groupEpoch }

// Iteration returns the next chain index r has not yet derived a key for.
func (r *Receiver) Iteration() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.iteration
}

// Decrypt verifies and decrypts a group envelope.
//
// Checks run from cheapest to most expensive, and nothing secret is touched
// before the signature verifies: shape and size, then group, sender and
// generation, then the iteration against the replay window and MaxSkip, then
// the hybrid signature over CBOR(header) || ciphertext, and only then key
// derivation and AEAD decryption. Verifying the signature first means a
// member that knows the shared chain key cannot forge messages in another
// member's name, and nobody without the signing key can make a receiver
// advance its chain or burn skipped keys.
//
// Decryption is all-or-nothing: the chain advance and skipped keys are
// computed on the side and committed only after the AEAD tag verifies. Any
// error leaves r unchanged.
func (r *Receiver) Decrypt(encoded []byte) ([]byte, error) {
	env, err := parseEnvelope(encoded)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.destroyed {
		return nil, ErrDestroyed
	}
	h := env.header
	if err := r.checkRouting(h); err != nil {
		return nil, err
	}
	if err := r.checkPosition(h.iteration); err != nil {
		return nil, err
	}
	if err := r.pub.Verify(MessageContext, signedPayload(env.headerBytes, env.ciphertext), env.sig); err != nil {
		return nil, ErrBadSignature
	}

	if h.iteration < r.iteration {
		return r.decryptSkipped(h, env)
	}
	return r.decryptAhead(h, env)
}

// checkRouting rejects an envelope that does not belong to this receiver.
func (r *Receiver) checkRouting(h header) error {
	switch {
	case h.group != r.group:
		return ErrWrongGroup
	case h.sender != r.sender:
		return ErrWrongSender
	case h.generation < r.generation:
		return ErrOldGeneration
	case h.generation > r.generation:
		return ErrUnknownGeneration
	}
	return nil
}

// checkPosition rejects an iteration whose key r does not hold and cannot
// derive within MaxSkip steps.
func (r *Receiver) checkPosition(iteration uint32) error {
	if iteration < r.iteration {
		if _, found := r.findSkipped(iteration); !found {
			return ErrReplay
		}
		return nil
	}
	if iteration-r.iteration > MaxSkip {
		return ErrTooManySkipped
	}
	return nil
}

// findSkipped returns the index of the skipped key for iteration.
func (r *Receiver) findSkipped(iteration uint32) (int, bool) {
	return slices.BinarySearchFunc(r.skipped, iteration, func(sk skippedKey, target uint32) int {
		return cmp.Compare(sk.iteration, target)
	})
}

// decryptSkipped decrypts a message that arrived after later ones, with a
// stored skipped key, and deletes that key on success.
func (r *Receiver) decryptSkipped(h header, env envelope) ([]byte, error) {
	idx, _ := r.findSkipped(h.iteration)
	plaintext, err := openMessage(r.skipped[idx].key, h.salt[:], env.ciphertext, env.headerBytes)
	if err != nil {
		return nil, err
	}
	clear(r.skipped[idx].key[:])
	r.skipped = slices.Delete(r.skipped, idx, idx+1)
	return plaintext, nil
}

// decryptAhead decrypts a message at or after the chain position. It walks a
// copy of the chain, keeping the keys of the iterations it passes, and
// commits them and the new chain key only after the message authenticates.
func (r *Receiver) decryptAhead(h header, env envelope) ([]byte, error) {
	chain := r.chain
	defer clear(chain[:])
	passed := make([]skippedKey, 0, h.iteration-r.iteration)
	discard := func() {
		for i := range passed {
			clear(passed[i].key[:])
		}
	}
	for it := r.iteration; it < h.iteration; it++ {
		mk, next := chainStep(chain)
		passed = append(passed, skippedKey{iteration: it, key: mk})
		clear(mk[:])
		chain = next
		clear(next[:])
	}
	mk, next := chainStep(chain)
	defer clear(mk[:])
	defer clear(next[:])
	plaintext, err := openMessage(mk, h.salt[:], env.ciphertext, env.headerBytes)
	if err != nil {
		discard()
		return nil, err
	}

	r.skipped = append(r.skipped, passed...)
	if excess := len(r.skipped) - MaxStoredSkipped; excess > 0 {
		for i := range excess {
			clear(r.skipped[i].key[:])
		}
		r.skipped = slices.Delete(r.skipped, 0, excess)
	}
	r.chain = next
	r.iteration = h.iteration + 1
	return plaintext, nil
}

// Destroy overwrites the chain key and all skipped message keys and makes
// every later operation fail with [ErrDestroyed]. It is best effort.
func (r *Receiver) Destroy() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.destroyed {
		return
	}
	clear(r.chain[:])
	for i := range r.skipped {
		clear(r.skipped[i].key[:])
	}
	r.skipped = nil
	r.destroyed = true
}

// receiverWire is the serialised form of a [Receiver]. Skipped is omitted
// when empty, so every receiver has exactly one encoding.
type receiverWire struct {
	Version    uint8         `cbor:"1,keyasint"`
	GroupID    []byte        `cbor:"2,keyasint"`
	Sender     []byte        `cbor:"3,keyasint"`
	Generation uint32        `cbor:"4,keyasint"`
	GroupEpoch uint64        `cbor:"5,keyasint"`
	Iteration  uint32        `cbor:"6,keyasint"`
	ChainKey   []byte        `cbor:"7,keyasint"`
	SigningPub []byte        `cbor:"8,keyasint"`
	Skipped    []skippedWire `cbor:"9,keyasint,omitempty"`
}

type skippedWire struct {
	_         struct{} `cbor:",toarray"`
	Iteration uint32
	Key       []byte
}

// Marshal serialises r, including its chain key and skipped message keys.
// The caller must encrypt the result before storing it, should clear it after
// use, and must overwrite older serialisations once a newer one is written,
// since an old one brings back message keys that were deleted.
func (r *Receiver) Marshal() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.destroyed {
		return nil, ErrDestroyed
	}
	w := receiverWire{
		Version:    ReceiverStateVersion,
		GroupID:    r.group[:],
		Sender:     r.sender[:],
		Generation: r.generation,
		GroupEpoch: r.groupEpoch,
		Iteration:  r.iteration,
		ChainKey:   r.chain[:],
		SigningPub: r.pub.Bytes(),
	}
	for i := range r.skipped {
		w.Skipped = append(w.Skipped, skippedWire{Iteration: r.skipped[i].iteration, Key: r.skipped[i].key[:]})
	}
	return encMode.Marshal(w)
}

// UnmarshalReceiver restores a receiver serialised by [Receiver.Marshal]. It
// accepts only the canonical encoding and checks every invariant (skipped
// keys strictly increasing, below the chain position and at most
// MaxStoredSkipped), so a corrupted serialisation is rejected with
// [ErrInvalidState].
func UnmarshalReceiver(encoded []byte) (*Receiver, error) {
	var w receiverWire
	if err := stateDecMode.Unmarshal(encoded, &w); err != nil {
		return nil, ErrInvalidState
	}
	defer func() {
		clear(w.ChainKey)
		for _, sk := range w.Skipped {
			clear(sk.Key)
		}
	}()
	switch {
	case w.Version != ReceiverStateVersion,
		len(w.GroupID) != len(GroupID{}),
		len(w.Sender) != identity.IDSize,
		len(w.ChainKey) != keySize,
		len(w.SigningPub) != hybridsig.PublicKeySize,
		len(w.Skipped) > MaxStoredSkipped:
		return nil, ErrInvalidState
	}
	canonical, err := encMode.Marshal(w)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		return nil, ErrInvalidState
	}
	clear(canonical)

	r := &Receiver{generation: w.Generation, groupEpoch: w.GroupEpoch, iteration: w.Iteration}
	copy(r.group[:], w.GroupID)
	copy(r.sender[:], w.Sender)
	if r.group == (GroupID{}) || r.sender.IsZero() {
		return nil, ErrInvalidState
	}
	for i, sk := range w.Skipped {
		if len(sk.Key) != keySize || sk.Iteration >= w.Iteration || (i > 0 && sk.Iteration <= w.Skipped[i-1].Iteration) {
			return nil, ErrInvalidState
		}
	}
	pub, err := hybridsig.ParsePublicKey(w.SigningPub)
	if err != nil {
		return nil, ErrInvalidState
	}
	r.pub = pub
	copy(r.chain[:], w.ChainKey)
	if len(w.Skipped) > 0 {
		r.skipped = make([]skippedKey, len(w.Skipped))
		for i, sk := range w.Skipped {
			r.skipped[i].iteration = sk.Iteration
			copy(r.skipped[i].key[:], sk.Key)
		}
	}
	return r, nil
}
