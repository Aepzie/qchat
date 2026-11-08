package senderkey

import (
	"bytes"
	"cmp"
	"crypto/hmac"
	"slices"
	"sync"
	"time"

	"github.com/Aepzie/qchat/internal/crypto/hybridsig"
	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/padding"
)

// ReceiverStateVersion is the version of the serialised [Receiver] format.
// Serialisations of other versions are rejected.
const ReceiverStateVersion = 2

// clock is the source of the creation times of skipped keys. Tests replace
// it.
var clock = time.Now

// skippedKey is the message key of a message that has not arrived yet.
type skippedKey struct {
	iteration uint32
	key       [keySize]byte
	// created is when the key was derived, in Unix seconds.
	created int64
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
	// key at that index. A frozen receiver no longer has a chain key.
	iteration uint32
	chain     [keySize]byte
	frozen    bool
	headerKey [HeaderKeySize]byte
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
	defer d.destroy()
	return &Receiver{
		group:      d.info.GroupID,
		sender:     from,
		generation: d.info.Generation,
		groupEpoch: d.info.GroupEpoch,
		iteration:  d.info.Iteration,
		chain:      d.chain,
		headerKey:  d.headerKey,
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

// HeaderCandidate returns the header key of r's generation with its group,
// sender and generation, for routing envelopes with [OpenHeader] or a
// [HeaderKeyring]. The key is secret. It stays valid after [Receiver.Freeze],
// because a frozen receiver still decrypts messages with stored skipped keys.
func (r *Receiver) HeaderCandidate() (HeaderCandidate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.destroyed {
		return HeaderCandidate{}, ErrDestroyed
	}
	return HeaderCandidate{Group: r.group, Sender: r.sender, Generation: r.generation, Key: r.headerKey}, nil
}

// Freeze stops r from advancing its chain. The caller freezes the receiver
// of a generation once a newer generation of the same sender is installed:
// from then on r decrypts only messages whose skipped keys it still stores,
// and reports [ErrFrozen] for anything at or after its chain position. That
// keeps a member who learned the old chain key (for example a removed one)
// from sending in the old generation, and lets the old generation die out as
// its skipped keys are used, evicted or pruned. Freeze deletes the chain
// key; the flag is part of the serialised state. Freezing twice, or a
// destroyed receiver, is a no-op.
func (r *Receiver) Freeze() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.destroyed || r.frozen {
		return
	}
	clear(r.chain[:])
	r.frozen = true
}

// Frozen reports whether [Receiver.Freeze] was called.
func (r *Receiver) Frozen() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.frozen
}

// StoredSkipped returns the number of skipped message keys r holds. A frozen
// receiver without skipped keys can decrypt nothing and may be deleted.
func (r *Receiver) StoredSkipped() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.skipped)
}

// PruneSkipped deletes the skipped message keys derived before before and
// returns how many it deleted. Their messages can no longer be decrypted.
// Skipped keys are timestamped (to the second) when Decrypt derives them;
// Decrypt itself never deletes keys by age, so the caller decides the
// maximum age and calls PruneSkipped, typically with now minus RotationAge.
func (r *Receiver) PruneSkipped(before time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.destroyed {
		return 0
	}
	n := len(r.skipped)
	// DeleteFunc overwrites every deleted entry, either with a kept one
	// moved forward or with zeros, so no pruned key stays in memory.
	r.skipped = slices.DeleteFunc(r.skipped, func(sk skippedKey) bool {
		return time.Unix(sk.created, 0).Before(before)
	})
	return n - len(r.skipped)
}

// Decrypt verifies and decrypts a group envelope and returns the plaintext
// and the authenticated header. The header's GroupEpoch and StateBinding are
// what the sender claimed about its group state; the caller compares them
// with its own state to detect a fork.
//
// Checks run from cheapest to most expensive, and nothing secret beyond the
// header key is touched before the signature verifies: shape and size, then
// the header decryption under r's header key, then group, sender and
// generation, then the iteration against the replay window, the frozen
// state and MaxSkip, then the hybrid signature, and only then message key
// derivation, the key commitment and AEAD decryption. Verifying the
// signature first means a member that knows the shared chain and header
// keys cannot forge messages in another member's name, and nobody without
// the signing key can make a receiver advance its chain or burn skipped
// keys. Checking the commitment means every member that accepts an envelope
// decrypts it with the same message key, and so to the same plaintext.
//
// Decryption is all-or-nothing: the chain advance and skipped keys are
// computed on the side and committed only after the AEAD tag verifies. Any
// error leaves r unchanged. Decrypt reads the clock only to timestamp new
// skipped keys.
func (r *Receiver) Decrypt(encoded []byte) ([]byte, Header, error) {
	env, err := parseEnvelope(encoded)
	if err != nil {
		return nil, Header{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.destroyed {
		return nil, Header{}, ErrDestroyed
	}
	h, ok := env.openWith(&r.headerKey)
	if !ok {
		return nil, Header{}, ErrNoHeaderKey
	}
	if err := r.checkRouting(h); err != nil {
		return nil, Header{}, err
	}
	if err := r.checkPosition(h.iteration); err != nil {
		return nil, Header{}, err
	}
	headerBytes := encodeHeader(h)
	defer clear(headerBytes)
	if err := r.pub.Verify(MessageContext, signedPayload(env.nonce, env.encHeader, env.ciphertext, headerBytes), env.sig); err != nil {
		return nil, Header{}, ErrBadSignature
	}

	var plaintext []byte
	if h.iteration < r.iteration {
		plaintext, err = r.decryptSkipped(h, headerBytes, env.ciphertext)
	} else {
		plaintext, err = r.decryptAhead(h, headerBytes, env.ciphertext)
	}
	if err != nil {
		return nil, Header{}, err
	}
	return plaintext, h.public(), nil
}

// checkRouting rejects a header that does not belong to this receiver. A
// header that opened under r's header key normally does; only a holder of
// that key can produce one that does not.
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
// derive within MaxSkip steps, or may not derive because r is frozen.
func (r *Receiver) checkPosition(iteration uint32) error {
	if iteration < r.iteration {
		if _, found := r.findSkipped(iteration); !found {
			return ErrReplay
		}
		return nil
	}
	if r.frozen {
		return ErrFrozen
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

// openCommitted checks the header's commitment to message key mk, decrypts
// the ciphertext and strips its padding. Every failure is [ErrDecrypt]; an
// authentic message with invalid padding can only come from a broken or
// malicious sender and is rejected like a forgery, before r's state changes.
func openCommitted(mk [keySize]byte, h header, headerBytes, ciphertext []byte) ([]byte, error) {
	commitment := commitMessageKey(mk)
	if !hmac.Equal(commitment[:], h.commitment[:]) {
		return nil, ErrDecrypt
	}
	padded, err := openMessage(mk, h.salt[:], ciphertext, headerBytes)
	if err != nil {
		return nil, err
	}
	plaintext, err := padding.Unpad(padded)
	if err != nil {
		clear(padded)
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// decryptSkipped decrypts a message that arrived after later ones, with a
// stored skipped key, and deletes that key on success.
func (r *Receiver) decryptSkipped(h header, headerBytes, ciphertext []byte) ([]byte, error) {
	idx, _ := r.findSkipped(h.iteration)
	plaintext, err := openCommitted(r.skipped[idx].key, h, headerBytes, ciphertext)
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
func (r *Receiver) decryptAhead(h header, headerBytes, ciphertext []byte) ([]byte, error) {
	chain := r.chain
	defer clear(chain[:])
	created := clock().Unix()
	passed := make([]skippedKey, 0, h.iteration-r.iteration)
	discard := func() {
		for i := range passed {
			clear(passed[i].key[:])
		}
	}
	for it := r.iteration; it < h.iteration; it++ {
		mk, next := chainStep(chain)
		passed = append(passed, skippedKey{iteration: it, key: mk, created: created})
		clear(mk[:])
		chain = next
		clear(next[:])
	}
	mk, next := chainStep(chain)
	defer clear(mk[:])
	defer clear(next[:])
	plaintext, err := openCommitted(mk, h, headerBytes, ciphertext)
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

// Destroy overwrites the chain key, the header key and all skipped message
// keys and makes every later operation fail with [ErrDestroyed]. It is best
// effort.
func (r *Receiver) Destroy() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.destroyed {
		return
	}
	clear(r.chain[:])
	clear(r.headerKey[:])
	for i := range r.skipped {
		clear(r.skipped[i].key[:])
	}
	r.skipped = nil
	r.destroyed = true
}

// receiverWire is the serialised form of a [Receiver]. ChainKey is absent
// exactly when the receiver is frozen, Skipped is omitted when empty and
// Frozen when false, so every receiver has exactly one encoding.
type receiverWire struct {
	Version    uint8         `cbor:"1,keyasint"`
	GroupID    []byte        `cbor:"2,keyasint"`
	Sender     []byte        `cbor:"3,keyasint"`
	Generation uint32        `cbor:"4,keyasint"`
	GroupEpoch uint64        `cbor:"5,keyasint"`
	Iteration  uint32        `cbor:"6,keyasint"`
	ChainKey   []byte        `cbor:"7,keyasint,omitempty"`
	SigningPub []byte        `cbor:"8,keyasint"`
	Skipped    []skippedWire `cbor:"9,keyasint,omitempty"`
	HeaderKey  []byte        `cbor:"10,keyasint"`
	Frozen     bool          `cbor:"11,keyasint,omitempty"`
}

type skippedWire struct {
	_         struct{} `cbor:",toarray"`
	Iteration uint32
	Key       []byte
	Created   int64
}

// Marshal serialises r, including its chain key, header key and skipped
// message keys with their creation times. The caller must encrypt the result
// before storing it, should clear it after use, and must overwrite older
// serialisations once a newer one is written, since an old one brings back
// message keys that were deleted (and, before a Freeze, the chain key).
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
		SigningPub: r.pub.Bytes(),
		HeaderKey:  r.headerKey[:],
		Frozen:     r.frozen,
	}
	if !r.frozen {
		w.ChainKey = r.chain[:]
	}
	for i := range r.skipped {
		w.Skipped = append(w.Skipped, skippedWire{Iteration: r.skipped[i].iteration, Key: r.skipped[i].key[:], Created: r.skipped[i].created})
	}
	return encMode.Marshal(w)
}

// UnmarshalReceiver restores a receiver serialised by [Receiver.Marshal]. It
// accepts only the canonical encoding of the current version and checks
// every invariant (a chain key exactly when not frozen, skipped keys
// strictly increasing, below the chain position, with a creation time and
// at most MaxStoredSkipped), so a corrupted or outdated serialisation is
// rejected with [ErrInvalidState].
func UnmarshalReceiver(encoded []byte) (*Receiver, error) {
	var w receiverWire
	if err := stateDecMode.Unmarshal(encoded, &w); err != nil {
		return nil, ErrInvalidState
	}
	defer func() {
		clear(w.ChainKey)
		clear(w.HeaderKey)
		for _, sk := range w.Skipped {
			clear(sk.Key)
		}
	}()
	chainSize := keySize
	if w.Frozen {
		chainSize = 0
	}
	switch {
	case w.Version != ReceiverStateVersion,
		len(w.GroupID) != len(GroupID{}),
		len(w.Sender) != identity.IDSize,
		len(w.ChainKey) != chainSize,
		len(w.HeaderKey) != HeaderKeySize,
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

	r := &Receiver{generation: w.Generation, groupEpoch: w.GroupEpoch, iteration: w.Iteration, frozen: w.Frozen}
	copy(r.group[:], w.GroupID)
	copy(r.sender[:], w.Sender)
	if r.group == (GroupID{}) || r.sender.IsZero() {
		return nil, ErrInvalidState
	}
	for i, sk := range w.Skipped {
		if len(sk.Key) != keySize || sk.Created <= 0 || sk.Iteration >= w.Iteration || (i > 0 && sk.Iteration <= w.Skipped[i-1].Iteration) {
			return nil, ErrInvalidState
		}
	}
	pub, err := hybridsig.ParsePublicKey(w.SigningPub)
	if err != nil {
		return nil, ErrInvalidState
	}
	r.pub = pub
	copy(r.chain[:], w.ChainKey)
	copy(r.headerKey[:], w.HeaderKey)
	if len(w.Skipped) > 0 {
		r.skipped = make([]skippedKey, len(w.Skipped))
		for i, sk := range w.Skipped {
			r.skipped[i] = skippedKey{iteration: sk.Iteration, created: sk.Created}
			copy(r.skipped[i].key[:], sk.Key)
		}
	}
	return r, nil
}
