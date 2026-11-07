package ratchet

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/craguS/qchat/internal/crypto/sealbox"
	"golang.org/x/crypto/chacha20poly1305"
)

// Limits on the state a peer can make a session hold.
const (
	// MaxSkip is the largest number of message keys a single decryption may
	// derive and store for messages that have not arrived yet (counting the
	// rest of the previous epoch plus the gap in the new one). Headers that
	// would need more are rejected with [ErrTooManySkipped] before any KEM or
	// AEAD work, so a forged counter cannot make the receiver burn CPU.
	MaxSkip = 1000

	// MaxStoredSkipped is the largest number of skipped message keys a
	// session keeps. When more accumulate, the oldest are deleted and the
	// corresponding messages, should they still arrive, can no longer be
	// decrypted. Every stored key weakens forward secrecy for its message, so
	// the bound is also a bound on that exposure.
	MaxStoredSkipped = 1000

	// MaxSkippedEpochAge is how many receiving epochs a skipped message key
	// survives: a key of epoch e is deleted as soon as the receiving epoch
	// exceeds e + MaxSkippedEpochAge. Since both sides start a new epoch
	// about once per round trip, a withheld message cannot keep its key
	// alive for long.
	MaxSkippedEpochAge = 2

	// MaxUnconsumedOwnKeys is the largest number of own ratchet private keys
	// a session keeps while waiting for the peer to encapsulate to them.
	// While that many are held, no further key is generated: deleting one
	// instead could delete the key a peer epoch already in flight targets.
	MaxUnconsumedOwnKeys = 4
)

// Errors returned by this package. Callers should compare with [errors.Is].
// None of them reveals anything secret: they depend only on the header,
// which is public, or on whether the AEAD tag verified.
var (
	// ErrDecrypt reports that a message failed to authenticate: it was
	// modified, belongs to another session or direction, or was encrypted
	// under keys this state does not hold.
	ErrDecrypt = errors.New("ratchet: message authentication failed")

	// ErrTooManySkipped reports a header whose counters would require storing
	// more than MaxSkip skipped message keys.
	ErrTooManySkipped = errors.New("ratchet: too many skipped messages")

	// ErrMalformedHeader reports a header that is not the canonical encoding
	// of a valid Header, or whose counters are inconsistent with the
	// session.
	ErrMalformedHeader = errors.New("ratchet: malformed header")

	// ErrUnknownTarget reports a message starting an epoch that this state
	// cannot start: it targets a key this side does not hold (never had, or
	// already consumed and deleted), or it skips an epoch.
	ErrUnknownTarget = errors.New("ratchet: message targets an unknown key")

	// ErrReplay reports a message from an epoch or position whose key is no
	// longer held: it was already decrypted (a replay), or it arrived so late
	// that its skipped key was deleted.
	ErrReplay = errors.New("ratchet: message key already used or discarded")

	// ErrNoPeerKey reports Encrypt on a responder state that has not yet
	// received a message, and therefore has no peer key to encapsulate to.
	ErrNoPeerKey = errors.New("ratchet: no peer ratchet key yet")

	// ErrExhausted reports that an epoch or message counter would overflow.
	ErrExhausted = errors.New("ratchet: counter exhausted")

	// ErrDestroyed reports use of a state after [State.Destroy].
	ErrDestroyed = errors.New("ratchet: state destroyed")

	// ErrInvalidParams reports invalid arguments to [New].
	ErrInvalidParams = errors.New("ratchet: invalid parameters")

	// ErrInvalidState reports a serialised state that [Unmarshal] rejects.
	ErrInvalidState = errors.New("ratchet: invalid serialised state")
)

// Role says which side of the session a state belongs to. It decides which
// root chain is used for sending: the initiator sends on A->B.
type Role uint8

// Roles. The zero value is invalid so that an unset role is caught.
const (
	Initiator Role = 1
	Responder Role = 2
)

func (r Role) valid() bool { return r == Initiator || r == Responder }

// Params are the inputs to [New], produced by the session handshake.
type Params struct {
	// Self and Peer are the identity IDs of this side and the other side.
	Self, Peer [32]byte
	// SK is the session secret agreed by the handshake.
	SK [32]byte
	// Role is this side's role in the handshake.
	Role Role
	// PeerInitialPub is required for the initiator and must be nil for the
	// responder: the responder's signed prekey public key, which is the
	// target of the initiator's first epoch.
	PeerInitialPub *sealbox.PublicKey
	// OwnInitialKey is required for the responder and must be nil for the
	// initiator: the signed prekey private key the initiator's first epoch
	// encapsulates to. New copies it, so the caller keeps ownership of its
	// own copy (the signed prekey is shared by many sessions).
	OwnInitialKey *sealbox.PrivateKey
}

// State is one side of a ratchet session.
//
// A State holds secret keys; it must be stored only in encrypted form (see
// [State.Marshal]) and destroyed with [State.Destroy] when no longer needed.
// Its methods are safe for concurrent use, but a session's persistence order
// is the caller's responsibility: the state must be written back after every
// Encrypt before the ciphertext is handed to the relay, and after every
// Decrypt before the plaintext is shown.
type State struct {
	mu        sync.Mutex
	destroyed bool

	role       Role
	self, peer [32]byte

	rootSend, rootRecv [keySize]byte
	send               sendChain
	recv               recvChain

	// peerPub is the newest ratchet public key announced by the peer (for
	// the initiator, initially the responder's signed prekey). peerPos is
	// the (epoch, n) position of the message that announced it, so that a
	// delayed older message cannot roll it back.
	peerPub *sealbox.PublicKey
	peerPos position

	// peerAck is the highest RecvEpoch the peer has reported, the newest
	// sending epoch of this side the peer has decrypted from.
	peerAck uint32

	// ownKeys are this side's unconsumed ratchet private keys, oldest
	// first. The last one is announced in every header. It is empty only
	// between a decryption that consumed every key and the next Encrypt.
	ownKeys []*sealbox.PrivateKey

	// rotate is set by every successful decryption: the next Encrypt
	// generates and announces a fresh own key.
	rotate bool

	// skipped are stored message keys of messages that have not arrived,
	// oldest first.
	skipped []skippedKey
}

type sendChain struct {
	epoch  uint32
	chain  [keySize]byte
	n, pn  uint32
	target [TargetSize]byte
	kemCT  []byte
}

type recvChain struct {
	epoch     uint32
	chain     [keySize]byte
	n         uint32
	target    [TargetSize]byte
	kemCTHash [sha256.Size]byte
}

type skippedKey struct {
	pos position
	key [keySize]byte
}

// position orders the messages of one direction: epochs increase, and the
// index increases within an epoch.
type position struct {
	epoch, n uint32
}

func (p position) after(q position) bool {
	return p.epoch > q.epoch || (p.epoch == q.epoch && p.n > q.n)
}

// New creates a session state from the handshake output.
//
// The initiator generates its first own ratchet key and will start epoch 1,
// targeting p.PeerInitialPub, on its first Encrypt. The responder cannot
// encrypt until it has decrypted the initiator's first message, which starts
// its receiving chain by decapsulating with p.OwnInitialKey.
func New(p Params) (*State, error) {
	if !p.Role.valid() || p.SK == ([32]byte{}) {
		return nil, ErrInvalidParams
	}
	s := &State{role: p.Role, self: p.Self, peer: p.Peer}
	ab, ba, err := deriveRoots(p.SK)
	if err != nil {
		return nil, err
	}
	defer clear(ab[:])
	defer clear(ba[:])
	switch p.Role {
	case Initiator:
		if p.PeerInitialPub == nil || p.OwnInitialKey != nil {
			return nil, ErrInvalidParams
		}
		own, err := sealbox.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("ratchet: generating ratchet key: %w", err)
		}
		s.rootSend, s.rootRecv = ab, ba
		s.peerPub = p.PeerInitialPub
		s.ownKeys = []*sealbox.PrivateKey{own}
	case Responder:
		if p.OwnInitialKey == nil || p.PeerInitialPub != nil {
			return nil, ErrInvalidParams
		}
		seed := p.OwnInitialKey.Bytes()
		if seed == nil {
			return nil, ErrInvalidParams
		}
		own, err := sealbox.NewPrivateKey(seed)
		clear(seed)
		if err != nil {
			return nil, ErrInvalidParams
		}
		s.rootSend, s.rootRecv = ba, ab
		s.ownKeys = []*sealbox.PrivateKey{own}
	}
	return s, nil
}

// ReceivedAny reports whether a message from the peer has been decrypted.
// The handshake stops attaching its Init to outgoing messages once this is
// true: the peer has evidently set up the session.
func (s *State) ReceivedAny() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recv.epoch > 0
}

// Encrypt encrypts plaintext as the next message to the peer and returns the
// encoded header and the ciphertext (plaintext plus a 16-byte tag).
//
// If no epoch has started, or the peer has announced a ratchet key newer than
// the one the current sending epoch targets and has acknowledged the current
// epoch (see [Header.RecvEpoch]), Encrypt first starts a new epoch by
// encapsulating to that key and mixing the shared secret into the sending
// root chain. If a message has been decrypted since the last own key was
// generated, and fewer than MaxUnconsumedOwnKeys are held, it also generates
// a fresh own ratchet key and announces it from this message on, so that the
// peer's next epoch targets a key that did not exist before. These two steps
// provide post-compromise security. On error the state is unchanged.
func (s *State) Encrypt(plaintext []byte) (header, ciphertext []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return nil, nil, ErrDestroyed
	}
	if s.peerPub == nil {
		return nil, nil, ErrNoPeerKey
	}

	next := s.send
	root := s.rootSend
	defer clear(next.chain[:])
	defer clear(root[:])

	target := targetOf(s.peerPub)
	if next.epoch == 0 || (target != next.target && s.peerAck >= next.epoch) {
		if next.epoch == math.MaxUint32 {
			return nil, nil, ErrExhausted
		}
		epoch := next.epoch + 1
		enc, ss, err := sealbox.Encapsulate(s.peerPub, ratchetInfo(s.self, s.peer, epoch))
		if err != nil {
			return nil, nil, fmt.Errorf("ratchet: starting epoch: %w", err)
		}
		newRoot, chain, err := kdfRK(root, ss)
		clear(ss[:])
		if err != nil {
			return nil, nil, err
		}
		next = sendChain{epoch: epoch, chain: chain, pn: next.n, target: target, kemCT: enc}
		root = newRoot
		clear(newRoot[:])
		clear(chain[:])
	}
	if next.n == math.MaxUint32 {
		return nil, nil, ErrExhausted
	}

	var fresh *sealbox.PrivateKey
	if (s.rotate && len(s.ownKeys) < MaxUnconsumedOwnKeys) || len(s.ownKeys) == 0 {
		if fresh, err = sealbox.GenerateKey(); err != nil {
			return nil, nil, fmt.Errorf("ratchet: generating ratchet key: %w", err)
		}
	}
	committed := false
	defer func() {
		if !committed && fresh != nil {
			fresh.Destroy()
		}
	}()
	announced := fresh
	if announced == nil {
		announced = s.ownKeys[len(s.ownKeys)-1]
	}
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("ratchet: generating salt: %w", err)
	}

	mk, nextChain := chainStep(next.chain)
	defer clear(mk[:])
	defer clear(nextChain[:])
	header, err = encodeHeader(Header{
		Version:    HeaderVersion,
		Epoch:      next.epoch,
		RatchetPub: announced.Public().Bytes(),
		Target:     next.target[:],
		KEMCT:      next.kemCT,
		PN:         next.pn,
		N:          next.n,
		Salt:       salt,
		RecvEpoch:  s.recv.epoch,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: encoding header: %w", err)
	}
	ciphertext, err = sealMessage(mk, salt, plaintext, associatedData(header, s.self, s.peer))
	if err != nil {
		return nil, nil, err
	}

	next.chain = nextChain
	next.n++
	s.send = next
	s.rootSend = root
	if fresh != nil {
		s.ownKeys = append(s.ownKeys, fresh)
		s.rotate = false
	}
	committed = true
	return header, ciphertext, nil
}

// dropOwnKeys destroys and removes the k oldest own keys.
func (s *State) dropOwnKeys(k int) {
	for _, own := range s.ownKeys[:k] {
		own.Destroy()
	}
	kept := copy(s.ownKeys, s.ownKeys[k:])
	clear(s.ownKeys[kept:])
	s.ownKeys = s.ownKeys[:kept]
}

// pendingDecrypt collects every state change of a decryption. Nothing is
// applied until the AEAD tag has verified, which makes Decrypt
// all-or-nothing: a forged, tampered, replayed or misdirected message leaves
// the state exactly as it was.
type pendingDecrypt struct {
	header      Header
	newSkipped  []skippedKey
	usedSkipped int
	recv        *recvChain
	rootRecv    *[keySize]byte
	consumedKey int
	peerPub     *sealbox.PublicKey
}

func (p *pendingDecrypt) wipe() {
	for i := range p.newSkipped {
		clear(p.newSkipped[i].key[:])
	}
	if p.recv != nil {
		clear(p.recv.chain[:])
	}
	if p.rootRecv != nil {
		clear(p.rootRecv[:])
	}
}

// Decrypt authenticates and decrypts a message from the peer. On any error
// the state is unchanged and remains usable; in particular a replayed
// message fails with [ErrReplay] because its message key was deleted when
// the message was first decrypted.
func (s *State) Decrypt(header, ciphertext []byte) (plaintext []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return nil, ErrDestroyed
	}
	h, err := ParseHeader(header)
	if err != nil {
		return nil, err
	}
	if h.RecvEpoch > s.send.epoch {
		return nil, ErrMalformedHeader
	}
	if len(ciphertext) < chacha20poly1305.Overhead {
		return nil, ErrDecrypt
	}
	ad := associatedData(header, s.peer, s.self)
	pos := position{h.Epoch, h.N}
	pending := &pendingDecrypt{header: h, usedSkipped: -1, consumedKey: -1}

	switch {
	case h.Epoch < s.recv.epoch || (h.Epoch == s.recv.epoch && h.N < s.recv.n):
		plaintext, err = s.decryptSkipped(pending, pos, ciphertext, ad)
	case h.Epoch == s.recv.epoch:
		plaintext, err = s.decryptCurrent(pending, ciphertext, ad)
	case h.Epoch == s.recv.epoch+1:
		plaintext, err = s.decryptNewEpoch(pending, ciphertext, ad)
	default:
		err = ErrUnknownTarget
	}
	if err == nil {
		err = s.preparePeerKey(pending, pos)
	}
	if err != nil {
		clear(plaintext)
		pending.wipe()
		return nil, err
	}
	s.commit(pending, pos)
	return plaintext, nil
}

// decryptSkipped handles a message from an earlier position, which can only
// be decrypted with a stored skipped key.
func (s *State) decryptSkipped(p *pendingDecrypt, pos position, ciphertext, ad []byte) ([]byte, error) {
	for i := range s.skipped {
		if s.skipped[i].pos != pos {
			continue
		}
		plaintext, err := openMessage(s.skipped[i].key, p.header.Salt, ciphertext, ad)
		if err != nil {
			return nil, err
		}
		p.usedSkipped = i
		return plaintext, nil
	}
	return nil, ErrReplay
}

// decryptCurrent handles a message of the current receiving epoch at or
// after the next expected index.
func (s *State) decryptCurrent(p *pendingDecrypt, ciphertext, ad []byte) ([]byte, error) {
	h := p.header
	if h.N-s.recv.n > MaxSkip {
		return nil, ErrTooManySkipped
	}
	if !bytes.Equal(h.Target, s.recv.target[:]) || sha256.Sum256(h.KEMCT) != s.recv.kemCTHash {
		return nil, ErrDecrypt
	}
	recv := s.recv
	p.recv = &recv
	return s.advanceAndOpen(p, h.Epoch, ciphertext, ad)
}

// decryptNewEpoch handles the first message to arrive from the peer's next
// epoch. It checks all counters before doing any KEM work. The epoch may
// target any of the own keys still held.
func (s *State) decryptNewEpoch(p *pendingDecrypt, ciphertext, ad []byte) ([]byte, error) {
	h := p.header
	previousGap := uint64(0)
	if s.recv.epoch == 0 {
		if h.PN != 0 {
			return nil, ErrMalformedHeader
		}
	} else {
		if h.PN < s.recv.n {
			return nil, ErrMalformedHeader
		}
		previousGap = uint64(h.PN - s.recv.n)
	}
	if previousGap+uint64(h.N) > MaxSkip {
		return nil, ErrTooManySkipped
	}
	keyIndex := -1
	for i, own := range s.ownKeys {
		target := targetOf(own.Public())
		if bytes.Equal(h.Target, target[:]) {
			keyIndex = i
			break
		}
	}
	if keyIndex < 0 {
		return nil, ErrUnknownTarget
	}

	if s.recv.epoch > 0 {
		chain := s.recv.chain
		for n := s.recv.n; n < h.PN; n++ {
			var mk [keySize]byte
			mk, chain = chainStep(chain)
			p.newSkipped = append(p.newSkipped, skippedKey{pos: position{s.recv.epoch, n}, key: mk})
		}
		clear(chain[:])
	}

	ss, err := sealbox.Decapsulate(s.ownKeys[keyIndex], h.KEMCT, ratchetInfo(s.peer, s.self, h.Epoch))
	if err != nil {
		return nil, ErrDecrypt
	}
	root, chain, err := kdfRK(s.rootRecv, ss)
	clear(ss[:])
	if err != nil {
		return nil, err
	}
	p.rootRecv = &root
	recv := recvChain{epoch: h.Epoch, chain: chain, kemCTHash: sha256.Sum256(h.KEMCT)}
	copy(recv.target[:], h.Target)
	clear(chain[:])
	p.recv = &recv
	p.consumedKey = keyIndex
	return s.advanceAndOpen(p, h.Epoch, ciphertext, ad)
}

// advanceAndOpen steps the pending receiving chain p.recv from its next
// index up to the message index, recording the skipped keys, and opens the
// message with the resulting key.
func (s *State) advanceAndOpen(p *pendingDecrypt, epoch uint32, ciphertext, ad []byte) ([]byte, error) {
	for p.recv.n < p.header.N {
		var mk [keySize]byte
		mk, p.recv.chain = chainStep(p.recv.chain)
		p.newSkipped = append(p.newSkipped, skippedKey{pos: position{epoch, p.recv.n}, key: mk})
		p.recv.n++
	}
	mk, next := chainStep(p.recv.chain)
	defer clear(mk[:])
	plaintext, err := openMessage(mk, p.header.Salt, ciphertext, ad)
	if err != nil {
		clear(next[:])
		return nil, err
	}
	p.recv.chain = next
	p.recv.n++
	return plaintext, nil
}

// preparePeerKey parses the announced ratchet key if the message is the
// newest one seen from the peer and announces a different key. It runs only
// after the message has authenticated, so the comparatively expensive key
// validation cannot be triggered by forgeries.
func (s *State) preparePeerKey(p *pendingDecrypt, pos position) error {
	if s.peerPub != nil && (!pos.after(s.peerPos) || bytes.Equal(p.header.RatchetPub, s.peerPub.Bytes())) {
		return nil
	}
	pub, err := sealbox.ParsePublicKey(p.header.RatchetPub)
	if err != nil {
		return ErrMalformedHeader
	}
	p.peerPub = pub
	return nil
}

// commit applies a verified decryption.
func (s *State) commit(p *pendingDecrypt, pos position) {
	if p.usedSkipped >= 0 {
		s.removeSkipped(p.usedSkipped)
	}
	if p.rootRecv != nil {
		s.rootRecv = *p.rootRecv
		clear(p.rootRecv[:])
	}
	if p.recv != nil {
		s.recv = *p.recv
		clear(p.recv.chain[:])
	}
	if len(p.newSkipped) > 0 {
		s.skipped = append(s.skipped, p.newSkipped...)
		for i := range p.newSkipped {
			clear(p.newSkipped[i].key[:])
		}
	}
	s.dropAgedSkipped()
	if excess := len(s.skipped) - MaxStoredSkipped; excess > 0 {
		s.dropOldestSkipped(excess)
	}
	if p.consumedKey >= 0 {
		s.dropOwnKeys(p.consumedKey + 1)
	}
	s.rotate = true
	s.peerAck = max(s.peerAck, p.header.RecvEpoch)
	if s.peerPub == nil || pos.after(s.peerPos) {
		if p.peerPub != nil {
			s.peerPub = p.peerPub
		}
		s.peerPos = pos
	}
}

// removeSkipped deletes the stored skipped key at index i, wiping it and the
// stale copy that shifting leaves in the backing array.
func (s *State) removeSkipped(i int) {
	clear(s.skipped[i].key[:])
	last := len(s.skipped) - 1
	copy(s.skipped[i:], s.skipped[i+1:])
	clear(s.skipped[last].key[:])
	s.skipped = s.skipped[:last]
}

// dropOldestSkipped deletes the k oldest stored skipped keys.
func (s *State) dropOldestSkipped(k int) {
	for i := range k {
		clear(s.skipped[i].key[:])
	}
	kept := copy(s.skipped, s.skipped[k:])
	for i := kept; i < len(s.skipped); i++ {
		clear(s.skipped[i].key[:])
	}
	s.skipped = s.skipped[:kept]
}

// dropAgedSkipped deletes every stored skipped key of an epoch more than
// MaxSkippedEpochAge epochs before the current receiving epoch.
func (s *State) dropAgedSkipped() {
	kept := 0
	for i := range s.skipped {
		if skippedTooOld(s.skipped[i].pos.epoch, s.recv.epoch) {
			clear(s.skipped[i].key[:])
			continue
		}
		s.skipped[kept] = s.skipped[i]
		kept++
	}
	for i := kept; i < len(s.skipped); i++ {
		clear(s.skipped[i].key[:])
	}
	s.skipped = s.skipped[:kept]
}

// skippedTooOld reports whether a skipped key of epoch must be deleted while
// the receiving epoch is current. epoch never exceeds current.
func skippedTooOld(epoch, current uint32) bool {
	return current-epoch > MaxSkippedEpochAge
}

// Destroy clears every secret held by s and makes all later calls fail with
// [ErrDestroyed]. Like [sealbox.PrivateKey.Destroy] this is best effort.
func (s *State) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.rootSend[:])
	clear(s.rootRecv[:])
	clear(s.send.chain[:])
	clear(s.recv.chain[:])
	for i := range s.skipped {
		clear(s.skipped[i].key[:])
	}
	s.skipped = nil
	for _, own := range s.ownKeys {
		own.Destroy()
	}
	s.ownKeys = nil
	s.peerPub = nil
	s.destroyed = true
}
