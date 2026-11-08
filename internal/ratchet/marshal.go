package ratchet

import (
	"bytes"
	"crypto/sha256"

	"github.com/Aepzie/qchat/internal/crypto/sealbox"
)

// StateVersion is the version of the serialised state format. Version 1
// states are rejected: their sessions must be started again.
const StateVersion = 2

// stateWire is the serialised form of a [State]: canonical CBOR with integer
// keys. Optional fields are omitted when zero, so every state has exactly one
// encoding.
type stateWire struct {
	Version       uint8         `cbor:"1,keyasint"`
	Role          uint8         `cbor:"2,keyasint"`
	Self          []byte        `cbor:"3,keyasint"`
	Peer          []byte        `cbor:"4,keyasint"`
	RootSend      []byte        `cbor:"5,keyasint"`
	RootRecv      []byte        `cbor:"6,keyasint"`
	SendEpoch     uint32        `cbor:"7,keyasint,omitempty"`
	SendChain     []byte        `cbor:"8,keyasint,omitempty"`
	SendN         uint32        `cbor:"9,keyasint,omitempty"`
	SendPN        uint32        `cbor:"10,keyasint,omitempty"`
	SendTarget    []byte        `cbor:"11,keyasint,omitempty"`
	SendKEMCT     []byte        `cbor:"12,keyasint,omitempty"`
	PeerPub       []byte        `cbor:"13,keyasint,omitempty"`
	PeerPubEpoch  uint32        `cbor:"14,keyasint,omitempty"`
	PeerPubN      uint32        `cbor:"15,keyasint,omitempty"`
	RecvEpoch     uint32        `cbor:"16,keyasint,omitempty"`
	RecvChain     []byte        `cbor:"17,keyasint,omitempty"`
	RecvN         uint32        `cbor:"18,keyasint,omitempty"`
	RecvTarget    []byte        `cbor:"19,keyasint,omitempty"`
	RecvKEMCTHash []byte        `cbor:"20,keyasint,omitempty"`
	OwnKeys       [][]byte      `cbor:"21,keyasint,omitempty"`
	Skipped       []skippedWire `cbor:"22,keyasint,omitempty"`
	Rotate        bool          `cbor:"23,keyasint,omitempty"`
	PeerAck       uint32        `cbor:"24,keyasint,omitempty"`
}

type skippedWire struct {
	_     struct{} `cbor:",toarray"`
	Epoch uint32
	N     uint32
	Key   []byte
}

// Marshal serialises the complete state, including the root, chain, skipped
// message and own ratchet private keys. The result is as sensitive as the
// session itself: the caller must encrypt it before storing it (the client
// database does) and should clear it after use. To preserve forward secrecy,
// older serialisations must be overwritten, not kept, once a newer one has
// been written.
func (s *State) Marshal() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return nil, ErrDestroyed
	}
	w := stateWire{
		Version:  StateVersion,
		Role:     uint8(s.role),
		Self:     s.self[:],
		Peer:     s.peer[:],
		RootSend: s.rootSend[:],
		RootRecv: s.rootRecv[:],
		Rotate:   s.rotate,
		PeerAck:  s.peerAck,
	}
	if s.send.epoch > 0 {
		w.SendEpoch = s.send.epoch
		w.SendChain = s.send.chain[:]
		w.SendN = s.send.n
		w.SendPN = s.send.pn
		w.SendTarget = s.send.target[:]
		w.SendKEMCT = s.send.kemCT
	}
	if s.peerPub != nil {
		w.PeerPub = s.peerPub.Bytes()
		w.PeerPubEpoch = s.peerPos.epoch
		w.PeerPubN = s.peerPos.n
	}
	if s.recv.epoch > 0 {
		w.RecvEpoch = s.recv.epoch
		w.RecvChain = s.recv.chain[:]
		w.RecvN = s.recv.n
		w.RecvTarget = s.recv.target[:]
		w.RecvKEMCTHash = s.recv.kemCTHash[:]
	}
	for _, own := range s.ownKeys {
		w.OwnKeys = append(w.OwnKeys, own.Bytes())
	}
	defer func() {
		for _, seed := range w.OwnKeys {
			clear(seed)
		}
	}()
	for _, sk := range s.skipped {
		w.Skipped = append(w.Skipped, skippedWire{Epoch: sk.pos.epoch, N: sk.pos.n, Key: sk.key[:]})
	}
	return encMode.Marshal(w)
}

// Unmarshal restores a state serialised by [State.Marshal]. It accepts only
// the canonical encoding and checks every invariant the state relies on, so
// a corrupted or hand-crafted serialisation is rejected with
// [ErrInvalidState] rather than producing a state that misbehaves later.
func Unmarshal(encoded []byte) (*State, error) {
	var w stateWire
	if err := stateDecMode.Unmarshal(encoded, &w); err != nil {
		return nil, ErrInvalidState
	}
	defer func() {
		for _, seed := range w.OwnKeys {
			clear(seed)
		}
		clear(w.RootSend)
		clear(w.RootRecv)
		clear(w.SendChain)
		clear(w.RecvChain)
		for _, sk := range w.Skipped {
			clear(sk.Key)
		}
	}()
	canonical, err := encMode.Marshal(w)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		return nil, ErrInvalidState
	}
	clear(canonical)

	return stateFromWire(&w)
}

func stateFromWire(w *stateWire) (*State, error) {
	role := Role(w.Role)
	if w.Version != StateVersion || !role.valid() {
		return nil, ErrInvalidState
	}
	if !hasLen(w.Self, 32) || !hasLen(w.Peer, 32) || !hasLen(w.RootSend, keySize) || !hasLen(w.RootRecv, keySize) {
		return nil, ErrInvalidState
	}
	s := &State{role: role}
	copy(s.self[:], w.Self)
	copy(s.peer[:], w.Peer)
	copy(s.rootSend[:], w.RootSend)
	copy(s.rootRecv[:], w.RootRecv)

	if w.SendEpoch == 0 {
		if w.SendChain != nil || w.SendN != 0 || w.SendPN != 0 || w.SendTarget != nil || w.SendKEMCT != nil {
			return nil, ErrInvalidState
		}
	} else {
		if !hasLen(w.SendChain, keySize) || !hasLen(w.SendTarget, TargetSize) || !hasLen(w.SendKEMCT, sealbox.EncapsulatedKeySize) {
			return nil, ErrInvalidState
		}
		s.send = sendChain{epoch: w.SendEpoch, n: w.SendN, pn: w.SendPN, kemCT: append([]byte(nil), w.SendKEMCT...)}
		copy(s.send.chain[:], w.SendChain)
		copy(s.send.target[:], w.SendTarget)
	}

	if w.PeerPub == nil {
		if w.PeerPubEpoch != 0 || w.PeerPubN != 0 || role == Initiator {
			return nil, ErrInvalidState
		}
	} else {
		pub, err := sealbox.ParsePublicKey(w.PeerPub)
		if err != nil {
			return nil, ErrInvalidState
		}
		s.peerPub = pub
		s.peerPos = position{w.PeerPubEpoch, w.PeerPubN}
	}
	if s.send.epoch > 0 && s.peerPub == nil {
		return nil, ErrInvalidState
	}

	if w.RecvEpoch == 0 {
		if w.RecvChain != nil || w.RecvN != 0 || w.RecvTarget != nil || w.RecvKEMCTHash != nil {
			return nil, ErrInvalidState
		}
		if role == Responder && w.PeerPub != nil {
			return nil, ErrInvalidState
		}
	} else {
		if !hasLen(w.RecvChain, keySize) || !hasLen(w.RecvTarget, TargetSize) || !hasLen(w.RecvKEMCTHash, sha256.Size) || w.RecvN == 0 || w.PeerPub == nil {
			return nil, ErrInvalidState
		}
		s.recv = recvChain{epoch: w.RecvEpoch, n: w.RecvN}
		copy(s.recv.chain[:], w.RecvChain)
		copy(s.recv.target[:], w.RecvTarget)
		copy(s.recv.kemCTHash[:], w.RecvKEMCTHash)
	}

	if len(w.OwnKeys) > MaxUnconsumedOwnKeys || (len(w.OwnKeys) == 0 && !w.Rotate) || (w.Rotate && s.recv.epoch == 0) {
		return nil, ErrInvalidState
	}
	s.rotate = w.Rotate
	if w.PeerAck > s.send.epoch {
		s.Destroy()
		return nil, ErrInvalidState
	}
	s.peerAck = w.PeerAck
	for _, seed := range w.OwnKeys {
		own, err := sealbox.NewPrivateKey(seed)
		if err != nil {
			s.Destroy()
			return nil, ErrInvalidState
		}
		s.ownKeys = append(s.ownKeys, own)
	}

	if len(w.Skipped) > MaxStoredSkipped {
		s.Destroy()
		return nil, ErrInvalidState
	}
	seen := make(map[position]struct{}, len(w.Skipped))
	for _, sk := range w.Skipped {
		pos := position{sk.Epoch, sk.N}
		_, dup := seen[pos]
		current := sk.Epoch == s.recv.epoch && sk.N >= s.recv.n
		if dup || sk.Epoch == 0 || sk.Epoch > s.recv.epoch || current || skippedTooOld(sk.Epoch, s.recv.epoch) || len(sk.Key) != keySize {
			s.Destroy()
			return nil, ErrInvalidState
		}
		seen[pos] = struct{}{}
		entry := skippedKey{pos: pos}
		copy(entry.key[:], sk.Key)
		s.skipped = append(s.skipped, entry)
	}
	return s, nil
}

// hasLen reports whether b has exactly n bytes.
func hasLen(b []byte, n int) bool {
	return len(b) == n
}
