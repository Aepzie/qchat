package senderkey

import (
	"slices"
	"sync"

	"github.com/Aepzie/qchat/internal/identity"
)

// HeaderCandidate is one header key a receiving member holds: the header key
// of one generation of one sender in one group, as distributed with that
// generation. Key is secret.
type HeaderCandidate struct {
	Group      GroupID
	Sender     identity.ID
	Generation uint32
	Key        [HeaderKeySize]byte
}

// matches reports whether h is a header the generation of c can have
// produced.
func (c *HeaderCandidate) matches(h header) bool {
	return h.group == c.Group && h.sender == c.Sender && h.generation == c.Generation
}

// OpenHeader finds which of candidates opens the encrypted header of a group
// envelope by trial decryption, and returns its index and the decrypted
// header. The relay cannot do this, which is the point: the header names the
// group, sender, generation and position of the message, and only members
// holding the generation's header key can read it.
//
// Each candidate costs one XChaCha20-Poly1305 authentication over a short
// fixed-size header (one HChaCha20, one ChaCha20 block and Poly1305 over
// about 200 bytes, roughly a microsecond), and the first that opens ends the
// search. A member has at most one current and a few superseded generations
// per other member and group, so the candidates number at most a small
// multiple of groups x 256; callers should narrow them to the generations of
// the sender the relay names when it does. A header that opens under a
// candidate's key but names another group, sender or generation than the
// candidate is skipped; only a holder of that key can produce one.
//
// The header is not authenticated by a signature until [Receiver.Decrypt]
// succeeds. Errors are [ErrMalformed] for an envelope of the wrong shape and
// [ErrNoHeaderKey] when no candidate fits; the index is then -1.
func OpenHeader(encoded []byte, candidates []HeaderCandidate) (int, Header, error) {
	env, err := parseEnvelope(encoded)
	if err != nil {
		return -1, Header{}, err
	}
	for i := range candidates {
		h, ok := env.openWith(&candidates[i].Key)
		if ok && candidates[i].matches(h) {
			return i, h.public(), nil
		}
	}
	return -1, Header{}, ErrNoHeaderKey
}

// openWith decrypts and parses the header of env under key.
func (env envelope) openWith(key *[HeaderKeySize]byte) (header, bool) {
	encoded, ok := openHeader(key, env.nonce, env.encHeader)
	if !ok {
		return header{}, false
	}
	h, err := parseHeader(encoded)
	clear(encoded)
	if err != nil {
		return header{}, false
	}
	return h, true
}

// HeaderKeyring is a set of header candidates that routes incoming group
// envelopes, a convenience around [OpenHeader] for callers that keep their
// header keys in memory. Adding a candidate for a (group, sender,
// generation) that is already present replaces it. The zero value is an
// empty keyring ready to use. It is safe for concurrent use.
type HeaderKeyring struct {
	mu         sync.Mutex
	candidates []HeaderCandidate
}

// Add inserts c, replacing any candidate for the same group, sender and
// generation.
func (k *HeaderKeyring) Add(c HeaderCandidate) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range k.candidates {
		if k.candidates[i].Group == c.Group && k.candidates[i].Sender == c.Sender && k.candidates[i].Generation == c.Generation {
			k.candidates[i] = c
			return
		}
	}
	k.candidates = append(k.candidates, c)
}

// Remove deletes the candidate for one generation of one sender in group.
func (k *HeaderKeyring) Remove(group GroupID, sender identity.ID, generation uint32) {
	k.removeFunc(func(c *HeaderCandidate) bool {
		return c.Group == group && c.Sender == sender && c.Generation == generation
	})
}

// RemoveGroup deletes every candidate of group.
func (k *HeaderKeyring) RemoveGroup(group GroupID) {
	k.removeFunc(func(c *HeaderCandidate) bool { return c.Group == group })
}

// removeFunc deletes the candidates for which drop is true. slices.DeleteFunc
// zeroes the vacated elements, so no deleted key stays in the backing array.
func (k *HeaderKeyring) removeFunc(drop func(*HeaderCandidate) bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.candidates = slices.DeleteFunc(k.candidates, func(c HeaderCandidate) bool {
		return drop(&c)
	})
}

// Len returns the number of candidates in k.
func (k *HeaderKeyring) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.candidates)
}

// Open routes an envelope with [OpenHeader] over the candidates of k.
func (k *HeaderKeyring) Open(encoded []byte) (Header, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, h, err := OpenHeader(encoded, k.candidates)
	return h, err
}

// Destroy overwrites and deletes every candidate. It is best effort; k stays
// usable and empty.
func (k *HeaderKeyring) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	clear(k.candidates[:cap(k.candidates)])
	k.candidates = nil
}
