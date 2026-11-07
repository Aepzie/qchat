package group

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"
	"unicode"
	"unicode/utf8"

	"github.com/craguS/qchat/internal/identity"
)

// Format parameters.
const (
	// Version is the format version of encoded states and controls.
	Version = 1

	// MaxMembers is the largest number of members a group may have. It
	// bounds the size of controls and states and the work of fanning a
	// control out over pairwise sessions.
	MaxMembers = 256

	// MaxNameRunes is the longest group name, in runes.
	MaxNameRunes = 64

	// MaxStateSize is the largest encoded state [UnmarshalState] accepts.
	// A state with MaxMembers members, all of them admins, and a name of
	// MaxNameRunes four-byte runes is about 17.8 KiB.
	MaxStateSize = 32 << 10
)

// ID names a group. It is chosen uniformly at random by the creator, so it
// reveals nothing about the group and collides with negligible probability.
// The zero ID is never a valid group ID.
type ID [32]byte

// IsZero reports whether id is the zero ID.
func (id ID) IsZero() bool {
	return id == ID{}
}

// State is the membership state of a group at one epoch.
//
// A valid state has a non-zero GroupID, a valid name, an epoch of at least
// 1, at most [MaxMembers] members sorted in ascending byte order without
// duplicates or zero IDs, and admins in the same order that are a non-empty
// subset of the members. The only exception is a dissolved group, the state
// after its last member left: it has neither members nor admins, and every
// further control is rejected because nobody is a member.
//
// States returned by this package are always valid and own their slices.
// A State must be treated as a value: modifying the slices of a state
// obtained from this package corrupts it.
type State struct {
	GroupID ID
	Name    string
	Epoch   uint64
	Members []identity.ID
	Admins  []identity.ID
}

// stateWire is the encoded state:
//
//	CBOR{1: version (=1), 2: group ID, 3: name, 4: epoch,
//	     5: members, 6: admins}
type stateWire struct {
	Version uint8         `cbor:"1,keyasint"`
	GroupID ID            `cbor:"2,keyasint"`
	Name    string        `cbor:"3,keyasint"`
	Epoch   uint64        `cbor:"4,keyasint"`
	Members []identity.ID `cbor:"5,keyasint"`
	Admins  []identity.ID `cbor:"6,keyasint"`
}

func (s State) wire() stateWire {
	return stateWire{Version: Version, GroupID: s.GroupID, Name: s.Name, Epoch: s.Epoch, Members: s.Members, Admins: s.Admins}
}

// Hash returns the SHA-256 hash of the canonical encoding of s (the bytes
// [State.Marshal] returns for a valid state). Controls commit to the hash of
// the state they apply to, so a control can only be applied by a receiver
// whose view of the group (name, epoch, members and admins) is identical to
// the actor's.
//
// Hash does not validate s. If s cannot be encoded at all, the zero hash is
// returned; no well-formed control carries the zero hash for an existing
// group, so such a state matches nothing.
func (s State) Hash() [32]byte {
	encoded, err := encMode.Marshal(s.wire())
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(encoded)
}

// IsMember reports whether id is a member of s. It relies on s.Members
// being sorted.
func (s State) IsMember(id identity.ID) bool {
	return containsID(s.Members, id)
}

// IsAdmin reports whether id is an admin of s. It relies on s.Admins being
// sorted.
func (s State) IsAdmin(id identity.ID) bool {
	return containsID(s.Admins, id)
}

// Marshal validates s and returns its canonical encoding. It returns an
// error wrapping [ErrMalformed], [ErrInvalidName] or [ErrTooManyMembers] for
// an invalid state.
func (s State) Marshal() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	encoded, err := encMode.Marshal(s.wire())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return encoded, nil
}

// UnmarshalState decodes a state encoded by [State.Marshal]. It accepts only
// the canonical encoding of a valid version 1 state no larger than
// [MaxStateSize], so a state read back from storage satisfies the same
// invariants as one produced by [Apply].
func UnmarshalState(b []byte) (State, error) {
	if len(b) == 0 || len(b) > MaxStateSize {
		return State{}, fmt.Errorf("%w: state size %d out of range", ErrMalformed, len(b))
	}
	var wire stateWire
	if err := decodeCanonical(b, &wire); err != nil {
		return State{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if wire.Version != Version {
		return State{}, fmt.Errorf("%w: state version %d", ErrMalformed, wire.Version)
	}
	s := State{GroupID: wire.GroupID, Name: wire.Name, Epoch: wire.Epoch, Members: wire.Members, Admins: wire.Admins}
	if err := s.validate(); err != nil {
		return State{}, err
	}
	return s, nil
}

// validate checks every invariant documented on [State].
func (s State) validate() error {
	if s.GroupID.IsZero() {
		return fmt.Errorf("%w: zero group ID", ErrMalformed)
	}
	if err := validateName(s.Name); err != nil {
		return err
	}
	if s.Epoch == 0 {
		return fmt.Errorf("%w: zero epoch", ErrMalformed)
	}
	if err := validateIDList(s.Members); err != nil {
		return err
	}
	if err := validateIDList(s.Admins); err != nil {
		return err
	}
	if len(s.Admins) == 0 && len(s.Members) > 0 {
		return fmt.Errorf("%w: group without admin", ErrMalformed)
	}
	for _, admin := range s.Admins {
		if !s.IsMember(admin) {
			return fmt.Errorf("%w: admin is not a member", ErrMalformed)
		}
	}
	return nil
}

// clone returns a deep copy of s, so that a derived state never aliases the
// caller's slices.
func (s State) clone() State {
	s.Members = slices.Clone(s.Members)
	s.Admins = slices.Clone(s.Admins)
	return s
}

// validateName enforces the name rules. Control characters could break
// terminal output, and format characters (bidirectional overrides and
// isolates, zero-width characters) let a name render differently from its
// content or reorder surrounding text, which an attacker could use to make
// one group impersonate another in the user interface.
func validateName(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: not valid UTF-8", ErrInvalidName)
	}
	runes := utf8.RuneCountInString(name)
	if runes < 1 || runes > MaxNameRunes {
		return fmt.Errorf("%w: %d runes, want 1 to %d", ErrInvalidName, runes, MaxNameRunes)
	}
	for _, r := range name {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return fmt.Errorf("%w: forbidden character U+%04X", ErrInvalidName, r)
		}
	}
	return nil
}

// validateIDList requires ids to hold at most MaxMembers non-zero IDs in
// strictly ascending order. Strict order makes the list canonical and rules
// out duplicates; the zero ID means "no ID" and can never be a member.
func validateIDList(ids []identity.ID) error {
	if len(ids) > MaxMembers {
		return fmt.Errorf("%w: %d IDs, at most %d allowed", ErrTooManyMembers, len(ids), MaxMembers)
	}
	for i, id := range ids {
		if id.IsZero() {
			return fmt.Errorf("%w: zero member ID", ErrMalformed)
		}
		if i > 0 && compareIDs(ids[i-1], id) >= 0 {
			return fmt.Errorf("%w: member IDs not strictly ascending", ErrMalformed)
		}
	}
	return nil
}

func compareIDs(a, b identity.ID) int {
	return bytes.Compare(a[:], b[:])
}

func containsID(sorted []identity.ID, id identity.ID) bool {
	_, found := slices.BinarySearchFunc(sorted, id, compareIDs)
	return found
}

// insertID returns a copy of sorted with id inserted in order.
func insertID(sorted []identity.ID, id identity.ID) []identity.ID {
	i, _ := slices.BinarySearchFunc(sorted, id, compareIDs)
	return slices.Insert(slices.Clone(sorted), i, id)
}

// removeID returns a copy of sorted without id.
func removeID(sorted []identity.ID, id identity.ID) []identity.ID {
	i, found := slices.BinarySearchFunc(sorted, id, compareIDs)
	if !found {
		return slices.Clone(sorted)
	}
	return slices.Delete(slices.Clone(sorted), i, i+1)
}
