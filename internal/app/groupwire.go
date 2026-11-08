package app

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/Aepzie/qchat/internal/group"
	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/store/clientdb"
)

// Encodings private to the client.
//
// The body of a pairwise e2e.KindGroupControl message is
//
//	{1: Control (optional), 2: History (optional)}
//
// Control is a signed control of package group. History is a run of earlier
// signed controls of one group, oldest first, sent only to a member being
// added: the adder sends the group's whole control history from create in
// as many messages as the pairwise body size requires, and then the add
// control itself. The new member replays the history (see verifyHistory)
// and accepts the group only if the replay, followed by the add, ends in a
// state that contains it. Every message carries at least one of the two
// fields.
//
// clientdb stores the State of a group opaquely; the App stores there
//
//	{1: State, 3: History, 4: Previous (optional), 5: OwnGeneration,
//	 6: Installed, 7: Invite}
//
// State is group.State.Marshal; History every control applied so far,
// oldest first, for onboarding members; Previous the state before the last
// applied control, kept while the group is at that epoch to resolve a
// conflicting control; OwnGeneration the highest own sender key generation
// ever started, so that generations never repeat even after the keys were
// deleted; Installed, per member, the sender key generations stored for it,
// ascending, with the time each was frozen (Unix seconds, 0 while it is
// the newest); Invite whether the user has not yet accepted a group it was
// put into by someone who is not a contact.

const (
	// groupIDPrefix starts the string form of a group ID used by the
	// interface: the prefix followed by 64 lowercase hex digits.
	groupIDPrefix = "grp-"
	// maxGroupBlob bounds the encodings of this file before decoding.
	maxGroupBlob = clientdb.MaxGroupStateSize
	// maxHistory bounds the number of controls in a group's history.
	maxHistory = 4096
	// maxInstalledGenerations bounds the generations kept per member; the
	// oldest are deleted first.
	maxInstalledGenerations = 8
)

var (
	groupEnc cbor.EncMode
	groupDec cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.IndefLength = cbor.IndefLengthForbidden
	encOpts.TagsMd = cbor.TagsForbidden
	var err error
	if groupEnc, err = encOpts.EncMode(); err != nil {
		panic("app: invalid CBOR encoding options: " + err.Error())
	}
	decOpts := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		MaxNestedLevels:   4,
		MaxArrayElements:  maxHistory,
		MaxMapPairs:       16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}
	if groupDec, err = decOpts.DecMode(); err != nil {
		panic("app: invalid CBOR decoding options: " + err.Error())
	}
}

// errMalformedGroupData reports a group encoding of this file that does not
// decode canonically.
var errMalformedGroupData = errors.New("app: malformed group data")

// decodeGroupBlob strictly decodes b into v and requires b to be the
// canonical encoding of v.
func decodeGroupBlob(b []byte, v any) error {
	if len(b) > maxGroupBlob {
		return errMalformedGroupData
	}
	if err := groupDec.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %w", errMalformedGroupData, err)
	}
	canonical, err := groupEnc.Marshal(v)
	if err != nil || !bytes.Equal(canonical, b) {
		return errMalformedGroupData
	}
	return nil
}

// controlMessage is the body of a group control message.
type controlMessage struct {
	Control []byte   `cbor:"1,keyasint,omitempty"`
	History [][]byte `cbor:"2,keyasint,omitempty"`
}

func marshalControlMessage(m controlMessage) ([]byte, error) {
	return groupEnc.Marshal(m)
}

func parseControlMessage(b []byte) (controlMessage, error) {
	var m controlMessage
	if err := decodeGroupBlob(b, &m); err != nil {
		return controlMessage{}, err
	}
	if len(m.Control) == 0 && len(m.History) == 0 {
		return controlMessage{}, errMalformedGroupData
	}
	for _, c := range m.History {
		if len(c) == 0 {
			return controlMessage{}, errMalformedGroupData
		}
	}
	return m, nil
}

// historyChunks splits controls into runs whose control messages fit
// limit bytes. A single control is always small enough (group.MaxControlSize).
func historyChunks(controls [][]byte, limit int) [][][]byte {
	var chunks [][][]byte
	var cur [][]byte
	size := 0
	for _, c := range controls {
		cost := len(c) + 8
		if len(cur) > 0 && size+cost > limit {
			chunks = append(chunks, cur)
			cur, size = nil, 0
		}
		cur = append(cur, c)
		size += cost
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks
}

// installedWire lists the stored sender key generations of one member.
type installedWire struct {
	Member      []byte   `cbor:"1,keyasint"`
	Generations []uint32 `cbor:"2,keyasint"`
	FrozenAt    []int64  `cbor:"3,keyasint"`
}

// installedGen is one stored sender key generation of a member.
type installedGen struct {
	gen uint32
	// frozenAt is when a newer generation superseded it, or zero.
	frozenAt int64
}

// storedGroup is what the App keeps in clientdb.Group.State.
type storedGroup struct {
	State         []byte          `cbor:"1,keyasint"`
	History       [][]byte        `cbor:"3,keyasint"`
	Previous      []byte          `cbor:"4,keyasint,omitempty"`
	OwnGeneration uint32          `cbor:"5,keyasint"`
	Installed     []installedWire `cbor:"6,keyasint"`
	Invite        bool            `cbor:"7,keyasint"`
}

// groupEntry is a decoded stored group.
type groupEntry struct {
	state   group.State
	history [][]byte
	// previous is the state before the last applied control, if kept.
	previous      *group.State
	ownGeneration uint32
	installed     map[identity.ID][]installedGen
	invite        bool
	left          bool
}

// lastInstalled returns the newest generation stored for member, or 0.
func (e groupEntry) lastInstalled(member identity.ID) uint32 {
	gens := e.installed[member]
	if len(gens) == 0 {
		return 0
	}
	return gens[len(gens)-1].gen
}

// hasInstalled reports whether generation gen of member is stored.
func (e groupEntry) hasInstalled(member identity.ID, gen uint32) bool {
	return slices.ContainsFunc(e.installed[member], func(g installedGen) bool { return g.gen == gen })
}

func marshalGroupEntry(e groupEntry) ([]byte, error) {
	st, err := e.state.Marshal()
	if err != nil {
		return nil, err
	}
	w := storedGroup{State: st, History: e.history, OwnGeneration: e.ownGeneration, Invite: e.invite, Installed: []installedWire{}}
	if w.History == nil {
		w.History = [][]byte{}
	}
	if e.previous != nil {
		if w.Previous, err = e.previous.Marshal(); err != nil {
			return nil, err
		}
	}
	members := make([]identity.ID, 0, len(e.installed))
	for id, gens := range e.installed {
		if len(gens) > 0 {
			members = append(members, id)
		}
	}
	slices.SortFunc(members, func(x, y identity.ID) int { return bytes.Compare(x[:], y[:]) })
	for _, id := range members {
		in := installedWire{Member: id[:]}
		for _, g := range e.installed[id] {
			in.Generations = append(in.Generations, g.gen)
			in.FrozenAt = append(in.FrozenAt, g.frozenAt)
		}
		w.Installed = append(w.Installed, in)
	}
	return groupEnc.Marshal(w)
}

func parseGroupEntry(b []byte, left bool) (groupEntry, error) {
	var w storedGroup
	if err := decodeGroupBlob(b, &w); err != nil {
		return groupEntry{}, err
	}
	st, err := group.UnmarshalState(w.State)
	if err != nil {
		return groupEntry{}, err
	}
	e := groupEntry{state: st, history: w.History, ownGeneration: w.OwnGeneration,
		invite: w.Invite, left: left, installed: map[identity.ID][]installedGen{}}
	if w.Previous != nil {
		prev, err := group.UnmarshalState(w.Previous)
		if err != nil {
			return groupEntry{}, err
		}
		e.previous = &prev
	}
	for _, in := range w.Installed {
		if len(in.Member) != identity.IDSize || len(in.Generations) == 0 || len(in.FrozenAt) != len(in.Generations) || !slices.IsSorted(in.Generations) {
			return groupEntry{}, errMalformedGroupData
		}
		gens := make([]installedGen, len(in.Generations))
		for i, g := range in.Generations {
			gens[i] = installedGen{gen: g, frozenAt: in.FrozenAt[i]}
		}
		e.installed[identity.ID(in.Member)] = gens
	}
	return e, nil
}

// groupKey returns the interface's form of a group ID.
func groupKey(id group.ID) string { return groupIDPrefix + hex.EncodeToString(id[:]) }

// isGroupKey reports whether s is meant as a group ID (it may still be
// malformed).
func isGroupKey(s string) bool { return strings.HasPrefix(s, groupIDPrefix) }

// parseGroupKey parses the interface's form of a group ID.
func parseGroupKey(s string) (group.ID, error) {
	raw, ok := strings.CutPrefix(s, groupIDPrefix)
	var id group.ID
	if !ok || len(raw) != 2*len(id) || strings.ToLower(raw) != raw {
		return group.ID{}, ErrUnknownGroup
	}
	if _, err := hex.Decode(id[:], []byte(raw)); err != nil || id.IsZero() {
		return group.ID{}, ErrUnknownGroup
	}
	return id, nil
}
