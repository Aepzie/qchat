package group

import (
	"fmt"

	"github.com/craguS/qchat/internal/identity"
)

// History limits.
const (
	// MaxHistoryControls is the largest number of controls in a history,
	// create included.
	MaxHistoryControls = 10000

	// MaxHistorySize bounds both the total size of the controls of a
	// history and the size of an encoded [History]. Every control other
	// than create is below 4 KiB, so a history of MaxHistoryControls
	// controls fits.
	MaxHistorySize = 40 << 20
)

// History is the ordered list of encoded controls that built a group: its
// create control followed by every control applied since, oldest first.
// Replaying it with [VerifyHistory] yields the group's current state, with
// every step verified, which is how a member who is added learns the
// membership without having to trust the adder's description of it.
//
// Its encoding, produced by [History.Marshal], is
//
//	CBOR{1: version (=1), 2: [control, ...]}
//
// with each control a byte string holding the encoded control.
type History [][]byte

// historyWire is the encoded history.
type historyWire struct {
	Version  uint8    `cbor:"1,keyasint"`
	Controls [][]byte `cbor:"2,keyasint"`
}

// Marshal returns the canonical encoding of h. It checks only the bounds
// ([ErrBadHistory]), not the controls, which [VerifyHistory] verifies.
func (h History) Marshal() ([]byte, error) {
	if err := checkHistoryBounds(h); err != nil {
		return nil, err
	}
	encoded, err := encMode.Marshal(historyWire{Version: Version, Controls: h})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(encoded) > MaxHistorySize {
		return nil, fmt.Errorf("%w: encoding of %d bytes", ErrBadHistory, len(encoded))
	}
	return encoded, nil
}

// UnmarshalHistory decodes a history encoded by [History.Marshal]. It
// accepts only the canonical encoding of a version 1 history within the
// bounds; the controls are not parsed or verified (use [VerifyHistory]).
// Errors wrap [ErrMalformed] or [ErrBadHistory].
func UnmarshalHistory(b []byte) (History, error) {
	if len(b) == 0 || len(b) > MaxHistorySize {
		return nil, fmt.Errorf("%w: history size %d out of range", ErrMalformed, len(b))
	}
	var wire historyWire
	if err := decodeCanonicalWith(historyDecMode, b, &wire); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if wire.Version != Version {
		return nil, fmt.Errorf("%w: history version %d", ErrMalformed, wire.Version)
	}
	if err := checkHistoryBounds(wire.Controls); err != nil {
		return nil, err
	}
	return History(wire.Controls), nil
}

// Verify is [VerifyHistory] applied to h.
func (h History) Verify(bundle func(identity.ID) (*identity.Bundle, error)) (State, error) {
	return VerifyHistory(h, bundle)
}

// checkHistoryBounds requires 1 to MaxHistoryControls controls of at most
// MaxHistorySize bytes in total.
func checkHistoryBounds(controls [][]byte) error {
	if len(controls) == 0 || len(controls) > MaxHistoryControls {
		return fmt.Errorf("%w: %d controls, want 1 to %d", ErrBadHistory, len(controls), MaxHistoryControls)
	}
	total := 0
	for _, raw := range controls {
		total += len(raw)
		if total > MaxHistorySize {
			return fmt.Errorf("%w: more than %d bytes of controls", ErrBadHistory, MaxHistorySize)
		}
	}
	return nil
}

// VerifyHistory replays controls, a group's history from its create control
// on, and returns the state it ends in. Every control is parsed and applied
// with [Apply] to the state of the previous one, so each signature, epoch,
// state hash and rule is checked exactly as for a control received live;
// the first control must be a create.
//
// bundle returns the verified bundle of an actor (for example from
// [identity.ParseBundleForID]); it is called once per distinct actor and
// its errors are returned wrapped. A history with no controls, more than
// [MaxHistoryControls] or more than [MaxHistorySize] bytes of controls is
// rejected with [ErrBadHistory] before any control is parsed. Other errors
// are those of [ParseControl] and [Apply], wrapped with the index of the
// failing control.
//
// The result is authentic only as far as its signers are: a verified
// history proves that every change was signed by an actor entitled to it at
// that point, not that it is the history the other members hold. Callers
// therefore accept a history only from a member they would accept the final
// control from (see [VerifyJoin]), and rely on [State.Binding] to detect
// forks.
func VerifyHistory(controls [][]byte, bundle func(identity.ID) (*identity.Bundle, error)) (State, error) {
	if err := checkHistoryBounds(controls); err != nil {
		return State{}, err
	}
	if bundle == nil {
		return State{}, fmt.Errorf("%w: no bundle source", ErrBadHistory)
	}
	bundles := make(map[identity.ID]*identity.Bundle)
	var cur *State
	for i, raw := range controls {
		c, err := ParseControl(raw)
		if err != nil {
			return State{}, fmt.Errorf("group: history control %d: %w", i, err)
		}
		actor, known := bundles[c.Actor]
		if !known {
			if actor, err = bundle(c.Actor); err != nil {
				return State{}, fmt.Errorf("group: history control %d: actor bundle: %w", i, err)
			}
			bundles[c.Actor] = actor
		}
		next, err := Apply(cur, c, actor)
		if err != nil {
			return State{}, fmt.Errorf("group: history control %d: %w", i, err)
		}
		cur = &next
	}
	return *cur, nil
}

// VerifyJoin verifies the history a member self receives when it is added
// to a group: controls must be the complete history from create and end with
// the control by which adder added self. It returns the resulting state, of
// which self is a member.
//
// adder must be the identity the history arrived from over its pairwise
// session, so that the joining member trusts the group exactly as far as it
// trusts the member who added it. A history that verifies but does not end
// with that add is rejected with [ErrBadHistory]; other errors are those of
// [VerifyHistory].
//
// A client that receives the history up to the state before the add and the
// add control separately uses [VerifyHistory] followed by [Apply] instead,
// with the same checks on the add.
func VerifyJoin(controls [][]byte, self, adder identity.ID, bundle func(identity.ID) (*identity.Bundle, error)) (State, error) {
	state, err := VerifyHistory(controls, bundle)
	if err != nil {
		return State{}, err
	}
	last, err := ParseControl(controls[len(controls)-1])
	if err != nil {
		return State{}, err
	}
	if last.Op != OpAdd || last.Target != self {
		return State{}, fmt.Errorf("%w: history does not end with the add of the joining member", ErrBadHistory)
	}
	if last.Actor != adder {
		return State{}, fmt.Errorf("%w: joining member was added by someone other than the sender", ErrBadHistory)
	}
	if !state.IsMember(self) {
		return State{}, fmt.Errorf("%w: joining member is not a member", ErrBadHistory)
	}
	return state, nil
}
