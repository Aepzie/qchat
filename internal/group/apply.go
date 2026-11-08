package group

import (
	"fmt"
	"math"
	"slices"

	"github.com/Aepzie/qchat/internal/identity"
)

// Apply verifies c and returns the state that results from applying it to
// cur. cur is nil exactly when c creates a group. actor must be the verified
// bundle of c.Actor (as returned by [identity.ParseBundleForID]); it is the
// key the signature is checked against.
//
// Apply checks, in this order:
//
//  1. c is well formed and its exported fields equal those encoded in
//     c.Raw ([ErrMalformed]); Apply only ever acts on what is signed.
//  2. actor belongs to c.Actor and the signature verifies under
//     [identity.ContextGroupControl] ([ErrBadSignature]). No rule below is
//     evaluated for an unauthenticated control, so the error an attacker
//     can provoke without a valid signature reveals nothing about the state.
//  3. cur is valid ([ErrMalformed]), create comes without a state and every
//     other operation with one ([ErrInvalidOp]), the group ID and state hash
//     match cur ([ErrStateMismatch]) and the epoch is cur.Epoch+1, or 1 for
//     create ([ErrStaleEpoch]). Binding each control to the exact previous
//     state rules out replays, reordering and forks silently merging.
//  4. The actor may perform the operation: it is a member
//     ([ErrNotMember]) and, except for leave, an admin ([ErrNotAdmin]); the
//     operation fits the state ([ErrInvalidOp], [ErrNotMember] for a target
//     that is not a member, [ErrTooManyMembers]); and the group keeps an
//     admin while it has members ([ErrLastAdmin]).
//
// Apply never modifies cur or c, and the returned state shares no memory
// with them.
func Apply(cur *State, c *Control, actor *identity.Bundle) (State, error) {
	if c == nil {
		return State{}, fmt.Errorf("%w: nil control", ErrMalformed)
	}
	parsed, err := ParseControl(c.Raw)
	if err != nil {
		return State{}, err
	}
	if !parsed.sameFields(c) {
		return State{}, fmt.Errorf("%w: control fields differ from its encoding", ErrMalformed)
	}
	if err := verify(parsed, actor); err != nil {
		return State{}, err
	}
	return transition(cur, parsed)
}

// sameFields reports whether the exported fields of c and other are equal,
// except Raw.
func (c *Control) sameFields(other *Control) bool {
	return c.GroupID == other.GroupID && c.Epoch == other.Epoch && c.Actor == other.Actor &&
		c.Op == other.Op && c.Target == other.Target && c.Name == other.Name &&
		slices.Equal(c.Members, other.Members) && c.StateHash == other.StateHash
}

// verify checks the signature of a parsed control against actor. The ID is
// recomputed from the signing key rather than taken from actor.ID, so that
// a bundle assembled by hand with a mismatched ID cannot lend its key to
// another identity.
func verify(c *Control, actor *identity.Bundle) error {
	if actor == nil || actor.SigningKey == nil {
		return fmt.Errorf("%w: no actor bundle", ErrBadSignature)
	}
	if actor.ID != c.Actor || identity.IDFromSigningKey(actor.SigningKey) != c.Actor {
		return fmt.Errorf("%w: bundle does not belong to the actor", ErrBadSignature)
	}
	if err := actor.SigningKey.Verify(identity.ContextGroupControl, c.tbs, c.sig); err != nil {
		return ErrBadSignature
	}
	return nil
}

// transition applies the rules of the specification to a syntactically
// valid control. It does not look at the signature.
func transition(cur *State, c *Control) (State, error) {
	if c.Op == OpCreate {
		return create(cur, c)
	}
	if cur == nil {
		return State{}, fmt.Errorf("%w: %v without a group state", ErrInvalidOp, c.Op)
	}
	if err := cur.validate(); err != nil {
		return State{}, fmt.Errorf("%w: current state: %w", ErrMalformed, err)
	}
	if c.GroupID != cur.GroupID {
		return State{}, fmt.Errorf("%w: different group", ErrStateMismatch)
	}
	if cur.Epoch == math.MaxUint64 || c.Epoch != cur.Epoch+1 {
		return State{}, fmt.Errorf("%w: epoch %d at state epoch %d", ErrStaleEpoch, c.Epoch, cur.Epoch)
	}
	if c.StateHash != cur.Hash() {
		return State{}, ErrStateMismatch
	}
	if !cur.IsMember(c.Actor) {
		return State{}, fmt.Errorf("%w: actor", ErrNotMember)
	}

	next := cur.clone()
	next.Epoch = c.Epoch
	if c.Op == OpLeave {
		return leave(cur, next, c.Actor)
	}
	if !cur.IsAdmin(c.Actor) {
		return State{}, fmt.Errorf("%w: %v requires admin rights", ErrNotAdmin, c.Op)
	}

	switch c.Op {
	case OpAdd:
		if cur.IsMember(c.Target) {
			return State{}, fmt.Errorf("%w: target is already a member", ErrInvalidOp)
		}
		if len(cur.Members) >= MaxMembers {
			return State{}, fmt.Errorf("%w: group is full", ErrTooManyMembers)
		}
		next.Members = insertID(cur.Members, c.Target)
	case OpRemove:
		if c.Target == c.Actor {
			return State{}, fmt.Errorf("%w: use leave to remove oneself", ErrInvalidOp)
		}
		if !cur.IsMember(c.Target) {
			return State{}, fmt.Errorf("%w: target", ErrNotMember)
		}
		next = next.withoutAdmin(c.Target)
		next.Members = removeID(cur.Members, c.Target)
		next.LastRemovalEpoch = c.Epoch
	case OpPromote:
		if !cur.IsMember(c.Target) {
			return State{}, fmt.Errorf("%w: target", ErrNotMember)
		}
		if cur.IsAdmin(c.Target) {
			return State{}, fmt.Errorf("%w: target is already an admin", ErrInvalidOp)
		}
		next = next.withAdmin(c.Target, c.Epoch)
	case OpDemote:
		if !cur.IsMember(c.Target) {
			return State{}, fmt.Errorf("%w: target", ErrNotMember)
		}
		if !cur.IsAdmin(c.Target) {
			return State{}, fmt.Errorf("%w: target is not an admin", ErrInvalidOp)
		}
		if len(cur.Admins) == 1 {
			return State{}, ErrLastAdmin
		}
		next = next.withoutAdmin(c.Target)
	case OpRename:
		next.Name = c.Name
	default:
		return State{}, fmt.Errorf("%w: %v", ErrInvalidOp, c.Op)
	}
	return next, nil
}

// create applies a create control. The creator is the sole admin: nobody
// else can be granted rights by a message they did not sign.
func create(cur *State, c *Control) (State, error) {
	if cur != nil {
		return State{}, fmt.Errorf("%w: create on an existing group", ErrInvalidOp)
	}
	if c.Epoch != 1 {
		return State{}, fmt.Errorf("%w: create at epoch %d", ErrStaleEpoch, c.Epoch)
	}
	next := State{
		GroupID:    c.GroupID,
		Name:       c.Name,
		Epoch:      1,
		Members:    slices.Clone(c.Members),
		Admins:     []identity.ID{c.Actor},
		AdminSince: []uint64{1},
	}
	if err := next.validate(); err != nil {
		return State{}, err
	}
	return next, nil
}

// leave removes actor from next. The last admin may only leave when it is
// the last member, which dissolves the group; otherwise the remaining
// members would be left with a group nobody can manage.
func leave(cur *State, next State, actor identity.ID) (State, error) {
	if cur.IsAdmin(actor) && len(cur.Admins) == 1 && len(cur.Members) > 1 {
		return State{}, ErrLastAdmin
	}
	next = next.withoutAdmin(actor)
	next.Members = removeID(cur.Members, actor)
	next.LastRemovalEpoch = next.Epoch
	return next, nil
}

// Recipients returns, sorted and without duplicates, the identities a
// control moving the group from old to next must be sent to: every member of
// next plus every member of old that is no longer one, so that removed and
// leaving members learn that they are out and delete the group's sender
// keys. For a create control, old is the zero State. The actor itself is
// included; callers skip their own ID when sending.
func Recipients(old, next State) []identity.ID {
	out := slices.Clone(next.Members)
	for _, member := range old.Members {
		if !next.IsMember(member) {
			out = append(out, member)
		}
	}
	slices.SortFunc(out, compareIDs)
	return slices.CompactFunc(out, func(a, b identity.ID) bool { return a == b })
}
