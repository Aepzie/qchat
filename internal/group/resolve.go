package group

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"

	"github.com/Aepzie/qchat/internal/identity"
)

// Resolve returns the winner of two conflicting controls, that is two
// controls that [Apply] accepted against the same state prev (same group,
// epoch prev.Epoch+1 and state hash prev.Hash()). Every member that sees
// both controls keeps the winner's state; the loser's actor re-issues its
// change on top of it if it still wants and is still allowed to.
//
// Each control is ranked by the key below, compared component by component,
// and the smaller key wins:
//
//  1. Class: revocations (remove, demote and leave, the operations that take
//     membership or rights away) before grants (add, promote, rename).
//  2. For revocations only, the seniority of the actor in prev: the epoch at
//     which it became an admin ([State.AdminSince]), smaller first. An actor
//     that is not an admin (only possible for leave) ranks after every
//     admin.
//  3. For revocations only, leave before remove and demote, so an actor's
//     own leave beats any other revocation it issued concurrently.
//  4. The SHA-256 hash of Raw, smaller first.
//
// Consequences:
//
//   - A control that removes or demotes the actor of the other control wins
//     whenever the other control is a grant, so an admin who is being
//     removed cannot get a concurrent add or promote of an accomplice
//     through.
//   - Of two admins who remove or demote each other, the one who has been an
//     admin longer wins. Seniority is fixed by the signed history: no actor
//     can obtain it by choosing its identity (as with the former rule that
//     compared actor IDs) or by re-signing. A senior admin's revocation also
//     beats a junior admin's revocation of the senior when the senior's own
//     control targets someone else; this gives the senior no power it did
//     not already have, since it could equally have removed the junior and
//     won the mutual removal.
//   - The hash, which an actor can grind by re-signing, only decides between
//     two grants, between two revocations of the same actor, or between the
//     leaves of two non-admins. Losing such a conflict takes no rights away
//     from anyone.
//
// The key is a total order: two different controls have equal keys only if
// their Raw encodings collide under SHA-256. Resolving any number of
// controls pairwise therefore yields the same winner in every order, which
// is what lets members that receive conflicting controls in different orders
// converge. (Ranking pairwise by "removes the other's actor" alone is not
// transitive: three admins that each remove the next have no consistent
// winner.)
//
// A nil argument loses against a non-nil one, and for byte-identical
// controls Resolve returns a. Resolve does not check that the controls are
// valid or conflict; callers pass only controls that [Apply] accepted
// against prev, typically through [ApplyOrResolve].
func Resolve(prev State, a, b *Control) *Control {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if compareConflictKeys(conflictKeyOf(prev, b), conflictKeyOf(prev, a)) < 0 {
		return b
	}
	return a
}

// conflictKey is the rank of a control in [Resolve]; smaller wins.
type conflictKey struct {
	grant     bool
	seniority uint64
	notLeave  bool
	rawHash   [32]byte
}

func conflictKeyOf(prev State, c *Control) conflictKey {
	key := conflictKey{rawHash: sha256.Sum256(c.Raw)}
	if !c.Op.revokes() {
		key.grant = true
		return key
	}
	key.seniority = math.MaxUint64
	if since, ok := prev.adminSince(c.Actor); ok {
		key.seniority = since
	}
	key.notLeave = c.Op != OpLeave
	return key
}

func compareConflictKeys(a, b conflictKey) int {
	switch {
	case a.grant != b.grant:
		return compareBools(a.grant, b.grant)
	case a.seniority != b.seniority:
		if a.seniority < b.seniority {
			return -1
		}
		return 1
	case a.notLeave != b.notLeave:
		return compareBools(a.notLeave, b.notLeave)
	}
	return bytes.Compare(a.rawHash[:], b.rawHash[:])
}

// compareBools orders false before true.
func compareBools(a, b bool) int {
	switch {
	case a == b:
		return 0
	case b:
		return -1
	}
	return 1
}

// revokes reports whether op takes membership or admin rights away.
func (op Op) revokes() bool {
	return op == OpRemove || op == OpDemote || op == OpLeave
}

// CanResolveAgainst reports whether c may still be resolved against the
// receiver's current state cur as a conflicting control: c is a non-create
// control of cur's group for cur's own epoch, so it competes with the control
// that produced cur. A receiver keeps the state before that control and the
// control itself while it is at that epoch, and passes them with c to
// [ApplyOrResolve], which also checks that c was built on the same state.
//
// The conflict window closes as soon as the receiver applies any later
// control: from then on a control for an earlier epoch is stale and dropped,
// even if it would have won. Members that end up on different sides of a
// late conflict hold different states, which [State.Binding] in the group
// message headers exposes.
func CanResolveAgainst(cur State, c *Control) bool {
	return c != nil && c.Op != OpCreate && c.GroupID == cur.GroupID && c.Epoch == cur.Epoch && cur.Epoch > 1
}

// ApplyOrResolve handles a control incoming that arrives while the receiver
// is at the state produced by applying the control applied to prev, and
// incoming is for the same epoch (see [CanResolveAgainst]). actor must be
// the verified bundle of incoming.Actor.
//
// incoming is verified with [Apply] against prev; any error from Apply is
// returned unchanged. applied must be the control the receiver accepted
// against prev; it is re-parsed and re-checked against prev, but its
// signature is not verified again. Both states are recomputed from prev, the
// winner is chosen with [Resolve], and the winner's state is returned with
// the winner (one of the two pointers passed in). When winner is applied,
// the receiver keeps its state and drops incoming; otherwise it replaces
// its state with the returned one.
func ApplyOrResolve(prev State, applied *Control, incoming *Control, actor *identity.Bundle) (next State, winner *Control, err error) {
	if applied == nil {
		return State{}, nil, fmt.Errorf("%w: no applied control", ErrMalformed)
	}
	parsed, err := ParseControl(applied.Raw)
	if err != nil {
		return State{}, nil, fmt.Errorf("group: applied control: %w", err)
	}
	if !parsed.sameFields(applied) {
		return State{}, nil, fmt.Errorf("%w: applied control fields differ from its encoding", ErrMalformed)
	}
	appliedState, err := transition(&prev, parsed)
	if err != nil {
		return State{}, nil, fmt.Errorf("group: applied control: %w", err)
	}
	incomingState, err := Apply(&prev, incoming, actor)
	if err != nil {
		return State{}, nil, err
	}
	if Resolve(prev, applied, incoming) == applied {
		return appliedState, applied, nil
	}
	return incomingState, incoming, nil
}
