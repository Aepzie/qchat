// Package group implements the membership state machine of qchat groups as
// specified in docs/design/phase-4-groups.md, section "Group state".
//
// A group is described by a [State]: a random group ID, a name, an epoch and
// the sorted lists of members and admins. Every change of the state is a
// signed [Control] message that names the epoch it creates and commits to
// the hash of the state it applies to. Controls travel over the pairwise
// ratchet sessions (which already encrypt and authenticate them per
// recipient); the hybrid signature inside the control additionally binds the
// change to the acting identity, so that a recipient can prove to itself who
// authorised a membership change even though it learnt about it from a
// pairwise channel with that same identity.
//
// The package is pure: it performs no I/O, keeps no global state and never
// mutates its inputs. [Apply] is the single place where the rules are
// enforced; [NewGroup] and [NewControl] run the same rules before signing, so
// a client never signs a change that its peers would reject.
//
// Two controls built on the same state conflict. [Resolve] picks the winner
// by a total order that ranks revocations by admin seniority, so members
// converge whatever order the controls arrive in; [CanResolveAgainst] and
// [ApplyOrResolve] bound and carry out the resolution. A member who is
// added learns the group by replaying its [History] with [VerifyJoin], and
// [State.Binding] lets group messages expose forked views.
//
// Encodings are canonical CBOR (RFC 8949 core deterministic encoding) and
// decoders accept only the canonical encoding of a value, so that a control
// or state has exactly one byte representation. This removes parser
// differentials between clients and makes state hashes and signatures
// unambiguous.
package group

import "errors"

// Errors returned by this package. Callers compare with [errors.Is]; the
// returned errors may wrap additional detail.
var (
	// ErrMalformed reports an encoding that is not exactly in the canonical
	// version 1 format, a field with an impossible value (zero IDs, unsorted
	// or duplicate member lists, fields that the operation forbids), or a
	// [Control] whose exported fields disagree with its Raw encoding.
	ErrMalformed = errors.New("group: malformed group data")

	// ErrBadSignature reports a control whose signature does not verify
	// under the given actor bundle, or a bundle that does not belong to the
	// control's actor.
	ErrBadSignature = errors.New("group: control signature does not verify")

	// ErrNotAdmin reports a control whose actor is a member but not an
	// admin, for an operation that requires admin rights.
	ErrNotAdmin = errors.New("group: actor is not an admin")

	// ErrNotMember reports a control whose actor, or whose target for an
	// operation on an existing member, is not a member of the group.
	ErrNotMember = errors.New("group: not a member of the group")

	// ErrStaleEpoch reports a control whose epoch is not exactly the
	// current epoch plus one (or 1 for create).
	ErrStaleEpoch = errors.New("group: control epoch does not follow the current epoch")

	// ErrStateMismatch reports a control for a different group or whose
	// state hash does not match the receiver's current state, typically a
	// conflicting concurrent change (see [Resolve]).
	ErrStateMismatch = errors.New("group: control does not apply to the current state")

	// ErrInvalidOp reports an unknown operation, an operation that does not
	// fit the state (create on an existing group, any other operation
	// without a state, adding an existing member, promoting an admin,
	// demoting a non-admin, removing oneself instead of leaving).
	ErrInvalidOp = errors.New("group: invalid operation")

	// ErrLastAdmin reports a demote or leave that would leave a group with
	// members but without an admin.
	ErrLastAdmin = errors.New("group: the last admin cannot step down")

	// ErrTooManyMembers reports a group that would exceed [MaxMembers].
	ErrTooManyMembers = errors.New("group: too many members")

	// ErrInvalidName reports a group name that is not 1 to [MaxNameRunes]
	// runes of valid UTF-8 free of control, format (including bidirectional
	// override) and line or paragraph separator characters.
	ErrInvalidName = errors.New("group: invalid group name")

	// ErrBadHistory reports a [History] outside the bounds
	// [MaxHistoryControls] and [MaxHistorySize], or a verified history that
	// does not end the way [VerifyJoin] requires.
	ErrBadHistory = errors.New("group: invalid group history")
)
