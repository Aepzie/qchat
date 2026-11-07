package group

import (
	"crypto/rand"
	"fmt"
	"math"
	"slices"

	"github.com/craguS/qchat/internal/crypto/hybridsig"
	"github.com/craguS/qchat/internal/identity"
)

// MaxControlSize is the largest encoded control [ParseControl] accepts. A
// create control with [MaxMembers] members and a name of [MaxNameRunes]
// four-byte runes is about 12.4 KiB.
const MaxControlSize = 16 << 10

// Op is a group operation.
type Op uint8

// Operations, with their wire values.
const (
	// OpCreate creates a group. Its actor becomes the sole admin; Name and
	// the complete initial Members list (which includes the actor) are set.
	OpCreate Op = 1

	// OpAdd adds Target as a member. Admins only.
	OpAdd Op = 2

	// OpRemove removes Target, which must be another member. Admins only.
	OpRemove Op = 3

	// OpPromote makes the member Target an admin. Admins only.
	OpPromote Op = 4

	// OpDemote takes admin rights from Target. Admins only; the last admin
	// cannot be demoted.
	OpDemote Op = 5

	// OpRename sets the group name to Name. Admins only.
	OpRename Op = 6

	// OpLeave removes the actor itself. Any member; the last admin cannot
	// leave while other members remain.
	OpLeave Op = 7
)

// String returns the lowercase name of op, or "op(N)" for unknown values.
func (op Op) String() string {
	switch op {
	case OpCreate:
		return "create"
	case OpAdd:
		return "add"
	case OpRemove:
		return "remove"
	case OpPromote:
		return "promote"
	case OpDemote:
		return "demote"
	case OpRename:
		return "rename"
	case OpLeave:
		return "leave"
	}
	return fmt.Sprintf("op(%d)", uint8(op))
}

func (op Op) hasTarget() bool {
	return op == OpAdd || op == OpRemove || op == OpPromote || op == OpDemote
}

func (op Op) hasName() bool {
	return op == OpCreate || op == OpRename
}

// Signer produces group control signatures. *identity.Identity implements
// it; signatures must be hybrid signatures under
// [identity.ContextGroupControl] by the identity named by ID.
type Signer interface {
	ID() identity.ID
	SignGroupControl(tbs []byte) ([]byte, error)
}

// Control is a parsed group control message. Fields that the operation does
// not use are zero: Target is set only for add, remove, promote and demote,
// Name only for create and rename, Members only for create, and StateHash
// for every operation except create.
//
// Raw is the authoritative encoding. [Apply] re-parses Raw and rejects a
// Control whose exported fields disagree with it, so modifying a parsed
// Control can never make Apply act on fields the signature does not cover.
type Control struct {
	GroupID   ID
	Epoch     uint64
	Actor     identity.ID
	Op        Op
	Target    identity.ID
	Name      string
	Members   []identity.ID
	StateHash [32]byte
	Raw       []byte

	tbs []byte
	sig []byte
}

// controlTBS holds fields 1 to 9 of a control; its canonical encoding is
// the message the signature covers.
type controlTBS struct {
	Version   uint8         `cbor:"1,keyasint"`
	GroupID   ID            `cbor:"2,keyasint"`
	Epoch     uint64        `cbor:"3,keyasint"`
	Actor     identity.ID   `cbor:"4,keyasint"`
	Op        Op            `cbor:"5,keyasint"`
	Target    identity.ID   `cbor:"6,keyasint"`
	Name      string        `cbor:"7,keyasint"`
	Members   []identity.ID `cbor:"8,keyasint"`
	StateHash [32]byte      `cbor:"9,keyasint"`
}

// controlWire is the complete encoded control, fields 1 to 10:
//
//	CBOR{1: version (=1), 2: group ID, 3: epoch, 4: actor, 5: op,
//	     6: target, 7: name, 8: members, 9: state hash, 10: signature}
//
// Every field is always present; unused ones hold their zero value (zero
// IDs and hash, empty name and member list), so each control has exactly
// one encoding.
type controlWire struct {
	Version   uint8         `cbor:"1,keyasint"`
	GroupID   ID            `cbor:"2,keyasint"`
	Epoch     uint64        `cbor:"3,keyasint"`
	Actor     identity.ID   `cbor:"4,keyasint"`
	Op        Op            `cbor:"5,keyasint"`
	Target    identity.ID   `cbor:"6,keyasint"`
	Name      string        `cbor:"7,keyasint"`
	Members   []identity.ID `cbor:"8,keyasint"`
	StateHash [32]byte      `cbor:"9,keyasint"`
	Sig       []byte        `cbor:"10,keyasint"`
}

func (w *controlWire) tbs() controlTBS {
	return controlTBS{
		Version: w.Version, GroupID: w.GroupID, Epoch: w.Epoch, Actor: w.Actor, Op: w.Op,
		Target: w.Target, Name: w.Name, Members: w.Members, StateHash: w.StateHash,
	}
}

func (t *controlTBS) wire(sig []byte) controlWire {
	return controlWire{
		Version: t.Version, GroupID: t.GroupID, Epoch: t.Epoch, Actor: t.Actor, Op: t.Op,
		Target: t.Target, Name: t.Name, Members: t.Members, StateHash: t.StateHash, Sig: sig,
	}
}

// control returns the Control described by t, without Raw or signature.
func (t *controlTBS) control() *Control {
	c := &Control{
		GroupID: t.GroupID, Epoch: t.Epoch, Actor: t.Actor, Op: t.Op, Target: t.Target,
		Name: t.Name, StateHash: t.StateHash,
	}
	if len(t.Members) > 0 {
		c.Members = slices.Clone(t.Members)
	}
	return c
}

// checkSyntax enforces every rule that does not depend on the current
// state: version, non-zero IDs and epoch, a known operation, and exactly the
// fields that the operation uses. Rejecting unused fields, rather than
// ignoring them, keeps signed bytes free of content no rule looks at.
func (t *controlTBS) checkSyntax() error {
	if t.Version != Version {
		return fmt.Errorf("%w: control version %d", ErrMalformed, t.Version)
	}
	if t.Op < OpCreate || t.Op > OpLeave {
		return fmt.Errorf("%w: %v", ErrInvalidOp, t.Op)
	}
	if t.GroupID.IsZero() || t.Actor.IsZero() {
		return fmt.Errorf("%w: zero group or actor ID", ErrMalformed)
	}
	if t.Epoch == 0 {
		return fmt.Errorf("%w: zero epoch", ErrMalformed)
	}
	if t.Op.hasTarget() == t.Target.IsZero() {
		return fmt.Errorf("%w: target presence does not match %v", ErrMalformed, t.Op)
	}
	if t.Op.hasName() {
		if err := validateName(t.Name); err != nil {
			return err
		}
	} else if t.Name != "" {
		return fmt.Errorf("%w: name set for %v", ErrMalformed, t.Op)
	}
	if t.Op != OpCreate {
		if len(t.Members) != 0 {
			return fmt.Errorf("%w: member list set for %v", ErrMalformed, t.Op)
		}
		if t.StateHash == ([32]byte{}) {
			return fmt.Errorf("%w: zero state hash for %v", ErrMalformed, t.Op)
		}
		return nil
	}
	if t.StateHash != ([32]byte{}) {
		return fmt.Errorf("%w: state hash set for create", ErrMalformed)
	}
	if err := validateIDList(t.Members); err != nil {
		return err
	}
	if !containsID(t.Members, t.Actor) {
		return fmt.Errorf("%w: creator is not a member", ErrMalformed)
	}
	return nil
}

// ParseControl decodes an encoded control and checks its syntax. It accepts
// only the canonical encoding of a version 1 control no larger than
// [MaxControlSize] whose fields are consistent with its operation (see
// [Control]) and whose signature has the hybrid signature size.
//
// ParseControl neither verifies the signature nor checks the control
// against any state: the result must not be acted on before [Apply]
// accepted it. Errors wrap [ErrMalformed], [ErrInvalidOp],
// [ErrInvalidName] or [ErrTooManyMembers].
func ParseControl(b []byte) (*Control, error) {
	if len(b) == 0 || len(b) > MaxControlSize {
		return nil, fmt.Errorf("%w: control size %d out of range", ErrMalformed, len(b))
	}
	var wire controlWire
	if err := decodeCanonical(b, &wire); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	t := wire.tbs()
	if err := t.checkSyntax(); err != nil {
		return nil, err
	}
	if len(wire.Sig) != hybridsig.SignatureSize {
		return nil, fmt.Errorf("%w: signature of %d bytes", ErrMalformed, len(wire.Sig))
	}

	// The signed bytes are rebuilt from the decoded fields. Since the input
	// was required to be canonical, they are byte for byte what the signer
	// encoded.
	tbs, err := encMode.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	c := t.control()
	c.Raw = slices.Clone(b)
	c.tbs = tbs
	c.sig = slices.Clone(wire.Sig)
	return c, nil
}

// NewGroup creates a group named name whose members are members plus the
// signer, who becomes the sole admin. It returns the initial state and the
// signed create control, which the caller sends to every other member.
//
// The group ID is drawn from crypto/rand. members may be in any order and
// may or may not include the signer; duplicates and zero IDs are rejected
// with [ErrMalformed], more than [MaxMembers] members in total with
// [ErrTooManyMembers] and an invalid name with [ErrInvalidName].
func NewGroup(s Signer, name string, members []identity.ID) (State, []byte, error) {
	creator := s.ID()
	list := slices.Clone(members)
	if !slices.Contains(list, creator) {
		list = append(list, creator)
	}
	slices.SortFunc(list, compareIDs)

	var groupID ID
	rand.Read(groupID[:])

	t := controlTBS{Version: Version, GroupID: groupID, Epoch: 1, Actor: creator, Op: OpCreate, Name: name, Members: list}
	raw, next, err := seal(s, nil, &t)
	if err != nil {
		return State{}, nil, err
	}
	return next, raw, nil
}

// NewControl builds and signs the control by which the signer performs op
// on cur, moving the group to epoch cur.Epoch+1. target is the member
// affected by add, remove, promote and demote and must be the zero ID
// otherwise; name is the new name for rename and must be empty otherwise.
// Create is not possible here: use [NewGroup].
//
// The control is checked with the same rules as [Apply] before it is
// signed, so the signer never signs a change its peers would reject, and the
// returned error is the one Apply would report. To obtain the new state, the
// caller applies the returned control with [ParseControl] and [Apply]
// against its own bundle, exactly like every receiver does.
func NewControl(s Signer, cur State, op Op, target identity.ID, name string) ([]byte, error) {
	if op == OpCreate {
		return nil, fmt.Errorf("%w: create requires NewGroup", ErrInvalidOp)
	}
	if cur.Epoch == math.MaxUint64 {
		return nil, fmt.Errorf("%w: epoch exhausted", ErrStaleEpoch)
	}
	t := controlTBS{
		Version: Version, GroupID: cur.GroupID, Epoch: cur.Epoch + 1, Actor: s.ID(), Op: op,
		Target: target, Name: name, StateHash: cur.Hash(),
	}
	raw, _, err := seal(s, &cur, &t)
	return raw, err
}

// seal checks t against cur, signs it and returns the encoded control with
// the state it produces.
func seal(s Signer, cur *State, t *controlTBS) ([]byte, State, error) {
	if err := t.checkSyntax(); err != nil {
		return nil, State{}, err
	}
	next, err := transition(cur, t.control())
	if err != nil {
		return nil, State{}, err
	}
	tbs, err := encMode.Marshal(t)
	if err != nil {
		return nil, State{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	sig, err := s.SignGroupControl(tbs)
	if err != nil {
		return nil, State{}, fmt.Errorf("group: signing control: %w", err)
	}
	if len(sig) != hybridsig.SignatureSize {
		return nil, State{}, fmt.Errorf("group: signer returned a signature of %d bytes", len(sig))
	}
	raw, err := encMode.Marshal(t.wire(sig))
	if err != nil {
		return nil, State{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return raw, next, nil
}
