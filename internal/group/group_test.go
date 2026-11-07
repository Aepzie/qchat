package group

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/craguS/qchat/internal/identity"
)

func TestNewGroupAndCreate(t *testing.T) {
	ms := testMembers(t)
	creator := ms[2]
	state, raw, err := NewGroup(creator.id, "Friends", ids(ms[4], ms[0]))
	if err != nil {
		t.Fatal(err)
	}
	want := ids(ms[0], ms[2], ms[4])
	if !slices.Equal(state.Members, want) || !slices.Equal(state.Admins, ids(creator)) {
		t.Fatalf("members %v admins %v", state.Members, state.Admins)
	}
	if state.Epoch != 1 || state.Name != "Friends" || state.GroupID.IsZero() {
		t.Fatalf("unexpected state %+v", state)
	}

	received := mustApply(t, nil, raw, creator)
	if !statesEqual(state, received) {
		t.Fatal("receiver state differs from creator state")
	}
	if got := Recipients(State{}, received); !slices.Equal(got, want) {
		t.Fatalf("Recipients = %v, want %v", got, want)
	}

	_, again, err := NewGroup(creator.id, "Friends", ids(ms[0], ms[2], ms[4]))
	if err != nil {
		t.Fatal(err)
	}
	other, err := ParseControl(again)
	if err != nil {
		t.Fatal(err)
	}
	if other.GroupID == state.GroupID {
		t.Fatal("group IDs repeat")
	}

	c, err := ParseControl(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(&state, c, creator.bundle); !errors.Is(err, ErrInvalidOp) {
		t.Fatalf("create on existing state: %v", err)
	}
}

func TestNewGroupRejects(t *testing.T) {
	ms := testMembers(t)
	cases := []struct {
		name    string
		members []identity.ID
		group   string
		want    error
	}{
		{"duplicate", ids(ms[1], ms[1]), "g", ErrMalformed},
		{"zero member", []identity.ID{{}}, "g", ErrMalformed},
		{"empty name", nil, "", ErrInvalidName},
		{"long name", nil, strings.Repeat("a", MaxNameRunes+1), ErrInvalidName},
		{"bidi override", nil, "a\u202eb", ErrInvalidName},
		{"control char", nil, "a\nb", ErrInvalidName},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := NewGroup(ms[0].id, tc.group, tc.members); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCreateRules(t *testing.T) {
	ms := testMembers(t)
	actor := ms[0]
	base := controlTBS{Version: Version, GroupID: ID{1}, Epoch: 1, Actor: actor.id.ID(), Op: OpCreate, Name: "g", Members: ids(ms[0], ms[1])}

	wrongEpoch := base
	wrongEpoch.Epoch = 2
	if _, err := applyRaw(nil, signRaw(t, actor.id, wrongEpoch), actor); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("create at epoch 2: %v", err)
	}

	notMember := base
	notMember.Members = ids(ms[1], ms[2])
	if _, err := applyRaw(nil, signRaw(t, actor.id, notMember), actor); !errors.Is(err, ErrMalformed) {
		t.Fatalf("creator not a member: %v", err)
	}

	unsorted := base
	unsorted.Members = ids(ms[1], ms[0])
	if _, err := applyRaw(nil, signRaw(t, actor.id, unsorted), actor); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unsorted members: %v", err)
	}

	withHash := base
	withHash.StateHash = [32]byte{1}
	if _, err := applyRaw(nil, signRaw(t, actor.id, withHash), actor); !errors.Is(err, ErrMalformed) {
		t.Fatalf("create with state hash: %v", err)
	}

	state := mustApply(t, nil, signRaw(t, actor.id, base), actor)
	if !slices.Equal(state.Admins, ids(actor)) {
		t.Fatalf("admins %v", state.Admins)
	}
}

func TestOperations(t *testing.T) {
	base, ms := baseGroup(t)
	adminA, adminB, plainC, plainD, outsider := ms[0], ms[1], ms[2], ms[3], ms[4]
	idOf := func(m member) identity.ID { return m.id.ID() }

	cases := []struct {
		name    string
		actor   member
		op      Op
		target  identity.ID
		newName string
		want    error
		check   func(t *testing.T, next State)
	}{
		{"admin adds", adminA, OpAdd, idOf(outsider), "", nil, func(t *testing.T, next State) {
			if !next.IsMember(idOf(outsider)) || next.IsAdmin(idOf(outsider)) {
				t.Fatal("outsider not added as plain member")
			}
		}},
		{"second admin adds", adminB, OpAdd, idOf(outsider), "", nil, nil},
		{"member adds", plainC, OpAdd, idOf(outsider), "", ErrNotAdmin, nil},
		{"outsider adds", outsider, OpAdd, randomID(t), "", ErrNotMember, nil},
		{"add existing", adminA, OpAdd, idOf(plainC), "", ErrInvalidOp, nil},

		{"admin removes member", adminA, OpRemove, idOf(plainC), "", nil, func(t *testing.T, next State) {
			if next.IsMember(idOf(plainC)) {
				t.Fatal("member not removed")
			}
		}},
		{"admin removes admin", adminA, OpRemove, idOf(adminB), "", nil, func(t *testing.T, next State) {
			if next.IsMember(idOf(adminB)) || next.IsAdmin(idOf(adminB)) {
				t.Fatal("admin not removed from both lists")
			}
		}},
		{"admin removes self", adminA, OpRemove, idOf(adminA), "", ErrInvalidOp, nil},
		{"remove non-member", adminA, OpRemove, idOf(outsider), "", ErrNotMember, nil},
		{"member removes", plainC, OpRemove, idOf(plainD), "", ErrNotAdmin, nil},

		{"admin promotes", adminA, OpPromote, idOf(plainC), "", nil, func(t *testing.T, next State) {
			if !next.IsAdmin(idOf(plainC)) {
				t.Fatal("member not promoted")
			}
		}},
		{"promote admin", adminA, OpPromote, idOf(adminB), "", ErrInvalidOp, nil},
		{"promote non-member", adminA, OpPromote, idOf(outsider), "", ErrNotMember, nil},
		{"member promotes", plainC, OpPromote, idOf(plainD), "", ErrNotAdmin, nil},
		{"member promotes self", plainC, OpPromote, idOf(plainC), "", ErrNotAdmin, nil},

		{"admin demotes admin", adminA, OpDemote, idOf(adminB), "", nil, func(t *testing.T, next State) {
			if next.IsAdmin(idOf(adminB)) || !next.IsMember(idOf(adminB)) {
				t.Fatal("admin not demoted to member")
			}
		}},
		{"admin demotes self", adminA, OpDemote, idOf(adminA), "", nil, nil},
		{"demote non-admin", adminA, OpDemote, idOf(plainC), "", ErrInvalidOp, nil},
		{"demote non-member", adminA, OpDemote, idOf(outsider), "", ErrNotMember, nil},
		{"member demotes", plainC, OpDemote, idOf(adminA), "", ErrNotAdmin, nil},

		{"admin renames", adminB, OpRename, identity.ID{}, "Renamed \u00e9\U0001F600", nil, func(t *testing.T, next State) {
			if next.Name != "Renamed \u00e9\U0001F600" {
				t.Fatalf("name %q", next.Name)
			}
		}},
		{"member renames", plainC, OpRename, identity.ID{}, "x", ErrNotAdmin, nil},
		{"rename invalid", adminA, OpRename, identity.ID{}, "a\u2066b", ErrInvalidName, nil},

		{"member leaves", plainC, OpLeave, identity.ID{}, "", nil, func(t *testing.T, next State) {
			if next.IsMember(idOf(plainC)) {
				t.Fatal("member did not leave")
			}
		}},
		{"admin leaves with other admin", adminA, OpLeave, identity.ID{}, "", nil, func(t *testing.T, next State) {
			if next.IsMember(idOf(adminA)) || next.IsAdmin(idOf(adminA)) || !next.IsAdmin(idOf(adminB)) {
				t.Fatal("admin leave produced wrong state")
			}
		}},
		{"outsider leaves", outsider, OpLeave, identity.ID{}, "", ErrNotMember, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, err := base.Marshal()
			if err != nil {
				t.Fatal(err)
			}

			raw, builderErr := NewControl(tc.actor.id, base, tc.op, tc.target, tc.newName)
			if !errors.Is(builderErr, tc.want) {
				t.Fatalf("NewControl: got %v, want %v", builderErr, tc.want)
			}
			if tc.want != nil {
				raw = signRaw(t, tc.actor.id, nextTBS(base, tc.actor.id.ID(), tc.op, tc.target, tc.newName))
			}

			next, err := applyRaw(&base, raw, tc.actor)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Apply: got %v, want %v", err, tc.want)
			}
			after, _ := base.Marshal()
			if !bytes.Equal(before, after) {
				t.Fatal("Apply modified the current state")
			}
			if err != nil {
				return
			}
			if next.Epoch != base.Epoch+1 || next.GroupID != base.GroupID {
				t.Fatalf("epoch %d group %x", next.Epoch, next.GroupID)
			}
			if err := next.validate(); err != nil {
				t.Fatalf("result invalid: %v", err)
			}
			if tc.check != nil {
				tc.check(t, next)
			}
		})
	}
}

func TestLastAdmin(t *testing.T) {
	ms := testMembers(t)
	admin, plain := ms[0], ms[1]
	_, raw, err := NewGroup(admin.id, "pair", ids(plain))
	if err != nil {
		t.Fatal(err)
	}
	pair := mustApply(t, nil, raw, admin)

	for _, op := range []Op{OpLeave, OpDemote} {
		target := identity.ID{}
		if op == OpDemote {
			target = admin.id.ID()
		}
		if _, err := NewControl(admin.id, pair, op, target, ""); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("NewControl(%v): %v", op, err)
		}
		forged := signRaw(t, admin.id, nextTBS(pair, admin.id.ID(), op, target, ""))
		if _, err := applyRaw(&pair, forged, admin); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("Apply(%v): %v", op, err)
		}
	}

	afterLeave := mustApply(t, &pair, mustControl(t, plain, pair, OpLeave, identity.ID{}, ""), plain)
	if got := Recipients(pair, afterLeave); !slices.Equal(got, ids(admin, plain)) {
		t.Fatalf("Recipients after leave = %v", got)
	}

	dissolved := mustApply(t, &afterLeave, mustControl(t, admin, afterLeave, OpLeave, identity.ID{}, ""), admin)
	if len(dissolved.Members) != 0 || len(dissolved.Admins) != 0 {
		t.Fatalf("dissolved state %+v", dissolved)
	}
	encoded, err := dissolved.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalState(encoded)
	if err != nil || !statesEqual(decoded, dissolved) {
		t.Fatalf("dissolved round trip: %v", err)
	}
	forged := signRaw(t, admin.id, nextTBS(dissolved, admin.id.ID(), OpAdd, plain.id.ID(), ""))
	if _, err := applyRaw(&dissolved, forged, admin); !errors.Is(err, ErrNotMember) {
		t.Fatalf("control on dissolved group: %v", err)
	}
}

func TestSignatureVerification(t *testing.T) {
	base, ms := baseGroup(t)
	actor, other := ms[0], ms[1]
	raw := mustControl(t, actor, base, OpRename, identity.ID{}, "new name")
	c, err := ParseControl(raw)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Apply(&base, c, other.bundle); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong actor bundle: %v", err)
	}
	if _, err := Apply(&base, c, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("nil bundle: %v", err)
	}
	impostor := *other.bundle
	impostor.ID = actor.id.ID()
	if _, err := Apply(&base, c, &impostor); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("bundle with foreign key: %v", err)
	}

	t.Run("claimed actor", func(t *testing.T) {
		forged := signRaw(t, actor.id, nextTBS(base, other.id.ID(), OpRename, identity.ID{}, "x"))
		if _, err := applyRaw(&base, forged, other); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("wrong context", func(t *testing.T) {
		tbsFields := nextTBS(base, actor.id.ID(), OpRename, identity.ID{}, "x")
		tbs, err := encMode.Marshal(tbsFields)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := actor.id.SignMessage(tbs)
		if err != nil {
			t.Fatal(err)
		}
		forged, err := encMode.Marshal(tbsFields.wire(sig))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := applyRaw(&base, forged, actor); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("tampered encoded fields", func(t *testing.T) {
		mutations := map[string]func(w *controlWire){
			"name":   func(w *controlWire) { w.Name = "other" },
			"op":     func(w *controlWire) { w.Op = OpLeave; w.Name = "" },
			"group":  func(w *controlWire) { w.GroupID[0] ^= 1 },
			"epoch":  func(w *controlWire) { w.Epoch++ },
			"hash":   func(w *controlWire) { w.StateHash[0] ^= 1 },
			"actor":  func(w *controlWire) { w.Actor = other.id.ID() },
			"sig":    func(w *controlWire) { w.Sig[len(w.Sig)-1] ^= 1 },
			"edsig":  func(w *controlWire) { w.Sig[0] ^= 1 },
			"target": func(w *controlWire) { w.Op = OpPromote; w.Name = ""; w.Target = ms[2].id.ID() },
		}
		for name, mutate := range mutations {
			var wire controlWire
			if err := decodeCanonical(raw, &wire); err != nil {
				t.Fatal(err)
			}
			wire.Sig = slices.Clone(wire.Sig)
			mutate(&wire)
			tampered, err := encMode.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := applyRaw(&base, tampered, actor); !errors.Is(err, ErrBadSignature) {
				t.Errorf("%s: got %v", name, err)
			}
		}
	})

	t.Run("tampered struct fields", func(t *testing.T) {
		mutations := map[string]func(c *Control){
			"name":    func(c *Control) { c.Name = "other" },
			"op":      func(c *Control) { c.Op = OpLeave },
			"target":  func(c *Control) { c.Target = ms[3].id.ID() },
			"members": func(c *Control) { c.Members = ids(ms[3]) },
			"epoch":   func(c *Control) { c.Epoch++ },
			"actor":   func(c *Control) { c.Actor = other.id.ID() },
		}
		for name, mutate := range mutations {
			copied, err := ParseControl(raw)
			if err != nil {
				t.Fatal(err)
			}
			mutate(copied)
			if _, err := Apply(&base, copied, actor.bundle); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s: got %v", name, err)
			}
		}
		if _, err := Apply(&base, nil, actor.bundle); !errors.Is(err, ErrMalformed) {
			t.Errorf("nil control: got %v", err)
		}
	})

	if _, err := Apply(&base, c, actor.bundle); err != nil {
		t.Fatalf("untampered control rejected: %v", err)
	}
}

func TestEpochAndStateHash(t *testing.T) {
	base, ms := baseGroup(t)
	admin := ms[0]
	renameRaw := mustControl(t, admin, base, OpRename, identity.ID{}, "one")
	renamed := mustApply(t, &base, renameRaw, admin)

	if _, err := applyRaw(&renamed, renameRaw, admin); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("replay: %v", err)
	}

	addRaw := mustControl(t, admin, renamed, OpAdd, ms[4].id.ID(), "")
	if _, err := applyRaw(&base, addRaw, admin); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("control from the future: %v", err)
	}

	divergent := mustApply(t, &base, mustControl(t, admin, base, OpRename, identity.ID{}, "two"), admin)
	if _, err := applyRaw(&divergent, addRaw, admin); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("same epoch, different state: %v", err)
	}

	foreign := renamed.clone()
	foreign.GroupID[0] ^= 1
	if _, err := applyRaw(&foreign, addRaw, admin); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("different group: %v", err)
	}

	skipped := nextTBS(base, admin.id.ID(), OpRename, identity.ID{}, "x")
	skipped.Epoch += 1
	if _, err := applyRaw(&base, signRaw(t, admin.id, skipped), admin); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("skipped epoch: %v", err)
	}

	wrongHash := nextTBS(base, admin.id.ID(), OpRename, identity.ID{}, "x")
	wrongHash.StateHash[5] ^= 1
	if _, err := applyRaw(&base, signRaw(t, admin.id, wrongHash), admin); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("wrong state hash: %v", err)
	}

	if _, err := applyRaw(nil, addRaw, admin); !errors.Is(err, ErrInvalidOp) {
		t.Fatalf("non-create without state: %v", err)
	}

	exhausted := base.clone()
	exhausted.Epoch = math.MaxUint64
	if _, err := NewControl(admin.id, exhausted, OpRename, identity.ID{}, "x"); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("exhausted epoch: %v", err)
	}

	invalid := base.clone()
	invalid.Admins = ids(ms[4])
	forged := signRaw(t, admin.id, nextTBS(invalid, admin.id.ID(), OpRename, identity.ID{}, "x"))
	if _, err := applyRaw(&invalid, forged, admin); !errors.Is(err, ErrMalformed) {
		t.Fatalf("invalid current state: %v", err)
	}
}

func TestRecipients(t *testing.T) {
	base, ms := baseGroup(t)
	removed := mustApply(t, &base, mustControl(t, ms[0], base, OpRemove, ms[2].id.ID(), ""), ms[0])
	if got, want := Recipients(base, removed), ids(ms[0], ms[1], ms[2], ms[3]); !slices.Equal(got, want) {
		t.Fatalf("remove: got %v, want %v", got, want)
	}
	left := mustApply(t, &base, mustControl(t, ms[3], base, OpLeave, identity.ID{}, ""), ms[3])
	if got, want := Recipients(base, left), ids(ms[0], ms[1], ms[2], ms[3]); !slices.Equal(got, want) {
		t.Fatalf("leave: got %v, want %v", got, want)
	}
	added := mustApply(t, &base, mustControl(t, ms[0], base, OpAdd, ms[4].id.ID(), ""), ms[0])
	if got, want := Recipients(base, added), ids(ms...); !slices.Equal(got, want) {
		t.Fatalf("add: got %v, want %v", got, want)
	}
	renamed := mustApply(t, &base, mustControl(t, ms[0], base, OpRename, identity.ID{}, "r"), ms[0])
	got := Recipients(base, renamed)
	if want := ids(ms[0], ms[1], ms[2], ms[3]); !slices.Equal(got, want) {
		t.Fatalf("rename: got %v, want %v", got, want)
	}
	got[0] = identity.ID{}
	if renamed.Members[0].IsZero() {
		t.Fatal("Recipients aliases the state")
	}
}

func katState() State {
	fill := func(b byte) identity.ID {
		var id identity.ID
		for i := range id {
			id[i] = b
		}
		return id
	}
	var group ID
	for i := range group {
		group[i] = 0x01
	}
	return State{
		GroupID: group,
		Name:    "qchat",
		Epoch:   7,
		Members: []identity.ID{fill(0x11), fill(0x22)},
		Admins:  []identity.ID{fill(0x11)},

		AdminSince:       []uint64{1},
		LastRemovalEpoch: 5,
	}
}

func TestStateEncodingKAT(t *testing.T) {
	var want []byte
	want = append(want, 0xa8, 0x01, 0x01, 0x02, 0x58, 0x20)
	want = append(want, bytes.Repeat([]byte{0x01}, 32)...)
	want = append(want, 0x03, 0x65, 'q', 'c', 'h', 'a', 't', 0x04, 0x07)
	want = append(want, 0x05, 0x82, 0x58, 0x20)
	want = append(want, bytes.Repeat([]byte{0x11}, 32)...)
	want = append(want, 0x58, 0x20)
	want = append(want, bytes.Repeat([]byte{0x22}, 32)...)
	want = append(want, 0x06, 0x81, 0x58, 0x20)
	want = append(want, bytes.Repeat([]byte{0x11}, 32)...)
	want = append(want, 0x07, 0x81, 0x01, 0x08, 0x05)

	state := katState()
	encoded, err := state.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoding\n got %x\nwant %x", encoded, want)
	}
	const wantHash = "baafc5398d44528806a4e5b96920a0f7b62e8b776f8c008bb3dab392a7a7bea1"
	hash := state.Hash()
	if got := hex.EncodeToString(hash[:]); got != wantHash {
		t.Fatalf("Hash = %s, want %s", got, wantHash)
	}
	if hash != sha256.Sum256(want) {
		t.Fatal("Hash is not SHA-256 of the encoding")
	}
	decoded, err := UnmarshalState(encoded)
	if err != nil || !statesEqual(decoded, state) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestUnmarshalStateRejects(t *testing.T) {
	good, err := katState().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encode := func(mutate func(w *stateWire)) []byte {
		w := katState().wire()
		w.Members = slices.Clone(w.Members)
		w.Admins = slices.Clone(w.Admins)
		mutate(&w)
		b, err := encMode.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	nonShortestEpoch := bytes.Replace(good, []byte{0x04, 0x07}, []byte{0x04, 0x18, 0x07}, 1)
	adminList := append([]byte{0x06, 0x81, 0x58, 0x20}, bytes.Repeat([]byte{0x11}, 32)...)
	nullAdmins := bytes.Replace(good, adminList, []byte{0x06, 0xf6}, 1)
	cases := map[string]struct {
		input []byte
		want  error
	}{
		"empty":            {nil, ErrMalformed},
		"trailing":         {append(slices.Clone(good), 0x00), ErrMalformed},
		"non-shortest":     {nonShortestEpoch, ErrMalformed},
		"null admins":      {nullAdmins, ErrMalformed},
		"oversized":        {make([]byte, MaxStateSize+1), ErrMalformed},
		"version":          {encode(func(w *stateWire) { w.Version = 2 }), ErrMalformed},
		"zero group":       {encode(func(w *stateWire) { w.GroupID = ID{} }), ErrMalformed},
		"zero epoch":       {encode(func(w *stateWire) { w.Epoch = 0 }), ErrMalformed},
		"unsorted":         {encode(func(w *stateWire) { slices.Reverse(w.Members) }), ErrMalformed},
		"duplicate":        {encode(func(w *stateWire) { w.Members[1] = w.Members[0] }), ErrMalformed},
		"admin not member": {encode(func(w *stateWire) { w.Admins = []identity.ID{{0x33}} }), ErrMalformed},
		"no admin":         {encode(func(w *stateWire) { w.Admins, w.AdminSince = nil, nil }), ErrMalformed},
		"no admin epoch":   {encode(func(w *stateWire) { w.AdminSince = nil }), ErrMalformed},
		"extra epoch":      {encode(func(w *stateWire) { w.AdminSince = []uint64{1, 2} }), ErrMalformed},
		"admin epoch zero": {encode(func(w *stateWire) { w.AdminSince = []uint64{0} }), ErrMalformed},
		"admin epoch late": {encode(func(w *stateWire) { w.AdminSince = []uint64{8} }), ErrMalformed},
		"removal late":     {encode(func(w *stateWire) { w.LastRemovalEpoch = 8 }), ErrMalformed},
		"duplicate epoch": {encode(func(w *stateWire) {
			w.Admins = slices.Clone(w.Members)
			w.AdminSince = []uint64{3, 3}
		}), ErrMalformed},
		"bad name": {encode(func(w *stateWire) { w.Name = "\u200b" }), ErrInvalidName},
	}
	for name, tc := range cases {
		if _, err := UnmarshalState(tc.input); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}

	type extraField struct {
		stateWire
		Extra uint8 `cbor:"7,keyasint"`
	}
	extra, err := encMode.Marshal(extraField{stateWire: katState().wire(), Extra: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalState(extra); !errors.Is(err, ErrMalformed) {
		t.Errorf("unknown field: got %v", err)
	}
}

func TestParseControlSyntax(t *testing.T) {
	base, ms := baseGroup(t)
	admin := ms[0]
	tbsFor := func(op Op, target identity.ID, name string) controlTBS {
		return nextTBS(base, admin.id.ID(), op, target, name)
	}
	cases := map[string]struct {
		fields controlTBS
		want   error
	}{
		"unknown op":         {tbsFor(8, identity.ID{}, ""), ErrInvalidOp},
		"zero op":            {tbsFor(0, identity.ID{}, ""), ErrInvalidOp},
		"leave with target":  {tbsFor(OpLeave, ms[1].id.ID(), ""), ErrMalformed},
		"add without target": {tbsFor(OpAdd, identity.ID{}, ""), ErrMalformed},
		"add with name":      {tbsFor(OpAdd, ms[4].id.ID(), "n"), ErrMalformed},
		"rename empty":       {tbsFor(OpRename, identity.ID{}, ""), ErrInvalidName},
		"members on add": {func() controlTBS {
			f := tbsFor(OpAdd, ms[4].id.ID(), "")
			f.Members = ids(ms[4])
			return f
		}(), ErrMalformed},
		"zero hash": {func() controlTBS {
			f := tbsFor(OpRename, identity.ID{}, "n")
			f.StateHash = [32]byte{}
			return f
		}(), ErrMalformed},
		"version 2": {func() controlTBS {
			f := tbsFor(OpRename, identity.ID{}, "n")
			f.Version = 2
			return f
		}(), ErrMalformed},
		"zero group": {func() controlTBS {
			f := tbsFor(OpRename, identity.ID{}, "n")
			f.GroupID = ID{}
			return f
		}(), ErrMalformed},
	}
	for name, tc := range cases {
		if _, err := ParseControl(signRaw(t, admin.id, tc.fields)); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}

	valid := mustControl(t, admin, base, OpRename, identity.ID{}, "n")
	var wire controlWire
	if err := decodeCanonical(valid, &wire); err != nil {
		t.Fatal(err)
	}
	wire.Sig = wire.Sig[:len(wire.Sig)-1]
	shortSig, err := encMode.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string][]byte{
		"short signature": shortSig,
		"trailing":        append(slices.Clone(valid), 0x00),
		"truncated":       valid[:len(valid)-1],
		"empty":           nil,
		"oversized":       make([]byte, MaxControlSize+1),
		"empty map":       {0xa0},
	}
	for name, input := range raw {
		if _, err := ParseControl(input); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v", name, err)
		}
	}

	c, err := ParseControl(valid)
	if err != nil {
		t.Fatal(err)
	}
	valid[0] ^= 0xff
	if c.Raw[0] == valid[0] {
		t.Fatal("Raw aliases the input")
	}
}

func TestMaxMembers(t *testing.T) {
	ms := testMembers(t)
	creator := ms[0]
	others := make([]identity.ID, 0, MaxMembers)
	for range MaxMembers - 1 {
		others = append(others, randomID(t))
	}

	if _, _, err := NewGroup(creator.id, "big", append(slices.Clone(others), randomID(t))); !errors.Is(err, ErrTooManyMembers) {
		t.Fatalf("257 members: %v", err)
	}

	full, raw, err := NewGroup(creator.id, strings.Repeat("\U0001F600", MaxNameRunes), others)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Members) != MaxMembers || len(raw) > MaxControlSize {
		t.Fatalf("%d members, control of %d bytes", len(full.Members), len(raw))
	}
	received := mustApply(t, nil, raw, creator)
	if !statesEqual(received, full) {
		t.Fatal("receiver state differs")
	}

	if _, err := NewControl(creator.id, full, OpAdd, ms[1].id.ID(), ""); !errors.Is(err, ErrTooManyMembers) {
		t.Fatalf("add to full group: %v", err)
	}
	forged := signRaw(t, creator.id, nextTBS(full, creator.id.ID(), OpAdd, ms[1].id.ID(), ""))
	if _, err := applyRaw(&full, forged, creator); !errors.Is(err, ErrTooManyMembers) {
		t.Fatalf("Apply add to full group: %v", err)
	}

	allAdmins := full.clone()
	allAdmins.Epoch = math.MaxUint64
	allAdmins.LastRemovalEpoch = math.MaxUint64
	allAdmins.Admins = slices.Clone(full.Members)
	allAdmins.AdminSince = make([]uint64, len(full.Members))
	for i := range allAdmins.AdminSince {
		allAdmins.AdminSince[i] = math.MaxUint64 - uint64(i)
	}
	encoded, err := allAdmins.Marshal()
	if err != nil || len(encoded) > MaxStateSize {
		t.Fatalf("largest state: %d bytes, %v", len(encoded), err)
	}
	if _, err := UnmarshalState(encoded); err != nil {
		t.Fatal(err)
	}

	tooBig := allAdmins.clone()
	tooBig.Members = append(tooBig.Members, identity.ID{0xff, 0xff, 0xff, 0xff})
	slices.SortFunc(tooBig.Members, compareIDs)
	if _, err := tooBig.Marshal(); !errors.Is(err, ErrTooManyMembers) {
		t.Fatalf("Marshal of 257 members: %v", err)
	}
	tooBigEncoded, err := encMode.Marshal(tooBig.wire())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalState(tooBigEncoded); !errors.Is(err, ErrTooManyMembers) {
		t.Fatalf("UnmarshalState of 257 members: %v", err)
	}
}

func TestValidateName(t *testing.T) {
	good := []string{"a", "Family \u00e9t\u00e9", strings.Repeat("\u4e2d", MaxNameRunes), "\U0001F600 emoji", "tab-free name"}
	for _, name := range good {
		if err := validateName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	bad := []string{
		"", strings.Repeat("a", MaxNameRunes+1), "a\x00b", "a\tb", "a\x7fb", "a\u0085b",
		"\u202eevil", "\u2066x\u2069", "\u200f", "\u061c", "zero\u200bwidth", "\ufeffbom",
		"line\u2028sep", "para\u2029sep", "\xff", "a\xc0\x80",
	}
	for _, name := range bad {
		if err := validateName(name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q: got %v", name, err)
		}
	}
}

func TestOpString(t *testing.T) {
	if OpCreate.String() != "create" || OpLeave.String() != "leave" || Op(9).String() != "op(9)" {
		t.Fatal("Op.String")
	}
}
