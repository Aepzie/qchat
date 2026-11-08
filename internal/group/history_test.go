package group

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/Aepzie/qchat/internal/identity"
)

// testHistory returns the history of a group created by ms[0] with ms[1]
// and ms[2], in which ms[1] is promoted, ms[1] adds ms[3], ms[0] renames
// the group, ms[1] removes ms[2] and finally ms[0] adds ms[4]. states[i] is
// the state after controls[i].
func testHistory(tb testing.TB) (History, []State, []member) {
	tb.Helper()
	ms := testMembers(tb)
	_, create, err := NewGroup(ms[0].id, "history", ids(ms[1], ms[2]))
	if err != nil {
		tb.Fatal(err)
	}
	controls := History{create}
	states := []State{mustApply(tb, nil, create, ms[0])}
	step := func(actor member, op Op, target identity.ID, name string) {
		cur := states[len(states)-1]
		raw := mustControl(tb, actor, cur, op, target, name)
		controls = append(controls, raw)
		states = append(states, mustApply(tb, &cur, raw, actor))
	}
	step(ms[0], OpPromote, ms[1].id.ID(), "")
	step(ms[1], OpAdd, ms[3].id.ID(), "")
	step(ms[0], OpRename, identity.ID{}, "renamed")
	step(ms[1], OpRemove, ms[2].id.ID(), "")
	step(ms[0], OpAdd, ms[4].id.ID(), "")
	return controls, states, ms
}

// bundleSource returns a bundle callback over ms that counts its calls.
func bundleSource(ms []member, calls map[identity.ID]int) func(identity.ID) (*identity.Bundle, error) {
	return func(id identity.ID) (*identity.Bundle, error) {
		calls[id]++
		for _, m := range ms {
			if m.id.ID() == id {
				return m.bundle, nil
			}
		}
		return nil, errUnknownActor
	}
}

var errUnknownActor = errors.New("unknown actor")

// rewire decodes raw as a control, lets mutate change it and re-encodes it
// without signing it again.
func rewire(tb testing.TB, raw []byte, mutate func(w *controlWire)) []byte {
	tb.Helper()
	var w controlWire
	if err := decMode.Unmarshal(raw, &w); err != nil {
		tb.Fatal(err)
	}
	mutate(&w)
	out, err := encMode.Marshal(w)
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

func TestVerifyHistory(t *testing.T) {
	controls, states, ms := testHistory(t)
	calls := map[identity.ID]int{}
	final, err := VerifyHistory(controls, bundleSource(ms, calls))
	if err != nil {
		t.Fatal(err)
	}
	if !statesEqual(final, states[len(states)-1]) {
		t.Fatal("replayed state differs")
	}
	if len(calls) != 2 || calls[ms[0].id.ID()] != 1 || calls[ms[1].id.ID()] != 1 {
		t.Fatalf("bundle calls %v, want one per actor", calls)
	}
	for i := range controls {
		prefix, err := VerifyHistory(controls[:i+1], bundleSource(ms, map[identity.ID]int{}))
		if err != nil || !statesEqual(prefix, states[i]) {
			t.Fatalf("prefix %d: %v", i, err)
		}
	}

	joined, err := VerifyJoin(controls, ms[4].id.ID(), ms[0].id.ID(), bundleSource(ms, map[identity.ID]int{}))
	if err != nil || !statesEqual(joined, final) || !joined.IsMember(ms[4].id.ID()) {
		t.Fatalf("VerifyJoin: %v", err)
	}

	encoded, err := controls.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalHistory(encoded)
	if err != nil || !slices.EqualFunc(decoded, controls, bytes.Equal) {
		t.Fatalf("history round trip: %v", err)
	}
	if viaMethod, err := decoded.Verify(bundleSource(ms, map[identity.ID]int{})); err != nil || !statesEqual(viaMethod, final) {
		t.Fatalf("History.Verify: %v", err)
	}
}

func TestVerifyHistoryRejectsForgeries(t *testing.T) {
	controls, states, ms := testHistory(t)
	replace := func(i int, raw []byte) History {
		forged := slices.Clone(controls)
		forged[i] = raw
		return forged
	}

	wrongHash := nextTBS(states[2], ms[0].id.ID(), OpRename, identity.ID{}, "renamed")
	wrongHash.StateHash[0] ^= 1
	otherCreator := nextTBS(states[0], ms[3].id.ID(), OpAdd, ms[4].id.ID(), "")
	notAdmin := nextTBS(states[2], ms[3].id.ID(), OpAdd, ms[4].id.ID(), "")
	foreignSigner := nextTBS(states[1], ms[1].id.ID(), OpAdd, ms[3].id.ID(), "")
	_, rivalCreate, err := NewGroup(ms[3].id, "history", ids(ms[0], ms[1], ms[2]))
	if err != nil {
		t.Fatal(err)
	}
	rival := rewire(t, rivalCreate, func(w *controlWire) { w.GroupID = states[0].GroupID })

	cases := map[string]struct {
		history History
		want    error
	}{
		"wrong state hash":  {replace(3, signRaw(t, ms[0].id, wrongHash)), ErrStateMismatch},
		"missing step":      {slices.Delete(slices.Clone(controls), 2, 3), ErrStaleEpoch},
		"reordered steps":   {append(History{controls[0], controls[2], controls[1]}, controls[3:]...), ErrStaleEpoch},
		"duplicated step":   {slices.Insert(slices.Clone(controls), 2, controls[1]), ErrStaleEpoch},
		"unsigned step":     {replace(1, rewire(t, controls[1], func(w *controlWire) { clear(w.Sig) })), ErrBadSignature},
		"foreign signature": {replace(2, signRaw(t, ms[3].id, foreignSigner)), ErrBadSignature},
		"member list lie": {replace(0, rewire(t, controls[0], func(w *controlWire) {
			w.Members = slices.Clone(w.Members)
			w.Members = insertID(w.Members, ms[4].id.ID())
		})), ErrBadSignature},
		"rival create":         {replace(0, signRaw(t, ms[3].id, mustTBS(t, rival))), ErrStateMismatch},
		"non-admin step":       {append(slices.Clone(controls[:3]), signRaw(t, ms[3].id, notAdmin)), ErrNotAdmin},
		"non-member step":      {History{controls[0], signRaw(t, ms[3].id, otherCreator)}, ErrNotMember},
		"no create":            {controls[1:], ErrInvalidOp},
		"second create":        {History{controls[0], controls[0]}, ErrInvalidOp},
		"garbage":              {replace(4, []byte{0xa0}), ErrMalformed},
		"empty":                {History{}, ErrBadHistory},
		"too many controls":    {make(History, MaxHistoryControls+1), ErrBadHistory},
		"too many bytes":       {oversizedHistory(), ErrBadHistory},
		"unknown actor bundle": {History{signRaw(t, identityOnly(t), createTBS(t))}, errUnknownActor},
	}
	for name, tc := range cases {
		if _, err := VerifyHistory(tc.history, bundleSource(ms, map[identity.ID]int{})); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}

	if _, err := VerifyHistory(controls, nil); !errors.Is(err, ErrBadHistory) {
		t.Errorf("nil bundle source: %v", err)
	}
	wrongBundle := func(identity.ID) (*identity.Bundle, error) { return ms[3].bundle, nil }
	if _, err := VerifyHistory(controls, wrongBundle); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong bundle: %v", err)
	}
}

// mustTBS returns the signed fields of the encoded control raw.
func mustTBS(tb testing.TB, raw []byte) controlTBS {
	tb.Helper()
	var w controlWire
	if err := decMode.Unmarshal(raw, &w); err != nil {
		tb.Fatal(err)
	}
	return w.tbs()
}

var (
	outsider    *identity.Identity
	outsiderErr error
)

// identityOnly returns an identity whose bundle no test source knows.
func identityOnly(tb testing.TB) *identity.Identity {
	tb.Helper()
	if outsider == nil && outsiderErr == nil {
		outsider, outsiderErr = identity.Generate()
	}
	if outsiderErr != nil {
		tb.Fatal(outsiderErr)
	}
	return outsider
}

// createTBS returns the fields of a create control by identityOnly.
func createTBS(tb testing.TB) controlTBS {
	tb.Helper()
	actor := identityOnly(tb).ID()
	return controlTBS{Version: Version, GroupID: ID{0x07}, Epoch: 1, Actor: actor, Op: OpCreate, Name: "x", Members: []identity.ID{actor}}
}

// oversizedHistory returns a history whose controls exceed MaxHistorySize
// in total, all sharing one buffer.
func oversizedHistory() History {
	shared := make([]byte, MaxControlSize+1)
	out := make(History, MaxHistorySize/len(shared)+1)
	for i := range out {
		out[i] = shared
	}
	return out
}

func TestVerifyJoin(t *testing.T) {
	controls, _, ms := testHistory(t)
	source := bundleSource(ms, map[identity.ID]int{})
	cases := map[string]struct {
		history     History
		self, adder identity.ID
	}{
		"other target":      {controls, ms[3].id.ID(), ms[0].id.ID()},
		"other adder":       {controls, ms[4].id.ID(), ms[1].id.ID()},
		"before the add":    {controls[:len(controls)-1], ms[4].id.ID(), ms[0].id.ID()},
		"not ending in add": {controls[:4], ms[2].id.ID(), ms[0].id.ID()},
	}
	for name, tc := range cases {
		if _, err := VerifyJoin(tc.history, tc.self, tc.adder, source); !errors.Is(err, ErrBadHistory) {
			t.Errorf("%s: got %v, want ErrBadHistory", name, err)
		}
	}
	forged := slices.Clone(controls)
	forged[len(forged)-1] = rewire(t, forged[len(forged)-1], func(w *controlWire) { w.Sig[0] ^= 1 })
	if _, err := VerifyJoin(forged, ms[4].id.ID(), ms[0].id.ID(), source); !errors.Is(err, ErrBadSignature) {
		t.Errorf("forged add: %v", err)
	}
}

func TestUnmarshalHistoryRejects(t *testing.T) {
	controls, _, _ := testHistory(t)
	good, err := controls[:2].Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encode := func(w historyWire) []byte {
		b, err := encMode.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	type extraField struct {
		historyWire
		Extra uint8 `cbor:"3,keyasint"`
	}
	extra, err := encMode.Marshal(extraField{historyWire: historyWire{Version: Version, Controls: controls[:1]}, Extra: 1})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		input []byte
		want  error
	}{
		"empty input":   {nil, ErrMalformed},
		"trailing":      {append(slices.Clone(good), 0x00), ErrMalformed},
		"version":       {encode(historyWire{Version: 2, Controls: controls[:1]}), ErrMalformed},
		"no controls":   {encode(historyWire{Version: Version}), ErrBadHistory},
		"unknown field": {extra, ErrMalformed},
		"oversized":     {make([]byte, MaxHistorySize+1), ErrMalformed},
	}
	for name, tc := range cases {
		if _, err := UnmarshalHistory(tc.input); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
	if _, err := (History{}).Marshal(); !errors.Is(err, ErrBadHistory) {
		t.Errorf("Marshal of an empty history: %v", err)
	}
	if _, err := oversizedHistory().Marshal(); !errors.Is(err, ErrBadHistory) {
		t.Errorf("Marshal of an oversized history: %v", err)
	}
}

func TestSeniorityAndRemovalEpoch(t *testing.T) {
	ms := testMembers(t)
	_, raw, err := NewGroup(ms[0].id, "epochs", ids(ms[1], ms[2], ms[3]))
	if err != nil {
		t.Fatal(err)
	}
	cur := mustApply(t, nil, raw, ms[0])
	if !slices.Equal(cur.AdminSince, []uint64{1}) || cur.LastRemovalEpoch != 0 {
		t.Fatalf("create: since %v, removal %d", cur.AdminSince, cur.LastRemovalEpoch)
	}
	steps := []struct {
		actor       member
		op          Op
		target      identity.ID
		since       map[identity.ID]uint64
		lastRemoval uint64
	}{
		{ms[0], OpPromote, ms[2].id.ID(), map[identity.ID]uint64{ms[0].id.ID(): 1, ms[2].id.ID(): 2}, 0},
		{ms[2], OpAdd, ms[4].id.ID(), map[identity.ID]uint64{ms[0].id.ID(): 1, ms[2].id.ID(): 2}, 0},
		{ms[0], OpRemove, ms[1].id.ID(), map[identity.ID]uint64{ms[0].id.ID(): 1, ms[2].id.ID(): 2}, 4},
		{ms[0], OpPromote, ms[3].id.ID(), map[identity.ID]uint64{ms[0].id.ID(): 1, ms[2].id.ID(): 2, ms[3].id.ID(): 5}, 4},
		{ms[3], OpDemote, ms[0].id.ID(), map[identity.ID]uint64{ms[2].id.ID(): 2, ms[3].id.ID(): 5}, 4},
		{ms[2], OpRename, identity.ID{}, map[identity.ID]uint64{ms[2].id.ID(): 2, ms[3].id.ID(): 5}, 4},
		{ms[2], OpPromote, ms[0].id.ID(), map[identity.ID]uint64{ms[0].id.ID(): 8, ms[2].id.ID(): 2, ms[3].id.ID(): 5}, 4},
		{ms[2], OpRemove, ms[3].id.ID(), map[identity.ID]uint64{ms[0].id.ID(): 8, ms[2].id.ID(): 2}, 9},
		{ms[4], OpLeave, identity.ID{}, map[identity.ID]uint64{ms[0].id.ID(): 8, ms[2].id.ID(): 2}, 10},
		{ms[2], OpLeave, identity.ID{}, map[identity.ID]uint64{ms[0].id.ID(): 8}, 11},
	}
	for _, step := range steps {
		name := ""
		if step.op == OpRename {
			name = "renamed"
		}
		cur = mustApply(t, &cur, mustControl(t, step.actor, cur, step.op, step.target, name), step.actor)
		if len(cur.Admins) != len(step.since) || cur.LastRemovalEpoch != step.lastRemoval {
			t.Fatalf("epoch %d (%v): admins %d, removal %d", cur.Epoch, step.op, len(cur.Admins), cur.LastRemovalEpoch)
		}
		for admin, since := range step.since {
			if got, ok := cur.adminSince(admin); !ok || got != since {
				t.Fatalf("epoch %d (%v): admin since %d, want %d", cur.Epoch, step.op, got, since)
			}
		}
		encoded, err := cur.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if decoded, err := UnmarshalState(encoded); err != nil || !statesEqual(decoded, cur) {
			t.Fatalf("round trip: %v", err)
		}
	}
	dissolved := mustApply(t, &cur, mustControl(t, ms[0], cur, OpLeave, identity.ID{}, ""), ms[0])
	if len(dissolved.AdminSince) != 0 || dissolved.LastRemovalEpoch != dissolved.Epoch {
		t.Fatalf("dissolved: since %v, removal %d", dissolved.AdminSince, dissolved.LastRemovalEpoch)
	}
	if _, err := dissolved.Marshal(); err != nil {
		t.Fatal(err)
	}
}

func TestBinding(t *testing.T) {
	state := katState()
	hash := state.Hash()
	input := []byte("qchat group state binding v1")
	input = append(input, state.GroupID[:]...)
	input = binary.BigEndian.AppendUint64(input, state.Epoch)
	input = append(input, hash[:]...)
	if state.Binding() != sha256.Sum256(input) {
		t.Fatal("Binding does not follow its definition")
	}
	const wantBinding = "407d37768fdfc50e5e3436e8f95d9f6e0ab614c8e170e524f1a13e00d0c00f44"
	binding := state.Binding()
	if got := hex.EncodeToString(binding[:]); got != wantBinding {
		t.Fatalf("Binding = %s, want %s", got, wantBinding)
	}

	mutations := []func(s *State){
		func(s *State) { s.Epoch++ },
		func(s *State) { s.Name = "other" },
		func(s *State) { s.LastRemovalEpoch = 6 },
		func(s *State) { s.AdminSince = []uint64{2} },
		func(s *State) { s.GroupID[31] ^= 1 },
	}
	for i, mutate := range mutations {
		other := state.clone()
		mutate(&other)
		if other.Binding() == binding {
			t.Errorf("mutation %d keeps the binding", i)
		}
	}
}
