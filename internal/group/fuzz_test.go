package group

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/craguS/qchat/internal/identity"
)

func FuzzParseControl(f *testing.F) {
	base, ms := baseGroup(f)
	f.Add(mustControl(f, ms[0], base, OpRename, identity.ID{}, "seed"))
	f.Add(mustControl(f, ms[0], base, OpAdd, ms[4].id.ID(), ""))
	f.Add(mustControl(f, ms[2], base, OpLeave, identity.ID{}, ""))
	_, create, err := NewGroup(ms[1].id, "seed group", ids(ms[0], ms[3]))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(create)
	f.Add([]byte{0xa0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		c, err := ParseControl(input)
		if err != nil {
			if c != nil {
				t.Fatal("non-nil control with error")
			}
			return
		}
		fields := controlTBS{
			Version: Version, GroupID: c.GroupID, Epoch: c.Epoch, Actor: c.Actor, Op: c.Op,
			Target: c.Target, Name: c.Name, Members: c.Members, StateHash: c.StateHash,
		}
		if err := fields.checkSyntax(); err != nil {
			t.Fatalf("accepted control fails syntax check: %v", err)
		}
		tbs, err := encMode.Marshal(fields)
		if err != nil || !bytes.Equal(tbs, c.tbs) {
			t.Fatalf("signed bytes differ from the fields: %v", err)
		}
		reencoded, err := encMode.Marshal(fields.wire(c.sig))
		if err != nil || !bytes.Equal(reencoded, input) || !bytes.Equal(c.Raw, input) {
			t.Fatalf("control is not the canonical encoding of its fields: %v", err)
		}
		again, err := ParseControl(c.Raw)
		if err != nil || !again.sameFields(c) {
			t.Fatalf("re-parse differs: %v", err)
		}
	})
}

// fuzzStates returns the states FuzzApply chooses from: a group with two
// admins, a group with a single admin, and a dissolved group.
func fuzzStates(tb testing.TB) ([]State, []member) {
	tb.Helper()
	base, ms := baseGroup(tb)
	_, raw, err := NewGroup(ms[3].id, "pair", ids(ms[2]))
	if err != nil {
		tb.Fatal(err)
	}
	pair := mustApply(tb, nil, raw, ms[3])
	alone := mustApply(tb, &pair, mustControl(tb, ms[2], pair, OpLeave, identity.ID{}, ""), ms[2])
	dissolved := mustApply(tb, &alone, mustControl(tb, ms[3], alone, OpLeave, identity.ID{}, ""), ms[3])
	return []State{base, pair, dissolved}, ms
}

func FuzzApply(f *testing.F) {
	states, ms := fuzzStates(f)
	f.Add(uint8(0), uint8(0), uint8(OpAdd), uint8(5), "", int8(0), false, false)
	f.Add(uint8(0), uint8(2), uint8(OpRemove), uint8(1), "", int8(0), false, false)
	f.Add(uint8(0), uint8(1), uint8(OpDemote), uint8(2), "", int8(0), false, false)
	f.Add(uint8(1), uint8(3), uint8(OpLeave), uint8(0), "", int8(0), false, false)
	f.Add(uint8(1), uint8(3), uint8(OpDemote), uint8(4), "", int8(0), false, false)
	f.Add(uint8(0), uint8(0), uint8(OpRename), uint8(0), "new \u202e name", int8(0), false, false)
	f.Add(uint8(0), uint8(0), uint8(OpPromote), uint8(3), "", int8(1), false, false)
	f.Add(uint8(0), uint8(0), uint8(OpPromote), uint8(3), "", int8(0), true, false)
	f.Add(uint8(0), uint8(0), uint8(OpPromote), uint8(3), "", int8(0), false, true)
	f.Add(uint8(2), uint8(2), uint8(OpAdd), uint8(1), "", int8(0), false, false)
	f.Fuzz(func(t *testing.T, stateIdx, actorIdx, op, targetIdx uint8, name string, epochDelta int8, badHash, wrongBundle bool) {
		cur := states[int(stateIdx)%len(states)]
		actor := ms[int(actorIdx)%len(ms)]
		target := identity.ID{}
		if idx := int(targetIdx) % (len(ms) + 2); idx > 0 && idx <= len(ms) {
			target = ms[idx-1].id.ID()
		} else if idx == len(ms)+1 {
			target = identity.ID{0x42}
		}

		fields := nextTBS(cur, actor.id.ID(), Op(op), target, name)
		fields.Epoch += uint64(int64(epochDelta))
		if badHash {
			fields.StateHash[0] ^= 1
		}
		if fields.checkSyntax() != nil {
			return
		}
		bundle := actor
		if wrongBundle {
			bundle = ms[(int(actorIdx)+1)%len(ms)]
		}

		before, err := encMode.Marshal(cur.wire())
		if err != nil {
			t.Fatal(err)
		}
		next, err := applyRaw(&cur, signRaw(t, actor.id, fields), bundle)
		after, _ := encMode.Marshal(cur.wire())
		if !bytes.Equal(before, after) {
			t.Fatal("Apply modified the current state")
		}

		honest := epochDelta == 0 && !badHash && !wrongBundle
		if honest {
			_, builderErr := NewControl(actor.id, cur, Op(op), target, name)
			if (builderErr == nil) != (err == nil) {
				t.Fatalf("NewControl and Apply disagree: %v vs %v", builderErr, err)
			}
		}
		if wrongBundle && !errors.Is(err, ErrBadSignature) {
			t.Fatalf("control accepted with a foreign bundle: %v", err)
		}
		if err != nil {
			return
		}
		if !honest {
			t.Fatal("dishonest control accepted")
		}
		if next.Epoch != cur.Epoch+1 || next.GroupID != cur.GroupID {
			t.Fatal("epoch or group changed incorrectly")
		}
		if !cur.IsMember(actor.id.ID()) {
			t.Fatal("non-member control accepted")
		}
		if Op(op) != OpLeave && !cur.IsAdmin(actor.id.ID()) {
			t.Fatal("admin operation by non-admin accepted")
		}
		encoded, err := next.Marshal()
		if err != nil {
			t.Fatalf("result invalid: %v", err)
		}
		decoded, err := UnmarshalState(encoded)
		if err != nil || decoded.Hash() != next.Hash() {
			t.Fatalf("result does not round trip: %v", err)
		}
		recipients := Recipients(cur, next)
		for _, member := range slices.Concat(cur.Members, next.Members) {
			if !containsID(recipients, member) {
				t.Fatal("Recipients misses a member")
			}
		}
	})
}
