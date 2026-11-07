package group

import (
	"bytes"
	"crypto/rand"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/identity"
)

// member is a test identity together with its verified bundle.
type member struct {
	id     *identity.Identity
	bundle *identity.Bundle
}

const memberCount = 5

var (
	membersOnce sync.Once
	membersErr  error
	allMembers  []member
)

// testMembers returns memberCount identities sorted by ID, generated once
// per test binary.
func testMembers(tb testing.TB) []member {
	tb.Helper()
	membersOnce.Do(func() {
		for range memberCount {
			id, err := identity.Generate()
			if err != nil {
				membersErr = err
				return
			}
			raw, err := id.Bundle(1, time.Unix(1700000000, 0))
			if err != nil {
				membersErr = err
				return
			}
			bundle, err := identity.ParseBundle(raw)
			if err != nil {
				membersErr = err
				return
			}
			allMembers = append(allMembers, member{id: id, bundle: bundle})
		}
		slices.SortFunc(allMembers, func(a, b member) int { return compareIDs(a.id.ID(), b.id.ID()) })
	})
	if membersErr != nil {
		tb.Fatal(membersErr)
	}
	return allMembers
}

// ids returns the IDs of ms.
func ids(ms ...member) []identity.ID {
	out := make([]identity.ID, len(ms))
	for i, m := range ms {
		out[i] = m.id.ID()
	}
	return out
}

func randomID(tb testing.TB) identity.ID {
	tb.Helper()
	var id identity.ID
	rand.Read(id[:])
	return id
}

// signRaw encodes and signs t with signer without any syntax or rule
// checks, so that tests can produce validly signed controls that the rules
// must reject.
func signRaw(tb testing.TB, signer *identity.Identity, t controlTBS) []byte {
	tb.Helper()
	tbs, err := encMode.Marshal(t)
	if err != nil {
		tb.Fatal(err)
	}
	sig, err := signer.SignGroupControl(tbs)
	if err != nil {
		tb.Fatal(err)
	}
	raw, err := encMode.Marshal(t.wire(sig))
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

// applyRaw parses raw and applies it to cur with the bundle of actor.
func applyRaw(cur *State, raw []byte, actor member) (State, error) {
	c, err := ParseControl(raw)
	if err != nil {
		return State{}, err
	}
	return Apply(cur, c, actor.bundle)
}

// mustApply applies a control the test expects to be accepted.
func mustApply(tb testing.TB, cur *State, raw []byte, actor member) State {
	tb.Helper()
	next, err := applyRaw(cur, raw, actor)
	if err != nil {
		tb.Fatalf("Apply: %v", err)
	}
	return next
}

// mustControl builds a control the test expects to be valid.
func mustControl(tb testing.TB, actor member, cur State, op Op, target identity.ID, name string) []byte {
	tb.Helper()
	raw, err := NewControl(actor.id, cur, op, target, name)
	if err != nil {
		tb.Fatalf("NewControl(%v): %v", op, err)
	}
	return raw
}

// nextTBS returns the unsigned control for op on cur as NewControl would
// build it.
func nextTBS(cur State, actor identity.ID, op Op, target identity.ID, name string) controlTBS {
	return controlTBS{
		Version: Version, GroupID: cur.GroupID, Epoch: cur.Epoch + 1, Actor: actor, Op: op,
		Target: target, Name: name, StateHash: cur.Hash(),
	}
}

func statesEqual(a, b State) bool {
	encA, errA := encMode.Marshal(a.wire())
	encB, errB := encMode.Marshal(b.wire())
	return errA == nil && errB == nil && bytes.Equal(encA, encB)
}

// baseGroup returns a group created by ms[0] with members ms[0..3] and
// admins ms[0] and ms[1]. ms[4] is not a member.
func baseGroup(tb testing.TB) (State, []member) {
	tb.Helper()
	ms := testMembers(tb)
	_, raw, err := NewGroup(ms[0].id, "base", ids(ms[1], ms[2], ms[3]))
	if err != nil {
		tb.Fatal(err)
	}
	created := mustApply(tb, nil, raw, ms[0])
	promoted := mustApply(tb, &created, mustControl(tb, ms[0], created, OpPromote, ms[1].id.ID(), ""), ms[0])
	return promoted, ms
}
