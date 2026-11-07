package group

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/craguS/qchat/internal/identity"
)

// conflict is a control built on a common state together with its actor.
type conflict struct {
	c     *Control
	actor member
}

func mustParse(tb testing.TB, raw []byte) *Control {
	tb.Helper()
	c, err := ParseControl(raw)
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

// newConflict builds and parses the control by which actor performs op on
// prev.
func newConflict(tb testing.TB, prev State, actor member, op Op, target identity.ID, name string) conflict {
	tb.Helper()
	return conflict{c: mustParse(tb, mustControl(tb, actor, prev, op, target, name)), actor: actor}
}

// seniorityGroup returns a group created by ms[3] with members ms[0] to
// ms[3], in which ms[0] was promoted at epoch 2 and ms[1] at epoch 3. The
// most senior admin, ms[3], has the largest ID of the four and the most
// junior one but ms[1], ms[0], the smallest, so seniority and ID order
// disagree.
func seniorityGroup(tb testing.TB) (State, []member) {
	tb.Helper()
	ms := testMembers(tb)
	_, raw, err := NewGroup(ms[3].id, "seniority", ids(ms[0], ms[1], ms[2]))
	if err != nil {
		tb.Fatal(err)
	}
	created := mustApply(tb, nil, raw, ms[3])
	first := mustApply(tb, &created, mustControl(tb, ms[3], created, OpPromote, ms[0].id.ID(), ""), ms[3])
	return mustApply(tb, &first, mustControl(tb, ms[3], first, OpPromote, ms[1].id.ID(), ""), ms[3]), ms
}

// requireWinner checks that want beats other in both argument orders of
// Resolve and of ApplyOrResolve, and that ApplyOrResolve returns the state
// Apply produces for want.
func requireWinner(t *testing.T, prev State, want, other conflict) {
	t.Helper()
	if Resolve(prev, want.c, other.c) != want.c || Resolve(prev, other.c, want.c) != want.c {
		t.Fatalf("Resolve: %v by %x does not beat %v by %x", want.c.Op, want.c.Actor[:4], other.c.Op, other.c.Actor[:4])
	}
	wantState, err := Apply(&prev, want.c, want.actor.bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]conflict{{want, other}, {other, want}} {
		next, winner, err := ApplyOrResolve(prev, pair[0].c, pair[1].c, pair[1].actor.bundle)
		if err != nil {
			t.Fatalf("ApplyOrResolve: %v", err)
		}
		if winner != want.c || !statesEqual(next, wantState) {
			t.Fatal("ApplyOrResolve picks a different winner or state")
		}
	}
}

func TestResolveRemovedAdminCannotGrind(t *testing.T) {
	prev, ms := seniorityGroup(t)
	remover, attacker := ms[3], ms[0]
	if compareIDs(attacker.id.ID(), remover.id.ID()) >= 0 {
		t.Fatal("test needs an attacker with the smaller ID")
	}
	removal := newConflict(t, prev, remover, OpRemove, attacker.id.ID(), "")

	counters := []conflict{
		newConflict(t, prev, attacker, OpRemove, remover.id.ID(), ""),
		newConflict(t, prev, attacker, OpDemote, remover.id.ID(), ""),
		newConflict(t, prev, attacker, OpRemove, ms[1].id.ID(), ""),
		newConflict(t, prev, attacker, OpPromote, ms[2].id.ID(), ""),
		newConflict(t, prev, attacker, OpAdd, ms[4].id.ID(), ""),
		newConflict(t, prev, attacker, OpRename, identity.ID{}, "mine"),
		newConflict(t, prev, attacker, OpLeave, identity.ID{}, ""),
	}
	for _, counter := range counters {
		requireWinner(t, prev, removal, counter)
	}

	removalHash := sha256.Sum256(removal.c.Raw)
	ground := false
	for range 64 {
		counter := newConflict(t, prev, attacker, OpRemove, remover.id.ID(), "")
		requireWinner(t, prev, removal, counter)
		if hash := sha256.Sum256(counter.c.Raw); bytes.Compare(hash[:], removalHash[:]) < 0 {
			ground = true
			break
		}
	}
	if !ground {
		t.Fatal("no re-signed counter-removal with a smaller hash found")
	}

	demotion := newConflict(t, prev, remover, OpDemote, attacker.id.ID(), "")
	requireWinner(t, prev, demotion, counters[0])

	after := mustApply(t, &prev, removal.c.Raw, remover)
	if _, err := NewControl(attacker.id, after, OpRemove, remover.id.ID(), ""); !errors.Is(err, ErrNotMember) {
		t.Fatalf("re-issued counter-removal: %v", err)
	}
}

func TestResolveMutualRemovalBySeniority(t *testing.T) {
	prev, ms := seniorityGroup(t)
	senior, middle, junior := ms[3], ms[0], ms[1]

	requireWinner(t, prev,
		newConflict(t, prev, senior, OpRemove, junior.id.ID(), ""),
		newConflict(t, prev, junior, OpRemove, senior.id.ID(), ""))
	requireWinner(t, prev,
		newConflict(t, prev, middle, OpRemove, junior.id.ID(), ""),
		newConflict(t, prev, junior, OpRemove, middle.id.ID(), ""))
	requireWinner(t, prev,
		newConflict(t, prev, middle, OpDemote, junior.id.ID(), ""),
		newConflict(t, prev, junior, OpDemote, middle.id.ID(), ""))
	requireWinner(t, prev,
		newConflict(t, prev, senior, OpDemote, middle.id.ID(), ""),
		newConflict(t, prev, middle, OpRemove, senior.id.ID(), ""))

	demoted := mustApply(t, &prev, mustControl(t, senior, prev, OpDemote, middle.id.ID(), ""), senior)
	repromoted := mustApply(t, &demoted, mustControl(t, senior, demoted, OpPromote, middle.id.ID(), ""), senior)
	if since, _ := repromoted.adminSince(middle.id.ID()); since != repromoted.Epoch {
		t.Fatalf("re-promoted admin since %d, want %d", since, repromoted.Epoch)
	}
	requireWinner(t, repromoted,
		newConflict(t, repromoted, junior, OpRemove, middle.id.ID(), ""),
		newConflict(t, repromoted, middle, OpRemove, junior.id.ID(), ""))
}

func TestResolveRevocationOrder(t *testing.T) {
	prev, ms := seniorityGroup(t)
	senior, junior, plain := ms[3], ms[1], ms[2]
	removeSenior := newConflict(t, prev, junior, OpRemove, senior.id.ID(), "")

	t.Run("removal beats the target's grants", func(t *testing.T) {
		requireWinner(t, prev, removeSenior, newConflict(t, prev, senior, OpAdd, ms[4].id.ID(), ""))
		requireWinner(t, prev, removeSenior, newConflict(t, prev, senior, OpPromote, plain.id.ID(), ""))
		requireWinner(t, prev, newConflict(t, prev, junior, OpDemote, senior.id.ID(), ""),
			newConflict(t, prev, senior, OpRename, identity.ID{}, "late"))
	})
	t.Run("senior revocation beats junior revocation", func(t *testing.T) {
		requireWinner(t, prev, newConflict(t, prev, senior, OpRemove, plain.id.ID(), ""), removeSenior)
		requireWinner(t, prev, newConflict(t, prev, senior, OpLeave, identity.ID{}, ""), removeSenior)
	})
	t.Run("leave", func(t *testing.T) {
		leave := newConflict(t, prev, junior, OpLeave, identity.ID{}, "")
		requireWinner(t, prev, leave, newConflict(t, prev, junior, OpRename, identity.ID{}, "x"))
		requireWinner(t, prev, leave, newConflict(t, prev, junior, OpRemove, plain.id.ID(), ""))
		plainLeave := newConflict(t, prev, plain, OpLeave, identity.ID{}, "")
		requireWinner(t, prev, plainLeave, newConflict(t, prev, senior, OpAdd, ms[4].id.ID(), ""))
		requireWinner(t, prev, newConflict(t, prev, junior, OpRemove, plain.id.ID(), ""), plainLeave)
	})
}

func TestResolveGrantsByHash(t *testing.T) {
	prev, ms := seniorityGroup(t)
	for range 4 {
		a := newConflict(t, prev, ms[3], OpRename, identity.ID{}, "a")
		b := newConflict(t, prev, ms[1], OpAdd, ms[4].id.ID(), "")
		hashA, hashB := sha256.Sum256(a.c.Raw), sha256.Sum256(b.c.Raw)
		if bytes.Compare(hashA[:], hashB[:]) < 0 {
			requireWinner(t, prev, a, b)
		} else {
			requireWinner(t, prev, b, a)
		}
	}

	c := newConflict(t, prev, ms[0], OpRename, identity.ID{}, "c")
	copied := mustParse(t, c.c.Raw)
	if Resolve(prev, c.c, copied) != c.c || Resolve(prev, copied, c.c) != copied {
		t.Fatal("identical controls must resolve to the first argument")
	}
	if Resolve(prev, c.c, nil) != c.c || Resolve(prev, nil, c.c) != c.c || Resolve(prev, nil, nil) != nil {
		t.Fatal("nil handling")
	}
}

// conflictSet returns every control the admins of a seniority group can
// issue on it, plus the leave of every member, with several signatures of
// some of them.
func conflictSet(tb testing.TB) (State, []conflict) {
	tb.Helper()
	prev, ms := seniorityGroup(tb)
	var out []conflict
	for _, actor := range ms[:4] {
		out = append(out, newConflict(tb, prev, actor, OpLeave, identity.ID{}, ""))
		if !prev.IsAdmin(actor.id.ID()) {
			continue
		}
		for _, target := range ms[:4] {
			for _, op := range []Op{OpRemove, OpDemote} {
				if raw, err := NewControl(actor.id, prev, op, target.id.ID(), ""); err == nil {
					out = append(out, conflict{c: mustParse(tb, raw), actor: actor})
				}
			}
		}
		out = append(out,
			newConflict(tb, prev, actor, OpPromote, ms[2].id.ID(), ""),
			newConflict(tb, prev, actor, OpAdd, ms[4].id.ID(), ""),
			newConflict(tb, prev, actor, OpRename, identity.ID{}, "r"),
			newConflict(tb, prev, actor, OpRename, identity.ID{}, "r"),
		)
	}
	return prev, out
}

func TestResolveIsTotalOrder(t *testing.T) {
	prev, set := conflictSet(t)
	n := len(set)
	beats := make([][]bool, n)
	for i := range set {
		beats[i] = make([]bool, n)
		for j := range set {
			if i == j || bytes.Equal(set[i].c.Raw, set[j].c.Raw) {
				continue
			}
			winner := Resolve(prev, set[i].c, set[j].c)
			if winner != Resolve(prev, set[j].c, set[i].c) {
				t.Fatalf("Resolve depends on argument order for %d, %d", i, j)
			}
			beats[i][j] = winner == set[i].c
		}
	}
	for i := range n {
		for j := range n {
			for k := range n {
				if i != j && j != k && i != k && beats[i][j] && beats[j][k] && !beats[i][k] {
					t.Fatalf("Resolve is not transitive: %d > %d > %d > %d", i, j, k, i)
				}
			}
		}
	}

	fold := func(order []int) *Control {
		var winner *Control
		for _, i := range order {
			winner = Resolve(prev, winner, set[i].c)
		}
		return winner
	}
	forward := make([]int, n)
	for i := range forward {
		forward[i] = i
	}
	backward := make([]int, n)
	for i := range backward {
		backward[i] = n - 1 - i
	}
	if fold(forward) != fold(backward) {
		t.Fatal("folding in different orders gives different winners")
	}
}

func TestResolveRemovalCycle(t *testing.T) {
	prev, ms := seniorityGroup(t)
	cycle := []conflict{
		newConflict(t, prev, ms[3], OpRemove, ms[0].id.ID(), ""),
		newConflict(t, prev, ms[0], OpRemove, ms[1].id.ID(), ""),
		newConflict(t, prev, ms[1], OpRemove, ms[3].id.ID(), ""),
	}
	orders := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, order := range orders {
		first := cycle[order[0]]
		cur, err := Apply(&prev, first.c, first.actor.bundle)
		if err != nil {
			t.Fatal(err)
		}
		applied := first.c
		for _, i := range order[1:] {
			if !CanResolveAgainst(cur, cycle[i].c) {
				t.Fatal("conflict outside the window")
			}
			if cur, applied, err = ApplyOrResolve(prev, applied, cycle[i].c, cycle[i].actor.bundle); err != nil {
				t.Fatal(err)
			}
		}
		if applied != cycle[0].c || cur.IsMember(ms[0].id.ID()) {
			t.Fatalf("order %v converges on a different winner", order)
		}
	}
}

func TestConflictWindow(t *testing.T) {
	prev, ms := baseGroup(t)
	applied := newConflict(t, prev, ms[0], OpRename, identity.ID{}, "applied")
	incoming := newConflict(t, prev, ms[1], OpAdd, ms[4].id.ID(), "")
	cur := mustApply(t, &prev, applied.c.Raw, ms[0])

	if !CanResolveAgainst(cur, incoming.c) {
		t.Fatal("conflicting control rejected inside the window")
	}
	later := mustApply(t, &cur, mustControl(t, ms[0], cur, OpRename, identity.ID{}, "later"), ms[0])
	if CanResolveAgainst(later, incoming.c) {
		t.Fatal("conflicting control accepted after a later control")
	}
	future := mustParse(t, mustControl(t, ms[0], later, OpRename, identity.ID{}, "future"))
	if CanResolveAgainst(cur, future) {
		t.Fatal("control for a later epoch treated as a conflict")
	}
	foreign := cur.clone()
	foreign.GroupID[0] ^= 1
	if CanResolveAgainst(foreign, incoming.c) {
		t.Fatal("control of another group treated as a conflict")
	}
	if CanResolveAgainst(cur, nil) {
		t.Fatal("nil control")
	}
	_, createRaw, err := NewGroup(ms[0].id, "other", nil)
	if err != nil {
		t.Fatal(err)
	}
	created := mustApply(t, nil, createRaw, ms[0])
	if CanResolveAgainst(created, mustParse(t, createRaw)) {
		t.Fatal("create treated as a conflict")
	}

	t.Run("ApplyOrResolve", func(t *testing.T) {
		if _, _, err := ApplyOrResolve(prev, applied.c, incoming.c, ms[2].bundle); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("foreign bundle: %v", err)
		}
		otherBase := nextTBS(prev, ms[0].id.ID(), OpRename, identity.ID{}, "sideways")
		otherBase.StateHash[0] ^= 1
		sideways := mustParse(t, signRaw(t, ms[0].id, otherBase))
		if !CanResolveAgainst(cur, sideways) {
			t.Fatal("same-epoch control outside the window")
		}
		if _, _, err := ApplyOrResolve(prev, applied.c, sideways, ms[0].bundle); !errors.Is(err, ErrStateMismatch) {
			t.Fatalf("control built on another state: %v", err)
		}
		alternative := prev.clone()
		alternative.Name = "alternative"
		if _, _, err := ApplyOrResolve(alternative, applied.c, incoming.c, ms[1].bundle); !errors.Is(err, ErrStateMismatch) {
			t.Fatalf("applied control not built on prev: %v", err)
		}
		tampered := *applied.c
		tampered.Name = "tampered"
		if _, _, err := ApplyOrResolve(prev, &tampered, incoming.c, ms[1].bundle); !errors.Is(err, ErrMalformed) {
			t.Fatalf("tampered applied control: %v", err)
		}
		if _, _, err := ApplyOrResolve(prev, nil, incoming.c, ms[1].bundle); !errors.Is(err, ErrMalformed) {
			t.Fatalf("nil applied control: %v", err)
		}
		duplicate := mustParse(t, applied.c.Raw)
		next, winner, err := ApplyOrResolve(prev, applied.c, duplicate, ms[0].bundle)
		if err != nil || winner != applied.c || !statesEqual(next, cur) {
			t.Fatalf("duplicate: %v", err)
		}
	})
}
