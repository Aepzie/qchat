package app

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Aepzie/qchat/internal/client"
	"github.com/Aepzie/qchat/internal/e2e"
	"github.com/Aepzie/qchat/internal/group"
	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/senderkey"
	"github.com/Aepzie/qchat/internal/tui"
)

// settle delivers queued messages to every user until no queue has any
// left, and returns the incoming group texts each user was shown.
func settle(t *testing.T, users ...*fakeUser) map[*fakeUser][]string {
	t.Helper()
	got := map[*fakeUser][]string{}
	for round := 0; ; round++ {
		if round > 50 {
			t.Fatal("deliveries did not settle")
		}
		busy := false
		for _, u := range users {
			for _, d := range u.relay.take(u.id) {
				busy = true
				u.app.handleDelivery(context.Background(), d)
			}
			got[u] = append(got[u], u.groupTexts()...)
		}
		if !busy {
			return got
		}
	}
}

// groupTexts drains the events of u and returns the group message texts.
func (u *fakeUser) groupTexts() []string {
	var texts []string
	for _, ev := range u.drainEvents() {
		if in, ok := ev.(tui.IncomingMessage); ok && in.GroupID != "" {
			texts = append(texts, in.Message.Text)
		}
	}
	return texts
}

func (u *fakeUser) createGroup(name string, members ...*fakeUser) string {
	u.t.Helper()
	ids := make([]string, len(members))
	for i, m := range members {
		ids[i] = m.cid()
	}
	info, err := u.app.CreateGroup(context.Background(), name, ids)
	if err != nil {
		u.t.Fatalf("CreateGroup: %v", err)
	}
	u.drainEvents()
	return info.ID
}

func (u *fakeUser) sendGroup(gid, text string) tui.MessageInfo {
	u.t.Helper()
	m, err := u.app.Send(context.Background(), gid, text)
	if err != nil {
		u.t.Fatalf("group send %q: %v", text, err)
	}
	if m.Status != tui.StatusSent {
		u.t.Fatalf("group send %q: status %v (%s)", text, m.Status, m.Error)
	}
	return m
}

func (u *fakeUser) change(gid string, op tui.GroupOp, member *fakeUser) error {
	c := tui.GroupChange{Op: op}
	if member != nil {
		c.Member = member.cid()
	}
	_, err := u.app.ChangeGroup(context.Background(), gid, c)
	u.drainEvents()
	return err
}

func (u *fakeUser) groupInfo(gid string) tui.GroupInfo {
	u.t.Helper()
	list, err := u.app.Groups()
	if err != nil {
		u.t.Fatal(err)
	}
	for _, g := range list {
		if g.ID == gid {
			return g
		}
	}
	u.t.Fatalf("group %s not listed", gid)
	return tui.GroupInfo{}
}

func (u *fakeUser) groupHistory(gid string) []string {
	u.t.Helper()
	msgs, err := u.app.History(gid, 100)
	if err != nil {
		u.t.Fatal(err)
	}
	var texts []string
	for _, m := range msgs {
		texts = append(texts, m.Text)
	}
	return texts
}

func memberIDs(g tui.GroupInfo) []string {
	var ids []string
	for _, m := range g.Members {
		ids = append(ids, m.ID)
	}
	return ids
}

// befriend makes every user a contact of every other one.
func befriend(users ...*fakeUser) {
	for _, u := range users {
		for _, v := range users {
			if u != v {
				u.add(v)
			}
		}
	}
}

// newGroupRelay returns a fake relay whose clock is the real time: sender
// keys record their creation with the real clock, so a fake clock far from
// it would make every send rotate.
func newGroupRelay() *fakeRelay {
	r := newFakeRelay()
	r.clock.now = time.Now().Truncate(time.Second)
	return r
}

func newGroupOfThree(t *testing.T) (*fakeRelay, *fakeUser, *fakeUser, *fakeUser, string) {
	t.Helper()
	r := newGroupRelay()
	alice, bob, carol := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob"), newFakeUser(t, r, "Carol")
	befriend(alice, bob, carol)
	gid := alice.createGroup("Book club", bob, carol)
	settle(t, alice, bob, carol)
	return r, alice, bob, carol, gid
}

func TestGroupMessagesReachEveryMember(t *testing.T) {
	r, alice, bob, carol, gid := newGroupOfThree(t)
	for _, u := range []*fakeUser{bob, carol} {
		g := u.groupInfo(gid)
		if g.Name != "Book club" || len(g.Members) != 3 || g.Invite || g.Left {
			t.Fatalf("%v sees %+v", u.prof.DisplayName(), g)
		}
		for _, m := range g.Members {
			if m.Admin != (m.ID == alice.cid()) {
				t.Errorf("member %s admin = %v", m.ID, m.Admin)
			}
		}
	}
	alice.sendGroup(gid, "hello all")
	bob.sendGroup(gid, "hi from bob")
	carol.sendGroup(gid, "hi from carol")
	got := settle(t, alice, bob, carol)
	wantTexts(t, "alice", got[alice], "hi from bob", "hi from carol")
	wantTexts(t, "bob", got[bob], "hello all", "hi from carol")
	wantTexts(t, "carol", got[carol], "hello all", "hi from bob")
	wantTexts(t, "bob's history", bob.groupHistory(gid), "hi from bob", "hello all", "hi from carol")
	if r.multi != 3 {
		t.Errorf("%d SendMulti requests, want 3", r.multi)
	}
	for _, u := range []*fakeUser{alice, bob, carol} {
		if n := len(u.relay.acksOf(u.id)); n == 0 {
			t.Errorf("%s acknowledged nothing", u.prof.DisplayName())
		}
		if u.dropped() != 0 {
			t.Errorf("%s dropped %d deliveries", u.prof.DisplayName(), u.dropped())
		}
	}
	if err := bob.app.MarkRead(gid); err != nil {
		t.Fatal(err)
	}
	if g := bob.groupInfo(gid); g.Unread != 0 {
		t.Errorf("unread after MarkRead = %d", g.Unread)
	}
}

// headerCandidatesOf returns every header key u holds for sender in gid.
func headerCandidatesOf(t *testing.T, u *fakeUser, sender *fakeUser) []senderkey.HeaderCandidate {
	t.Helper()
	c, err := u.app.headerCandidates(context.Background(), sender.id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGroupRemoveRotatesKeys(t *testing.T) {
	r, alice, bob, carol, gid := newGroupOfThree(t)
	alice.sendGroup(gid, "before")
	bob.sendGroup(gid, "bob before")
	settle(t, alice, bob, carol)
	stolen := headerCandidatesOf(t, carol, alice)
	if len(stolen) != 1 {
		t.Fatalf("carol holds %d keys of alice", len(stolen))
	}

	if err := bob.change(gid, tui.GroupRemove, carol); err == nil || err.Error() != "only admins can do that" {
		t.Fatalf("non-admin remove: %v", err)
	}
	if err := alice.change(gid, tui.GroupRemove, carol); err != nil {
		t.Fatal(err)
	}
	settle(t, alice, bob, carol)
	if g := carol.groupInfo(gid); !g.Left {
		t.Fatal("carol does not know she was removed")
	}
	if c := headerCandidatesOf(t, carol, alice); len(c) != 0 {
		t.Errorf("carol kept %d sender keys", len(c))
	}
	if _, err := carol.app.Send(context.Background(), gid, "still here?"); !errors.Is(err, ErrLeftGroup) {
		t.Errorf("removed member could send: %v", err)
	}
	for _, u := range []*fakeUser{alice, bob} {
		g := u.groupInfo(gid)
		if slices.Contains(memberIDs(g), carol.cid()) {
			t.Errorf("%s still lists carol", u.prof.DisplayName())
		}
	}

	alice.sendGroup(gid, "after")
	bob.sendGroup(gid, "bob after")
	r.mu.Lock()
	leaked := r.queues[carol.id]
	r.mu.Unlock()
	if len(leaked) != 0 {
		t.Errorf("relay queued %d messages for the removed member", len(leaked))
	}
	bobQueue := r.queues[bob.id]
	var envelope []byte
	for _, d := range bobQueue {
		if senderkey.IsGroupEnvelope(d.Payload) {
			envelope = d.Payload
		}
	}
	if envelope == nil {
		t.Fatal("no group envelope for bob")
	}
	if _, _, err := senderkey.OpenHeader(envelope, stolen); !errors.Is(err, senderkey.ErrNoHeaderKey) {
		t.Errorf("old key opens a message sent after the removal: %v", err)
	}
	carol.app.handleDelivery(context.Background(), client.Delivery{From: [32]byte(alice.id), Payload: envelope, QueueID: 999})
	if texts := carol.groupTexts(); len(texts) != 0 {
		t.Errorf("removed member read %q", texts)
	}
	got := settle(t, alice, bob, carol)
	wantTexts(t, "alice", got[alice], "bob after")
	wantTexts(t, "bob", got[bob], "after")
	wantTexts(t, "carol", got[carol])

	s, err := alice.app.ownSender(context.Background(), mustGroupID(t, gid))
	if err != nil || s == nil || s.Generation() != 2 {
		t.Fatalf("alice's sender after removal: %v, %v", s, err)
	}
	s.Destroy()
}

func mustGroupID(t *testing.T, gid string) group.ID {
	t.Helper()
	id, err := parseGroupKey(gid)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestGroupLeave(t *testing.T) {
	_, alice, bob, carol, gid := newGroupOfThree(t)
	bob.sendGroup(gid, "hi")
	settle(t, alice, bob, carol)
	if err := alice.change(gid, tui.GroupLeave, nil); err == nil {
		t.Fatal("the last admin could leave")
	}
	if err := carol.change(gid, tui.GroupLeave, nil); err != nil {
		t.Fatal(err)
	}
	settle(t, alice, bob, carol)
	if !carol.groupInfo(gid).Left || len(headerCandidatesOf(t, carol, bob)) != 0 {
		t.Fatal("carol did not leave cleanly")
	}
	bob.sendGroup(gid, "bye carol")
	got := settle(t, alice, bob, carol)
	wantTexts(t, "alice", got[alice], "bye carol")
	wantTexts(t, "carol", got[carol])
	s, err := bob.app.ownSender(context.Background(), mustGroupID(t, gid))
	if err != nil || s.Generation() != 2 {
		t.Fatalf("bob did not rotate after carol left: %v", err)
	}
	s.Destroy()
}

func TestGroupAddMemberReadsOnlyNewMessages(t *testing.T) {
	r, alice, bob, carol, gid := newGroupOfThree(t)
	dave := newFakeUser(t, r, "Dave")
	befriend(alice, dave)
	alice.sendGroup(gid, "old news")
	bob.sendGroup(gid, "old bob")
	settle(t, alice, bob, carol)
	oldEnvelope := lastEnvelopeFor(t, r, alice, carol)

	if err := alice.change(gid, tui.GroupAdd, dave); err != nil {
		t.Fatal(err)
	}
	settle(t, alice, bob, carol, dave)
	g := dave.groupInfo(gid)
	if len(g.Members) != 4 || g.Invite || g.Name != "Book club" {
		t.Fatalf("dave sees %+v", g)
	}
	dave.app.handleDelivery(context.Background(), client.Delivery{From: [32]byte(alice.id), Payload: oldEnvelope, QueueID: 1000})
	if texts := dave.groupTexts(); len(texts) != 0 {
		t.Errorf("new member read old message %q", texts)
	}

	alice.sendGroup(gid, "welcome dave")
	bob.sendGroup(gid, "hi dave")
	dave.sendGroup(gid, "hello everyone")
	got := settle(t, alice, bob, carol, dave)
	wantTexts(t, "dave", got[dave], "welcome dave", "hi dave")
	wantTexts(t, "carol", got[carol], "welcome dave", "hi dave", "hello everyone")
	wantTexts(t, "dave's history", dave.groupHistory(gid), "hello everyone", "welcome dave", "hi dave")
}

// lastEnvelopeFor returns a copy of the latest group envelope from sender
// the relay delivered to to (already taken by settle, so it is re-sent).
func lastEnvelopeFor(t *testing.T, r *fakeRelay, sender, to *fakeUser) []byte {
	t.Helper()
	sender.sendGroup(sender.groupIDs()[0], "probe")
	q := r.take(to.id)
	for i := len(q) - 1; i >= 0; i-- {
		if senderkey.IsGroupEnvelope(q[i].Payload) {
			for _, d := range q {
				to.app.handleDelivery(context.Background(), d)
			}
			to.drainEvents()
			return q[i].Payload
		}
	}
	t.Fatal("no envelope")
	return nil
}

func (u *fakeUser) groupIDs() []string {
	list, err := u.app.Groups()
	if err != nil {
		u.t.Fatal(err)
	}
	var ids []string
	for _, g := range list {
		ids = append(ids, g.ID)
	}
	return ids
}

func TestGroupInvitationFromStranger(t *testing.T) {
	r := newGroupRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	gid := alice.createGroup("Strangers", bob)
	settle(t, alice, bob)
	if g := bob.groupInfo(gid); !g.Invite {
		t.Fatal("a group from a non-contact is not an invitation")
	}
	if _, err := bob.app.Send(context.Background(), gid, "hi"); !errors.Is(err, ErrInvitation) {
		t.Fatalf("send to an invitation: %v", err)
	}
	alice.sendGroup(gid, "you can read this")
	got := settle(t, alice, bob)
	wantTexts(t, "bob", got[bob], "you can read this")
	if err := bob.change(gid, tui.GroupAccept, nil); err != nil {
		t.Fatal(err)
	}
	bob.sendGroup(gid, "accepted")
	got = settle(t, alice, bob)
	wantTexts(t, "alice", got[alice], "accepted")
}

func TestGroupForgedAndStaleControlsRejected(t *testing.T) {
	_, alice, bob, carol, gid := newGroupOfThree(t)
	id := mustGroupID(t, gid)
	cur, _, err := bob.app.loadGroup(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	fake := cur.state
	fake.Epoch = 2
	fake.Admins, fake.AdminSince = nil, nil
	for _, id := range []identity.ID{alice.id, bob.id} {
		since := uint64(1)
		if id == bob.id {
			since = 2
		}
		i, _ := slices.BinarySearchFunc(fake.Admins, id, func(x, y identity.ID) int { return slices.Compare(x[:], y[:]) })
		fake.Admins = slices.Insert(fake.Admins, i, id)
		fake.AdminSince = slices.Insert(fake.AdminSince, i, since)
	}
	raw, err := group.NewControl(bob.prof.Identity, fake, group.OpRemove, carol.id, "")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := marshalControlMessage(controlMessage{Control: raw})
	if reason := bob.app.sendPairwise(context.Background(), alice.id, e2e.KindGroupControl, body); reason != "" {
		t.Fatal(reason)
	}
	settle(t, alice, bob, carol)
	if g := alice.groupInfo(gid); !slices.Contains(memberIDs(g), carol.cid()) {
		t.Fatal("non-admin control was applied")
	}
	alice.app.groupMu.Lock()
	waiting := len(alice.app.pending)
	alice.app.groupMu.Unlock()
	if waiting != 1 {
		t.Fatalf("%d controls wait, want the forged one", waiting)
	}
	alice.relay.clock.Advance(pendingMaxAge + time.Minute)
	before := alice.dropped()
	bob.sendGroup(gid, "trigger")
	settle(t, alice, bob, carol)
	if alice.dropped() != before+1 || len(alice.app.pending) != 0 {
		t.Errorf("forged control not dropped after waiting (dropped %d -> %d)", before, alice.dropped())
	}

	stale, _ := marshalControlMessage(controlMessage{Control: cur.history[0]})
	if reason := alice.app.sendPairwise(context.Background(), bob.id, e2e.KindGroupControl, stale); reason != "" {
		t.Fatal(reason)
	}
	forwarded, _ := marshalControlMessage(controlMessage{Control: cur.history[0]})
	if reason := carol.app.sendPairwise(context.Background(), bob.id, e2e.KindGroupControl, forwarded); reason != "" {
		t.Fatal(reason)
	}
	before = bob.dropped()
	settle(t, alice, bob, carol)
	if bob.dropped() != before+2 {
		t.Errorf("replayed and forwarded creates not dropped (dropped %d -> %d)", before, bob.dropped())
	}
	if _, err := bob.app.ChangeGroup(context.Background(), gid, tui.GroupChange{Op: tui.GroupRename, Name: "Mine"}); err == nil {
		t.Error("non-admin rename accepted locally")
	}
}

func TestGroupMessageBeforeSenderKey(t *testing.T) {
	r, alice, bob, carol, gid := newGroupOfThree(t)
	bob.sendGroup(gid, "early bird")
	queue := r.take(carol.id)
	var pairwise, envelopes []client.Delivery
	for _, d := range queue {
		if senderkey.IsGroupEnvelope(d.Payload) {
			envelopes = append(envelopes, d)
		} else {
			pairwise = append(pairwise, d)
		}
	}
	if len(envelopes) != 1 || len(pairwise) == 0 {
		t.Fatalf("carol's queue: %d envelopes, %d pairwise", len(envelopes), len(pairwise))
	}
	carol.app.handleDelivery(context.Background(), envelopes[0])
	if texts := carol.groupTexts(); len(texts) != 0 {
		t.Fatalf("decrypted without the sender key: %q", texts)
	}
	if slices.Contains(r.acksOf(carol.id), envelopes[0].QueueID) {
		t.Fatal("waiting message was acknowledged")
	}
	for _, d := range pairwise {
		carol.app.handleDelivery(context.Background(), d)
	}
	wantTexts(t, "carol", carol.groupTexts(), "early bird")
	if !slices.Contains(r.acksOf(carol.id), envelopes[0].QueueID) {
		t.Fatal("message not acknowledged once read")
	}
	settle(t, alice, bob, carol)
}

func TestGroupSenderKeyBeforeRestartAndRedelivery(t *testing.T) {
	r, alice, bob, carol, gid := newGroupOfThree(t)
	bob.sendGroup(gid, "first")
	queue := r.take(carol.id)
	var envelope client.Delivery
	for _, d := range queue {
		if senderkey.IsGroupEnvelope(d.Payload) {
			envelope = d
		}
	}
	carol.app.handleDelivery(context.Background(), envelope)
	carol.restart()
	for _, d := range queue {
		if d.QueueID != envelope.QueueID {
			carol.app.handleDelivery(context.Background(), d)
		}
	}
	if texts := carol.groupTexts(); len(texts) != 0 {
		t.Fatalf("pending message survived a restart in memory: %q", texts)
	}
	carol.app.handleDelivery(context.Background(), envelope)
	wantTexts(t, "carol", carol.groupTexts(), "first")
	settle(t, alice, bob, carol)
}

func TestGroupPersistsAcrossRestart(t *testing.T) {
	_, alice, bob, carol, gid := newGroupOfThree(t)
	alice.sendGroup(gid, "one")
	bob.sendGroup(gid, "two")
	settle(t, alice, bob, carol)
	bob.restart()
	alice.restart()
	if g := bob.groupInfo(gid); g.Name != "Book club" || len(g.Members) != 3 {
		t.Fatalf("after restart bob sees %+v", g)
	}
	wantTexts(t, "bob's history", bob.groupHistory(gid), "two", "one")
	alice.sendGroup(gid, "three")
	bob.sendGroup(gid, "four")
	got := settle(t, alice, bob, carol)
	wantTexts(t, "carol", got[carol], "three", "four")
	wantTexts(t, "alice", got[alice], "four")
	s, err := bob.app.ownSender(context.Background(), mustGroupID(t, gid))
	if err != nil || s.Generation() != 1 || s.Iteration() != 2 {
		t.Fatalf("bob's sender after restart: gen %d it %d, %v", s.Generation(), s.Iteration(), err)
	}
	s.Destroy()
	if _, ok := any(bob.prof.DB).(groupStatusUpdater); !ok {
		return
	}
	hist, _ := bob.app.History(gid, 10)
	for _, m := range hist {
		if m.Outgoing && m.Status != tui.StatusSent {
			t.Errorf("stored outgoing group message %q has status %v", m.Text, m.Status)
		}
	}
}

func TestGroupWireRoundTrip(t *testing.T) {
	_, alice, _, _, gid := newGroupOfThree(t)
	e, found, err := alice.app.loadGroup(context.Background(), mustGroupID(t, gid))
	if err != nil || !found {
		t.Fatal(err)
	}
	blob, err := marshalGroupEntry(e)
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseGroupEntry(blob, false)
	if err != nil || back.state.Hash() != e.state.Hash() || len(back.history) != 1 || back.ownGeneration != 1 {
		t.Fatalf("round trip: %+v, %v", back, err)
	}
	if _, err := parseGroupEntry(append(blob, 0), false); err == nil {
		t.Error("trailing byte accepted")
	}
	if _, err := parseControlMessage([]byte{0xa0}); err == nil {
		t.Error("empty control message accepted")
	}
	chunks := historyChunks([][]byte{make([]byte, 600), make([]byte, 600), make([]byte, 100)}, 1000)
	if len(chunks) != 2 || len(chunks[0]) != 1 || len(chunks[1]) != 2 {
		t.Errorf("chunks %d", len(chunks))
	}
	if _, err := parseGroupKey(gid[:len(gid)-1]); err == nil {
		t.Error("short group ID accepted")
	}
}

func TestGroupConcurrentChangesConverge(t *testing.T) {
	_, alice, bob, carol, gid := newGroupOfThree(t)
	if err := alice.change(gid, tui.GroupPromote, bob); err != nil {
		t.Fatal(err)
	}
	settle(t, alice, bob, carol)
	if _, err := alice.app.ChangeGroup(context.Background(), gid, tui.GroupChange{Op: tui.GroupRename, Name: "Alpha"}); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.app.ChangeGroup(context.Background(), gid, tui.GroupChange{Op: tui.GroupRename, Name: "Beta"}); err != nil {
		t.Fatal(err)
	}
	settle(t, alice, bob, carol)
	id := mustGroupID(t, gid)
	var hashes [][32]byte
	for _, u := range []*fakeUser{alice, bob, carol} {
		e, _, err := u.app.loadGroup(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, e.state.Hash())
	}
	if hashes[0] != hashes[1] || hashes[1] != hashes[2] {
		t.Fatalf("members diverged after a conflict: %x", hashes)
	}
	alice.sendGroup(gid, "same page")
	got := settle(t, alice, bob, carol)
	wantTexts(t, "carol", got[carol], "same page")
}

func TestGroupOutOfSyncIsFlagged(t *testing.T) {
	r, alice, bob, carol, gid := newGroupOfThree(t)
	if _, err := alice.app.ChangeGroup(context.Background(), gid, tui.GroupChange{Op: tui.GroupRename, Name: "Renamed"}); err != nil {
		t.Fatal(err)
	}
	r.take(carol.id)
	settle(t, alice, bob)
	bob.sendGroup(gid, "from the new state")
	for _, d := range r.take(carol.id) {
		carol.app.handleDelivery(context.Background(), d)
	}
	var flagged bool
	for _, ev := range carol.drainEvents() {
		if in, ok := ev.(tui.IncomingMessage); ok && in.GroupID == gid {
			flagged = in.OutOfSync
		}
	}
	if !flagged || !carol.groupInfo(gid).OutOfSync {
		t.Fatal("message from a diverging group state not flagged")
	}
	alice.sendGroup(gid, "hello")
	got := settle(t, alice, bob)
	wantTexts(t, "bob", got[bob], "hello")
	if bob.groupInfo(gid).OutOfSync {
		t.Error("in-sync message flagged")
	}
}

// expectGroupText waits for a group message with the given text.
func expectGroupText(t *testing.T, u *user, gid, text string) {
	t.Helper()
	for {
		in := expectEvent[tui.IncomingMessage](t, u)
		if in.GroupID == gid && in.Message.Text == text {
			return
		}
	}
}

func TestRelayGroup(t *testing.T) {
	r := startRelay(t)
	alice, bob, carol := newUser(t, r, "Alice"), newUser(t, r, "Bob"), newUser(t, r, "Carol")
	users := []*user{alice, bob, carol}
	for _, u := range users {
		for _, v := range users {
			if u != v {
				addContact(t, u, v.id(), v.name)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), eventTimeout)
	defer cancel()
	info, err := alice.app.CreateGroup(ctx, "Relay club", []string{bob.id(), carol.id()})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []*user{bob, carol} {
		waitFor(t, u.name+" joining", func() bool {
			list, err := u.app.Groups()
			return err == nil && len(list) == 1 && list[0].ID == info.ID && len(list[0].Members) == 3
		})
	}
	if m := send(t, alice, info.ID, "hello relay"); m.Status != tui.StatusSent {
		t.Fatalf("group send: %v %s", m.Status, m.Error)
	}
	expectGroupText(t, bob, info.ID, "hello relay")
	expectGroupText(t, carol, info.ID, "hello relay")
	send(t, bob, info.ID, "bob here")
	expectGroupText(t, alice, info.ID, "bob here")
	expectGroupText(t, carol, info.ID, "bob here")

	if _, err := alice.app.ChangeGroup(ctx, info.ID, tui.GroupChange{Op: tui.GroupRemove, Member: carol.id()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "carol's removal", func() bool {
		list, err := carol.app.Groups()
		return err == nil && len(list) == 1 && list[0].Left
	})
	waitFor(t, "bob seeing the removal", func() bool {
		list, err := bob.app.Groups()
		return err == nil && len(list) == 1 && len(list[0].Members) == 2
	})
	send(t, alice, info.ID, "without carol")
	expectGroupText(t, bob, info.ID, "without carol")
	if n := carol.droppedCount(); n != 0 {
		t.Errorf("carol dropped %d deliveries", n)
	}
}
