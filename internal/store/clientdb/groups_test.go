package clientdb

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleGroup(t *testing.T, joined time.Time) Group {
	t.Helper()
	return Group{ID: randomID(t), State: randomBytes(t, 300), Joined: joined}
}

func sampleGroupMessage(t *testing.T, group, sender [32]byte, body string) GroupMessage {
	t.Helper()
	now := time.Now()
	return GroupMessage{
		Group:    group,
		Sender:   sender,
		MsgID:    randomMsgID(t),
		Dir:      Incoming,
		Sent:     now.Add(-time.Second),
		Received: now,
		Body:     body,
		Status:   StatusReceived,
		Flags:    FlagClockSkew,
	}
}

func equalGroup(a, b Group) bool {
	return a.ID == b.ID && bytes.Equal(a.State, b.State) && a.Joined.Equal(b.Joined) && a.Left == b.Left
}

func equalGroupMessage(a, b GroupMessage) bool {
	return a.Group == b.Group && a.Sender == b.Sender && a.MsgID == b.MsgID && a.Dir == b.Dir &&
		a.Sent.Equal(b.Sent) && a.Received.Equal(b.Received) && a.Body == b.Body &&
		a.Status == b.Status && a.Flags == b.Flags
}

func TestGroupRoundTrip(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	base := time.Now()
	later := sampleGroup(t, base.Add(time.Hour))
	earlier := sampleGroup(t, base)

	for _, g := range []Group{later, earlier} {
		if err := d.PutGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := d.GetGroup(ctx, later.ID); err != nil || !equalGroup(got, later) {
		t.Fatalf("GetGroup = %+v, %v", got, err)
	}
	list, err := d.ListGroups(ctx)
	if err != nil || len(list) != 2 || !equalGroup(list[0], earlier) || !equalGroup(list[1], later) {
		t.Fatalf("ListGroups = %+v, %v", list, err)
	}

	later.State = []byte("new epoch")
	later.Left = true
	if err := d.PutGroup(ctx, later); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetGroup(ctx, later.ID); err != nil || !equalGroup(got, later) {
		t.Fatalf("GetGroup after update = %+v, %v", got, err)
	}
	if _, err := d.GetGroup(ctx, randomID(t)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGroup(unknown): %v", err)
	}
	if err := d.DeleteGroup(ctx, later.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteGroup(ctx, later.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second DeleteGroup: %v", err)
	}
	if list, err := d.ListGroups(ctx); err != nil || len(list) != 1 || list[0].ID != earlier.ID {
		t.Fatalf("ListGroups after delete = %+v, %v", list, err)
	}
}

func TestSenderKeyRoundTrip(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	group, other, alice, bob := randomID(t), randomID(t), randomID(t), randomID(t)
	own := randomBytes(t, 200)

	if _, err := d.GetOwnSenderKey(ctx, group); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetOwnSenderKey before put: %v", err)
	}
	if err := d.PutOwnSenderKey(ctx, group, own); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetOwnSenderKey(ctx, group); err != nil || !bytes.Equal(got, own) {
		t.Fatalf("GetOwnSenderKey = %x, %v", got, err)
	}
	if _, err := d.GetOwnSenderKey(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Fatalf("own key leaked to another group: %v", err)
	}

	states := map[[2]uint32][]byte{}
	put := func(g, member [32]byte, memberIndex, generation uint32) {
		t.Helper()
		state := randomBytes(t, 100)
		if err := d.PutMemberSenderKey(ctx, g, member, generation, state); err != nil {
			t.Fatal(err)
		}
		states[[2]uint32{memberIndex, generation}] = state
	}
	put(group, alice, 0, 1)
	put(group, alice, 0, 2)
	put(group, bob, 1, 1)
	put(other, alice, 2, 1)
	get := func(g, member [32]byte, generation uint32) ([]byte, error) {
		t.Helper()
		return d.GetMemberSenderKey(ctx, g, member, generation)
	}
	if got, err := get(group, alice, 2); err != nil || !bytes.Equal(got, states[[2]uint32{0, 2}]) {
		t.Fatalf("alice generation 2 = %x, %v", got, err)
	}
	if got, err := get(other, alice, 1); err != nil || !bytes.Equal(got, states[[2]uint32{2, 1}]) {
		t.Fatalf("alice in other group = %x, %v", got, err)
	}
	if _, err := get(group, alice, 3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown generation: %v", err)
	}

	replaced := []byte("advanced chain")
	if err := d.PutMemberSenderKey(ctx, group, alice, 1, replaced); err != nil {
		t.Fatal(err)
	}
	if got, err := get(group, alice, 1); err != nil || !bytes.Equal(got, replaced) {
		t.Fatalf("replaced state = %x, %v", got, err)
	}

	if err := d.DeleteMemberSenderKey(ctx, group, alice, 1); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteMemberSenderKey(ctx, group, alice, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second DeleteMemberSenderKey: %v", err)
	}
	if _, err := get(group, alice, 2); err != nil {
		t.Fatalf("deleting one generation removed another: %v", err)
	}

	if err := d.DeleteMemberSenderKeys(ctx, group, alice); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteMemberSenderKeys(ctx, group, alice); err != nil {
		t.Fatalf("deleting nothing: %v", err)
	}
	if _, err := get(group, alice, 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("alice's keys survive DeleteMemberSenderKeys: %v", err)
	}
	if _, err := get(group, bob, 1); err != nil {
		t.Fatalf("bob's key deleted with alice's: %v", err)
	}
	if _, err := get(other, alice, 1); err != nil {
		t.Fatalf("alice's key in another group deleted: %v", err)
	}

	if err := d.DeleteGroupSenderKeys(ctx, group); err != nil {
		t.Fatal(err)
	}
	if _, err := get(group, bob, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob's key survives DeleteGroupSenderKeys: %v", err)
	}
	if _, err := d.GetOwnSenderKey(ctx, group); !errors.Is(err, ErrNotFound) {
		t.Fatalf("own key survives DeleteGroupSenderKeys: %v", err)
	}
	if _, err := get(other, alice, 1); err != nil {
		t.Fatalf("other group's keys deleted: %v", err)
	}
	if err := d.DeleteGroupSenderKeys(ctx, group); err != nil {
		t.Fatalf("deleting nothing: %v", err)
	}
}

func TestUpdateGroupMessageStatus(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	group, self := randomID(t), randomID(t)
	m := sampleGroupMessage(t, group, self, "outgoing")
	m.Dir, m.Status, m.Flags = Outgoing, StatusSent, 0
	if err := d.AppendGroupMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateGroupMessageStatus(ctx, group, self, m.MsgID, StatusDelivered); err != nil {
		t.Fatalf("UpdateGroupMessageStatus: %v", err)
	}
	got, err := d.GroupMessages(ctx, group, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Status != StatusDelivered || got[0].Body != "outgoing" {
		t.Fatalf("after update: %+v", got)
	}
	if err := d.UpdateGroupMessageStatus(ctx, group, self, randomMsgID(t), StatusDelivered); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown message: err = %v, want ErrNotFound", err)
	}
	if err := d.UpdateGroupMessageStatus(ctx, randomID(t), self, m.MsgID, StatusDelivered); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other group: err = %v, want ErrNotFound", err)
	}
	if err := d.UpdateGroupMessageStatus(ctx, group, self, m.MsgID, 200); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad status: err = %v, want ErrInvalid", err)
	}
}

func TestGroupMessages(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	group, other, alice := randomID(t), randomID(t), randomID(t)
	contact := sampleContact(t, "Peer")
	if err := d.PutContact(ctx, contact); err != nil {
		t.Fatal(err)
	}

	var sent []GroupMessage
	for i := range 5 {
		m := sampleGroupMessage(t, group, alice, "group message "+string(rune('a'+i)))
		if err := d.AppendGroupMessage(ctx, m); err != nil {
			t.Fatal(err)
		}
		sent = append(sent, m)
		if i == 2 {
			if err := d.AppendMessage(ctx, sampleMessage(t, contact.ID, "1:1 in between")); err != nil {
				t.Fatal(err)
			}
			if err := d.AppendGroupMessage(ctx, sampleGroupMessage(t, other, alice, "other group")); err != nil {
				t.Fatal(err)
			}
		}
	}

	latest, err := d.GroupMessages(ctx, group, 3, 0)
	if err != nil || len(latest) != 3 {
		t.Fatalf("GroupMessages = %d, %v", len(latest), err)
	}
	for i, m := range latest {
		if !equalGroupMessage(m, sent[2+i]) {
			t.Fatalf("message %d = %+v, want %+v", i, m, sent[2+i])
		}
	}
	older, err := d.GroupMessages(ctx, group, 10, latest[0].Seq)
	if err != nil || len(older) != 2 || !equalGroupMessage(older[0], sent[0]) || !equalGroupMessage(older[1], sent[1]) {
		t.Fatalf("older page = %+v, %v", older, err)
	}
	if msgs, err := d.Messages(ctx, contact.ID, 10, 0); err != nil || len(msgs) != 1 {
		t.Fatalf("1:1 conversation sees group messages: %d, %v", len(msgs), err)
	}
	if msgs, err := d.GroupMessages(ctx, contact.ID, 10, 0); err != nil || len(msgs) != 0 {
		t.Fatalf("group conversation sees 1:1 messages: %d, %v", len(msgs), err)
	}

	if err := d.AppendGroupMessage(ctx, sent[0]); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	sameIDOtherSender := sent[0]
	sameIDOtherSender.Sender = randomID(t)
	if err := d.AppendGroupMessage(ctx, sameIDOtherSender); err != nil {
		t.Fatalf("same MsgID from another sender: %v", err)
	}
	if ok, err := d.HasGroupMessage(ctx, group, alice, sent[1].MsgID); err != nil || !ok {
		t.Fatalf("HasGroupMessage = %v, %v", ok, err)
	}
	if ok, err := d.HasGroupMessage(ctx, other, alice, sent[1].MsgID); err != nil || ok {
		t.Fatalf("HasGroupMessage(other group) = %v, %v", ok, err)
	}

	if err := d.PutGroup(ctx, Group{ID: group, State: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if err := d.PutOwnSenderKey(ctx, group, []byte{2}); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if msgs, err := d.GroupMessages(ctx, group, 10, 0); err != nil || len(msgs) != 0 {
		t.Fatalf("messages after DeleteGroup = %d, %v", len(msgs), err)
	}
	if _, err := d.GetOwnSenderKey(ctx, group); !errors.Is(err, ErrNotFound) {
		t.Fatalf("own sender key after DeleteGroup: %v", err)
	}
	if err := d.AppendGroupMessage(ctx, sent[3]); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay after DeleteGroup: %v", err)
	}
	if msgs, err := d.GroupMessages(ctx, other, 10, 0); err != nil || len(msgs) != 1 {
		t.Fatalf("other group's messages after DeleteGroup = %d, %v", len(msgs), err)
	}
	if msgs, err := d.Messages(ctx, contact.ID, 10, 0); err != nil || len(msgs) != 1 {
		t.Fatalf("1:1 messages after DeleteGroup = %d, %v", len(msgs), err)
	}
}

func TestCommitGroupReceive(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	group, alice := randomID(t), randomID(t)
	first := []byte("receiver state 1")
	if err := d.PutMemberSenderKey(ctx, group, alice, 4, first); err != nil {
		t.Fatal(err)
	}
	m := sampleGroupMessage(t, group, alice, "hello group")
	next := []byte("receiver state 2")
	if err := d.CommitGroupReceive(ctx, group, alice, 4, next, m); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetMemberSenderKey(ctx, group, alice, 4); err != nil || !bytes.Equal(got, next) {
		t.Fatalf("state after commit = %q, %v", got, err)
	}
	if msgs, err := d.GroupMessages(ctx, group, 10, 0); err != nil || len(msgs) != 1 || !equalGroupMessage(msgs[0], m) {
		t.Fatalf("messages after commit = %+v, %v", msgs, err)
	}

	if err := d.CommitGroupReceive(ctx, group, alice, 4, []byte("replayed state"), m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replayed commit: %v", err)
	}
	if got, _ := d.GetMemberSenderKey(ctx, group, alice, 4); !bytes.Equal(got, next) {
		t.Fatalf("duplicate commit changed the state to %q", got)
	}

	fresh := sampleGroupMessage(t, group, alice, "new generation")
	if err := d.CommitGroupReceive(ctx, group, alice, 5, []byte("gen 5"), fresh); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetMemberSenderKey(ctx, group, alice, 5); err != nil || string(got) != "gen 5" {
		t.Fatalf("new generation state = %q, %v", got, err)
	}
	if got, err := d.GetMemberSenderKey(ctx, group, alice, 4); err != nil || !bytes.Equal(got, next) {
		t.Fatalf("old generation touched: %q, %v", got, err)
	}

	bad := sampleGroupMessage(t, group, alice, "x")
	outgoing := bad
	outgoing.Dir = Outgoing
	outgoing.Status = StatusSent
	invalid := bad
	invalid.Status = 0
	tests := []struct {
		name   string
		group  [32]byte
		member [32]byte
		state  []byte
		m      GroupMessage
	}{
		{"Outgoing", group, alice, []byte{1}, outgoing},
		{"WrongGroup", randomID(t), alice, []byte{1}, bad},
		{"WrongSender", group, randomID(t), []byte{1}, bad},
		{"EmptyState", group, alice, nil, bad},
		{"HugeState", group, alice, make([]byte, MaxSenderKeyStateSize+1), bad},
		{"InvalidMessage", group, alice, []byte{1}, invalid},
	}
	for _, tc := range tests {
		if err := d.CommitGroupReceive(ctx, tc.group, tc.member, 9, tc.state, tc.m); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", tc.name, err)
		}
	}
	if ok, _ := d.HasGroupMessage(ctx, group, alice, bad.MsgID); ok {
		t.Fatal("rejected commit stored its message")
	}
	if _, err := d.GetMemberSenderKey(ctx, group, alice, 9); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected commit stored its state: %v", err)
	}
}

// TestCommitGroupReceiveIsAtomic makes the state write fail after the
// message was appended and checks that the message is rolled back.
func TestCommitGroupReceiveIsAtomic(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	group, alice := randomID(t), randomID(t)
	if _, err := d.conn.Exec(`CREATE TRIGGER fail_sender_keys BEFORE INSERT ON sender_keys BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	m := sampleGroupMessage(t, group, alice, "must not persist")
	if err := d.CommitGroupReceive(ctx, group, alice, 1, []byte("state"), m); err == nil {
		t.Fatal("commit succeeded despite failing state write")
	}
	if ok, err := d.HasGroupMessage(ctx, group, alice, m.MsgID); err != nil || ok {
		t.Fatalf("message survived a failed commit: %v, %v", ok, err)
	}
	if msgs, err := d.GroupMessages(ctx, group, 10, 0); err != nil || len(msgs) != 0 {
		t.Fatalf("messages after failed commit = %d, %v", len(msgs), err)
	}
	if _, err := d.conn.Exec(`DROP TRIGGER fail_sender_keys`); err != nil {
		t.Fatal(err)
	}
	if err := d.CommitGroupReceive(ctx, group, alice, 1, []byte("state"), m); err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
}

func TestCommitGroupSend(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	group, self := randomID(t), randomID(t)
	m := sampleGroupMessage(t, group, self, "outgoing")
	m.Dir = Outgoing
	m.Status = StatusSent
	if err := d.CommitGroupSend(ctx, []byte("own state 1"), m); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetOwnSenderKey(ctx, group); err != nil || string(got) != "own state 1" {
		t.Fatalf("own state = %q, %v", got, err)
	}
	if err := d.CommitGroupSend(ctx, []byte("own state 2"), m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate send: %v", err)
	}
	if got, _ := d.GetOwnSenderKey(ctx, group); string(got) != "own state 1" {
		t.Fatalf("duplicate send changed own state to %q", got)
	}
	incoming := sampleGroupMessage(t, group, self, "in")
	if err := d.CommitGroupSend(ctx, []byte{1}, incoming); !errors.Is(err, ErrInvalid) {
		t.Fatalf("incoming message: %v", err)
	}
}

func TestGroupValidation(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	id := randomID(t)
	for name, err := range map[string]error{
		"EmptyGroupState":   d.PutGroup(ctx, Group{ID: id}),
		"HugeGroupState":    d.PutGroup(ctx, Group{ID: id, State: make([]byte, MaxGroupStateSize+1)}),
		"BadJoined":         d.PutGroup(ctx, Group{ID: id, State: []byte{1}, Joined: time.Unix(-1, 0)}),
		"EmptyOwnState":     d.PutOwnSenderKey(ctx, id, nil),
		"HugeOwnState":      d.PutOwnSenderKey(ctx, id, make([]byte, MaxSenderKeyStateSize+1)),
		"EmptyMemberState":  d.PutMemberSenderKey(ctx, id, id, 1, []byte{}),
		"BadDirection":      d.AppendGroupMessage(ctx, GroupMessage{Group: id, Status: StatusSent}),
		"BadBody":           d.AppendGroupMessage(ctx, GroupMessage{Group: id, Dir: Incoming, Status: StatusReceived, Body: "\xff"}),
		"ZeroLimit":         func() error { _, err := d.GroupMessages(ctx, id, 0, 0); return err }(),
		"NegativeCursor":    func() error { _, err := d.GroupMessages(ctx, id, 1, -1); return err }(),
		"OversizedBodySize": d.AppendGroupMessage(ctx, GroupMessage{Group: id, Dir: Incoming, Status: StatusReceived, Body: string(make([]byte, MaxBodySize+1))}),
	} {
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestGroupRowSwapDetected(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	a, b := sampleGroup(t, time.Now()), sampleGroup(t, time.Now())
	for _, g := range []Group{a, b} {
		if err := d.PutGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.conn.Exec(`UPDATE chat_groups SET value = (SELECT value FROM chat_groups WHERE lookup = ?) WHERE lookup = ?`,
		d.keys.groupLookup(a.ID), d.keys.groupLookup(b.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetGroup(ctx, b.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("swapped group row: %v, want ErrCorrupt", err)
	}

	group, alice := randomID(t), randomID(t)
	if err := d.PutMemberSenderKey(ctx, group, alice, 1, []byte("gen 1")); err != nil {
		t.Fatal(err)
	}
	if err := d.PutMemberSenderKey(ctx, group, alice, 2, []byte("gen 2")); err != nil {
		t.Fatal(err)
	}
	if err := d.PutOwnSenderKey(ctx, group, []byte("own")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.Exec(`UPDATE sender_keys SET value = (SELECT value FROM sender_keys WHERE lookup = ?) WHERE lookup = ?`,
		d.keys.memberSenderKeyLookup(group, alice, 1), d.keys.memberSenderKeyLookup(group, alice, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetMemberSenderKey(ctx, group, alice, 2); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("swapped sender key row: %v, want ErrCorrupt", err)
	}
	if _, err := d.conn.Exec(`UPDATE sender_keys SET value = (SELECT value FROM sender_keys WHERE lookup = ?) WHERE lookup = ?`,
		d.keys.memberSenderKeyLookup(group, alice, 1), d.keys.ownSenderKeyLookup(group)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetOwnSenderKey(ctx, group); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("member row copied into own row: %v, want ErrCorrupt", err)
	}

	contact := sampleContact(t, "Peer")
	gm := sampleGroupMessage(t, contact.ID, contact.ID, "group row")
	if err := d.AppendGroupMessage(ctx, gm); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.Exec(`UPDATE messages SET peer = ? WHERE lookup = ?`,
		d.keys.contactLookup(contact.ID), d.keys.groupMessageLookup(gm.Group, gm.Sender, gm.MsgID)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Messages(ctx, contact.ID, 10, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("group row read as a 1:1 message: %v, want ErrCorrupt", err)
	}
}

func TestNoGroupPlaintextInFile(t *testing.T) {
	ctx := context.Background()
	d, path, _ := openTemp(t)
	name := []byte("UNIQUE-GROUP-NAME-Quokka-Society")
	g := Group{ID: randomID(t), State: append(append([]byte("state:"), name...), randomBytes(t, 64)...), Joined: time.Now()}
	member := randomID(t)
	own := randomBytes(t, 96)
	receiver := randomBytes(t, 96)
	m := sampleGroupMessage(t, g.ID, member, "the group meets at the old mill")
	if err := d.PutGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := d.PutOwnSenderKey(ctx, g.ID, own); err != nil {
		t.Fatal(err)
	}
	if err := d.CommitGroupReceive(ctx, g.ID, member, 7, receiver, m); err != nil {
		t.Fatal(err)
	}

	needles := map[string][]byte{
		"group ID":        g.ID[:],
		"group name":      name,
		"member ID":       member[:],
		"message ID":      m.MsgID[:],
		"body":            []byte(m.Body),
		"own sender key":  own,
		"receiver state":  receiver,
		"group state end": g.State[len(g.State)-32:],
	}
	scan := func(stage string) {
		t.Helper()
		for what, needle := range needles {
			if found := filesContain(t, path, needle); len(found) > 0 {
				t.Errorf("%s: %s found in plaintext in %v", stage, what, found)
			}
		}
	}
	scan("open")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	scan("closed")
}

func sealedSenderKeyRow(t *testing.T, d *DB, lookup []byte) []byte {
	t.Helper()
	var sealed []byte
	if err := d.conn.QueryRow(`SELECT value FROM sender_keys WHERE lookup = ?`, lookup).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	return sealed
}

// TestDeletedSenderKeysLeaveNoTrace checks that every way of deleting
// sender key states checkpoints the WAL, so neither the sealed rows nor
// their nonces remain in the files.
func TestDeletedSenderKeysLeaveNoTrace(t *testing.T) {
	ctx := context.Background()
	d, path, _ := openTemp(t)
	group, gone, alice, bob := randomID(t), randomID(t), randomID(t), randomID(t)
	if err := d.PutContact(ctx, sampleContact(t, "Filler")); err != nil {
		t.Fatal(err)
	}
	type row struct {
		what   string
		lookup []byte
	}
	var rows []row
	putMember := func(what string, g, member [32]byte, generation uint32) {
		if err := d.PutMemberSenderKey(ctx, g, member, generation, randomBytes(t, 128)); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row{what, d.keys.memberSenderKeyLookup(g, member, generation)})
	}
	putMember("single generation", group, alice, 1)
	putMember("member generation", group, bob, 1)
	putMember("member generation 2", group, bob, 2)
	putMember("group member", gone, alice, 1)
	if err := d.PutOwnSenderKey(ctx, gone, randomBytes(t, 128)); err != nil {
		t.Fatal(err)
	}
	rows = append(rows, row{"own key of deleted group", d.keys.ownSenderKeyLookup(gone)})
	if err := d.PutGroup(ctx, Group{ID: gone, State: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	sealed := make(map[string][]byte)
	for _, r := range rows {
		sealed[r.what] = sealedSenderKeyRow(t, d, r.lookup)
	}
	if len(filesContain(t, path, sealed["single generation"])) == 0 {
		t.Fatal("stored ciphertext not found in the files; the scan would prove nothing")
	}

	if err := d.DeleteMemberSenderKey(ctx, group, alice, 1); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteMemberSenderKeys(ctx, group, bob); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteGroup(ctx, gone); err != nil {
		t.Fatal(err)
	}
	for what, value := range sealed {
		for part, needle := range map[string][]byte{"row": value, "nonce": value[:24], "ciphertext": value[24:]} {
			if found := filesContain(t, path, needle); len(found) > 0 {
				t.Errorf("%s %s still present in %v after delete", what, part, found)
			}
		}
	}
	if info, err := os.Stat(path + "-wal"); err == nil && info.Size() != 0 {
		t.Errorf("-wal file is %d bytes after checkpoint, want 0", info.Size())
	}
}

func TestMigrationFromV4(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "qchat.db")
	key := randomKey(t)

	all := migrations
	migrations = all[:4]
	v4, err := Open(path, key)
	migrations = all
	if err != nil {
		t.Fatal(err)
	}
	c := sampleContact(t, "Old Friend")
	m := sampleMessage(t, c.ID, "from schema 4")
	if err := v4.PutContact(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := v4.AppendMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	var tables int
	if err := v4.conn.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('chat_groups', 'sender_keys')`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("v4 database has %d group tables, %v", tables, err)
	}
	if err := v4.Close(); err != nil {
		t.Fatal(err)
	}

	d, err := OpenExisting(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var version int
	if err := d.conn.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != len(migrations) || len(migrations) < 5 {
		t.Fatalf("schema version = %d, %v; want %d", version, err, len(migrations))
	}
	if got, err := d.GetContact(ctx, c.ID); err != nil || !equalContact(got, c) {
		t.Fatalf("contact after migration = %+v, %v", got, err)
	}
	old, err := d.Messages(ctx, c.ID, 10, 0)
	if err != nil || len(old) != 1 || !equalMessage(old[0], m) {
		t.Fatalf("messages after migration = %+v, %v", old, err)
	}
	if err := d.AppendMessage(ctx, m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay after migration: %v", err)
	}
	g := sampleGroup(t, time.Now())
	if err := d.PutGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	gm := sampleGroupMessage(t, g.ID, c.ID, "first group message")
	if err := d.CommitGroupReceive(ctx, g.ID, c.ID, 1, []byte("state"), gm); err != nil {
		t.Fatal(err)
	}
	if msgs, err := d.GroupMessages(ctx, g.ID, 10, 0); err != nil || len(msgs) != 1 || msgs[0].Seq <= old[0].Seq {
		t.Fatalf("group messages after migration = %+v, %v", msgs, err)
	}
}
