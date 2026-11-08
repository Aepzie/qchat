package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testGroupID(c byte) string { return groupPrefix + strings.Repeat(string(c), 64) }

// withBookClub adds a group with the user, Alice and a stranger.
func withBookClub(fb *fakeBackend) string {
	id := testGroupID('a')
	fb.groups = append(fb.groups, GroupInfo{
		ID:   id,
		Name: "Book club",
		Members: []GroupMember{
			{ID: selfID, ShortID: "qc1-ssss-ssss", DisplayName: "Me", Admin: true, Self: true},
			{ID: aliceID, ShortID: "qc1-aaaa-aaaa", DisplayName: "Alice"},
			{ID: carolID, ShortID: "qc1-cccc-cccc"},
		},
		Unread: 1,
	})
	fb.history[id] = []MessageInfo{
		{ID: "g1", Text: "chapter one?", From: aliceID, Sent: testClock.Add(-time.Hour), Received: testClock.Add(-time.Hour)},
		{ID: "g2", Text: "yes", From: carolID, Sent: testClock.Add(-time.Minute), Received: testClock.Add(-time.Minute)},
	}
	return id
}

func openGroup(t *testing.T, m Model, id string) Model {
	t.Helper()
	m = drain(t, m, m.openConversation(id))
	if m.open != id {
		t.Fatalf("open = %q, want %q", m.open, id)
	}
	return m
}

func TestGroupSidebarAndHistory(t *testing.T) {
	fb := newFakeBackend()
	id := withBookClub(fb)
	m := newChatModel(t, fb, 110, 30)
	row := sidebarLine(t, m, "# Book club")
	if !strings.Contains(row, " 1 ") {
		t.Errorf("unread badge missing in %q", row)
	}
	s := screen(m)
	if strings.Index(s, "Bob") > strings.Index(s, "# Book club") {
		t.Error("groups are not listed after contacts")
	}
	m = openGroup(t, m, id)
	s = screen(m)
	for _, want := range []string{"Alice", "chapter one?", "qc1-cccc-cccc", "3 members", "relay sees recipients"} {
		if !strings.Contains(s, want) {
			t.Errorf("group view lacks %q:\n%s", want, s)
		}
	}
	if fb.read[len(fb.read)-1] != id {
		t.Errorf("group not marked read: %v", fb.read)
	}
	checkFits(t, m)

	m = say(t, m, "see you thursday")
	if got := fb.sent[len(fb.sent)-1]; got != id+"|see you thursday" {
		t.Errorf("sent %q", got)
	}
	checkFits(t, m)
}

func TestGroupIncomingMessageAndNotice(t *testing.T) {
	fb := newFakeBackend()
	id := withBookClub(fb)
	m := newChatModel(t, fb, 110, 30)
	m = do(t, m, chatEventMsg{event: IncomingMessage{ContactID: aliceID, GroupID: id,
		Message: MessageInfo{ID: "n1", Text: "new message", From: aliceID, Sent: testClock, Received: testClock}}})
	if c := m.conv(id); c.unread != 2 {
		t.Errorf("unread = %d, want 2", c.unread)
	}
	m = do(t, m, chatEventMsg{event: GroupChanged{GroupID: id, Notice: "Alice added Bob.\x1b[2J"}})
	m = openGroup(t, m, id)
	s := screen(m)
	for _, want := range []string{"new message", "Alice added Bob."} {
		if !strings.Contains(s, want) {
			t.Errorf("group view lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "\x1b[2J") {
		t.Error("notice was not sanitised")
	}
}

func TestGroupCreateCommand(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 110, 30)
	m = say(t, m, "/group create Book club "+bobID+" "+carolID+" "+bobID)
	if len(fb.created) != 1 || fb.created[0] != "Book club|"+bobID+","+carolID {
		t.Fatalf("created %q", fb.created)
	}
	if c := m.openConv(); c.kind != convGroup || c.group.Name != "Book club" {
		t.Fatalf("open conversation %+v", c)
	}
	if !strings.Contains(screen(m), "Created the group Book club.") {
		t.Errorf("no confirmation:\n%s", screen(m))
	}

	m = say(t, m, "/group create")
	if !strings.Contains(screen(m), "usage: /group create") {
		t.Error("missing usage for /group create without a name")
	}
	m = say(t, m, "/group create Oops qc1-notanid")
	if len(fb.created) != 1 {
		t.Errorf("created with an invalid ID: %q", fb.created)
	}
}

func TestGroupChangeCommands(t *testing.T) {
	fb := newFakeBackend()
	id := withBookClub(fb)
	m := newChatModel(t, fb, 110, 30)

	m = say(t, m, "/group remove Alice")
	if !strings.Contains(screen(m), "Open a group first") || len(fb.changes) != 0 {
		t.Fatalf("group command outside a group: %v", fb.changes)
	}
	m = openGroup(t, m, id)
	for _, c := range []struct {
		line string
		want string
	}{
		{"/group remove alice", fmt.Sprintf("%s|%d|%s|", id, GroupRemove, aliceID)},
		{"/group admin qc1-cccc-cccc", fmt.Sprintf("%s|%d|%s|", id, GroupPromote, carolID)},
		{"/group unadmin " + carolID, fmt.Sprintf("%s|%d|%s|", id, GroupDemote, carolID)},
		{"/group add " + bobID, fmt.Sprintf("%s|%d|%s|", id, GroupAdd, bobID)},
		{"/group rename Readers", fmt.Sprintf("%s|%d||Readers", id, GroupRename)},
		{"/group accept", fmt.Sprintf("%s|%d||", id, GroupAccept)},
		{"/group acc", fmt.Sprintf("%s|%d||", id, GroupAccept)},
	} {
		m = say(t, m, c.line)
		if got := fb.changes[len(fb.changes)-1]; got != c.want {
			t.Errorf("%s: change %q, want %q", c.line, got, c.want)
		}
	}
	if !strings.Contains(screen(m), "Readers") {
		t.Error("rename not reflected")
	}
	n := len(fb.changes)
	m = say(t, m, "/group remove nobody")
	if len(fb.changes) != n || !strings.Contains(screen(m), "No single member") {
		t.Error("unknown member was not rejected")
	}
}

func TestGroupMembersOverlay(t *testing.T) {
	fb := newFakeBackend()
	id := withBookClub(fb)
	m := newChatModel(t, fb, 110, 30)
	m = openGroup(t, m, id)
	m = say(t, m, "/group members")
	if m.overlay.kind != overlayMembers {
		t.Fatal("members overlay not open")
	}
	s := screen(m)
	for _, want := range []string{"# Book club", "3 members", "Me (you, admin)", "Alice", "qc1-cccc-cccc", "relay sees the recipients"} {
		if !strings.Contains(s, want) {
			t.Errorf("overlay lacks %q:\n%s", want, s)
		}
	}
	checkFits(t, m)
	m = do(t, m, keyEsc)
	if m.overlay.kind != overlayNone {
		t.Error("esc did not close the overlay")
	}
}

func TestGroupLeftAndInvitationAreReadOnly(t *testing.T) {
	fb := newFakeBackend()
	id := withBookClub(fb)
	fb.groups[0].Left = true
	invite := testGroupID('b')
	fb.groups = append(fb.groups, GroupInfo{ID: invite, Name: "Strangers", Invite: true,
		Members: []GroupMember{{ID: selfID, Self: true}, {ID: carolID, Admin: true}}})
	m := newChatModel(t, fb, 110, 30)
	m = openGroup(t, m, id)
	m = say(t, m, "hello?")
	if len(fb.sent) != 0 || !strings.Contains(screen(m), "no longer a member") {
		t.Errorf("sent to a left group: %v", fb.sent)
	}
	m = openGroup(t, m, invite)
	m = say(t, m, "hi")
	if len(fb.sent) != 0 || !strings.Contains(screen(m), "/group accept") {
		t.Errorf("sent to an invitation: %v", fb.sent)
	}
}

func TestGroupLeaveAsksFirst(t *testing.T) {
	fb := newFakeBackend()
	id := withBookClub(fb)
	m := newChatModel(t, fb, 110, 30)
	m = openGroup(t, m, id)

	m = say(t, m, "/group leave")
	if !m.confirm.active || len(fb.changes) != 0 {
		t.Fatalf("leave did not ask first: %v", fb.changes)
	}
	s := screen(m)
	for _, want := range []string{"Leave # Book club?", "y/N", "y leave"} {
		if !strings.Contains(s, want) {
			t.Errorf("confirmation lacks %q:\n%s", want, s)
		}
	}
	checkFits(t, m)
	m = do(t, m, press('n', "n", 0))
	if m.confirm.active || len(fb.changes) != 0 || !strings.Contains(screen(m), "You stay in the group.") {
		t.Fatalf("n did not keep the membership: %v", fb.changes)
	}

	m = say(t, m, "/group leave")
	m = do(t, m, press('y', "y", 0))
	if want := fmt.Sprintf("%s|%d||", id, GroupLeave); len(fb.changes) != 1 || fb.changes[0] != want {
		t.Fatalf("changes %v, want %q", fb.changes, want)
	}
	if !strings.Contains(screen(m), "You left the group.") {
		t.Errorf("no confirmation of leaving:\n%s", screen(m))
	}
}

func TestGroupOutOfSync(t *testing.T) {
	fb := newFakeBackend()
	id := withBookClub(fb)
	other := testGroupID('b')
	fb.groups = append(fb.groups, GroupInfo{ID: other, Name: "Synced", Members: []GroupMember{{ID: selfID, Self: true}, {ID: aliceID}}})
	fb.groups[0].OutOfSync = true
	m := newChatModel(t, fb, 110, 30)
	if row := sidebarLine(t, m, "# Book club"); !strings.Contains(row, "⚠") {
		t.Errorf("no out-of-sync marker in %q", row)
	}
	if row := sidebarLine(t, m, "# Synced"); strings.Contains(row, "⚠") {
		t.Errorf("synced group marked in %q", row)
	}
	m = openGroup(t, m, id)
	s := screen(m)
	if !strings.Contains(s, "Group out of sync") || !strings.Contains(s, "group state differs from this member") {
		t.Errorf("no out-of-sync banner:\n%s", s)
	}
	checkFits(t, m)

	m = openGroup(t, m, other)
	if strings.Contains(screen(m), "out of sync") {
		t.Error("banner shown for a synced group")
	}
	m = do(t, m, chatEventMsg{event: IncomingMessage{ContactID: aliceID, GroupID: other, OutOfSync: true,
		Message: MessageInfo{ID: "s1", Text: "from elsewhere", From: aliceID, Sent: testClock, Received: testClock}}})
	if !m.conv(other).group.OutOfSync || !strings.Contains(screen(m), "Group out of sync") {
		t.Errorf("out-of-sync message did not raise the banner:\n%s", screen(m))
	}

	fb.groups[0].Left = true
	m = do(t, m, chatEventMsg{event: GroupChanged{GroupID: id}})
	m = openGroup(t, m, id)
	if strings.Contains(screen(m), "Group out of sync") {
		t.Error("banner shown for a group the user left")
	}
}

func TestGroupHeaderShowsAdmin(t *testing.T) {
	fb := newFakeBackend()
	id := withBookClub(fb)
	m := openGroup(t, newChatModel(t, fb, 120, 30), id)
	if !strings.Contains(screen(m), "3 members · you are admin") {
		t.Errorf("header lacks the admin note:\n%s", screen(m))
	}
	fb.groups[0].Members[0].Admin = false
	m = do(t, m, chatEventMsg{event: GroupChanged{GroupID: id}})
	if s := screen(m); strings.Contains(s, "you are admin") || !strings.Contains(s, "3 members") {
		t.Errorf("header after demotion:\n%s", s)
	}
}

func TestGroupPaletteAndCompletion(t *testing.T) {
	fb := newFakeBackend()
	id := withBookClub(fb)
	m := openGroup(t, newChatModel(t, fb, 110, 30), id)

	m = typeText(t, m, "/group ")
	s := screen(m)
	for _, c := range groupCommands[:5] {
		if !strings.Contains(s, c.name) {
			t.Errorf("palette lacks %s:\n%s", c.name, s)
		}
	}
	checkFits(t, m)
	m = update(t, m, keyTab)
	if m.input.Value() != "/group create" {
		t.Fatalf("tab after /group: %q", m.input.Value())
	}
	m.input.Reset()
	m.resetPalette()

	m = typeText(t, m, "/group r")
	m = update(t, m, keyTab)
	if m.input.Value() != "/group remove" {
		t.Fatalf("first tab: %q", m.input.Value())
	}
	m = update(t, m, keyTab)
	if m.input.Value() != "/group rename" {
		t.Fatalf("second tab: %q", m.input.Value())
	}
	m.input.Reset()
	m.resetPalette()

	m = typeText(t, m, "/group mem")
	if strings.Contains(screen(m), "/group create") {
		t.Error("palette not filtered")
	}
	m = do(t, m, keyEnter)
	if m.overlay.kind != overlayMembers {
		t.Error("enter on a partial subcommand did not run it")
	}
	m = do(t, m, keyEsc)

	m = typeText(t, m, "/group remove al")
	if _, open := m.paletteMatches(); open {
		t.Error("palette open while typing an argument")
	}
}

func TestGroupErrorsShown(t *testing.T) {
	fb := newFakeBackend()
	id := withBookClub(fb)
	m := openGroup(t, newChatModel(t, fb, 110, 30), id)
	fb.groupErr = errors.New("only admins may rename")
	m = say(t, m, "/group rename Readers")
	if s := screen(m); !strings.Contains(s, "Group change failed") || !strings.Contains(s, "only admins may rename") {
		t.Errorf("error not shown:\n%s", s)
	}
	m = say(t, m, "/group create Second "+bobID)
	if !strings.Contains(screen(m), "Group change failed") {
		t.Errorf("create error not shown:\n%s", screen(m))
	}
	m = say(t, m, "/group frobnicate")
	if !strings.Contains(screen(m), "usage: /group create") {
		t.Errorf("unknown subcommand without usage:\n%s", screen(m))
	}
}

func TestGroupNamesSanitised(t *testing.T) {
	const evil = "\x1b]0;pwned\x07Ev\u202eil\x1b[2J\nname"
	fb := newFakeBackend()
	id := withBookClub(fb)
	fb.groups[0].Name = evil
	fb.groups[0].OutOfSync = true
	fb.groups[0].Members[1].DisplayName = evil
	m := newChatModel(t, fb, 110, 30)
	m = openGroup(t, m, id)
	m = do(t, m, chatEventMsg{event: IncomingMessage{ContactID: aliceID, GroupID: id,
		Message: MessageInfo{ID: "e1", Text: "hi", From: aliceID, Sent: testClock, Received: testClock}}})
	check := func() {
		t.Helper()
		for _, bad := range []string{"\x1b]", "\u202e", "\x1b[2J", "\x07"} {
			if strings.Contains(m.View().Content, bad) {
				t.Errorf("view contains %q", bad)
			}
		}
		checkFits(t, m)
	}
	check()
	m = say(t, m, "/group members")
	check()
	m = do(t, m, keyEsc)
	m = say(t, m, "/group leave")
	check()
}

func TestGroupViewsFitEverySize(t *testing.T) {
	fb := newFakeBackend()
	id := withBookClub(fb)
	fb.groups[0].OutOfSync = true
	fb.groups[0].Name = strings.Repeat("very long group name ", 6)
	for _, size := range [][2]int{{200, 50}, {110, 30}, {80, 24}, {60, 12}, {39, 30}, {39, 9}, {31, 5}, {20, 4}, {5, 2}, {1, 1}} {
		m := openGroup(t, newChatModel(t, fb, size[0], size[1]), id)
		checkFits(t, m)
		m = typeText(t, m, "/group ")
		checkFits(t, m)
		m.input.Reset()
		m.resetPalette()
		m = say(t, m, "/group leave")
		checkFits(t, m)
		m = do(t, m, press('n', "n", 0))
		m = say(t, m, "/group members")
		checkFits(t, m)
	}
}
