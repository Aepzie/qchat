package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

// searchBackend is a fakeBackend that searches its canned history.
type searchBackend struct {
	*fakeBackend
	queries []string
	err     error
	extra   []SearchHit
}

func (s *searchBackend) Search(_ context.Context, query, convID string, limit int) ([]SearchHit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, query+"|"+convID)
	if s.err != nil {
		return nil, s.err
	}
	var hits []SearchHit
	for id, msgs := range s.history {
		if convID != "" && id != convID {
			continue
		}
		for _, mi := range msgs {
			if strings.Contains(strings.ToLower(mi.Text), strings.ToLower(query)) {
				hits = append(hits, SearchHit{ConversationID: id, MessageID: mi.ID, Outgoing: mi.Outgoing, From: mi.From, Text: mi.Text, At: mi.Sent})
			}
		}
	}
	hits = append(hits, s.extra...)
	return hits[:min(len(hits), limit)], nil
}

func newSearchBackend() *searchBackend {
	fb := newFakeBackend()
	fb.history[bobID] = []MessageInfo{
		{ID: "b1", Text: "the KEYS are under the mat", Sent: testClock.Add(-2 * time.Hour)},
	}
	return &searchBackend{fakeBackend: fb}
}

func TestSearchCurrentConversation(t *testing.T) {
	sb := newSearchBackend()
	m := newChatModel(t, sb, 100, 30)
	m = do(t, m, keyCtrlN)
	m = say(t, m, "/search alice")
	if m.overlay.kind != overlaySearch {
		t.Fatalf("no search overlay:\n%s", screen(m))
	}
	if strings.Join(sb.queries, ",") != "alice|"+aliceID {
		t.Errorf("queries %v", sb.queries)
	}
	s := screen(m)
	for _, want := range []string{"Search “alice”", "in Alice", "2 messages", "hi, it's Alice", "hello Alice", "7 Nov 2026"} {
		if !strings.Contains(s, want) {
			t.Errorf("search overlay lacks %q:\n%s", want, s)
		}
	}
	if !strings.Contains(m.View().Content, m.st.match.Render("Alice")) {
		t.Error("the match is not highlighted")
	}
	checkFits(t, m)
	t.Logf("search 100x30:\n%s", s)
	m = do(t, m, keyEsc)
	if m.overlay.kind != overlayNone {
		t.Fatal("esc did not close the search")
	}
}

func TestSearchAllAndJump(t *testing.T) {
	sb := newSearchBackend()
	m := newChatModel(t, sb, 100, 30)
	m = say(t, m, "/search all keys")
	if strings.Join(sb.queries, ",") != "keys|" {
		t.Errorf("queries %v", sb.queries)
	}
	s := screen(m)
	if !strings.Contains(s, "in all conversations") || !strings.Contains(s, "Bob") || !strings.Contains(s, "the KEYS are under the mat") {
		t.Fatalf("search all:\n%s", s)
	}
	m = do(t, m, keyEnter)
	if m.overlay.kind != overlayNone || m.open != bobID {
		t.Fatalf("enter did not open Bob: open=%q", m.open)
	}
	if !strings.Contains(screen(m), "the KEYS are under the mat") {
		t.Errorf("Bob's history not shown:\n%s", screen(m))
	}
}

func TestSearchErrorsAndUsage(t *testing.T) {
	sb := newSearchBackend()
	m := newChatModel(t, sb, 100, 30)
	m = say(t, m, "/search keys")
	if m.overlay.kind != overlayNone || !strings.Contains(screen(m), "Open a contact or group to search it") {
		t.Errorf("search in System:\n%s", screen(m))
	}
	m = say(t, m, "/search all   ")
	if !strings.Contains(screen(m), "usage: /search") {
		t.Errorf("empty query:\n%s", screen(m))
	}
	m = say(t, m, "/search all nothing-matches-this")
	if !strings.Contains(screen(m), "No stored message contains") {
		t.Errorf("no results:\n%s", screen(m))
	}
	m = do(t, m, keyEsc)

	sb.err = errors.New("database locked")
	m = say(t, m, "/search all x")
	if !strings.Contains(screen(m), "Search failed: database locked") {
		t.Errorf("error not shown:\n%s", screen(m))
	}
	m = do(t, m, keyEsc)

	plain := newChatModel(t, newFakeBackend(), 100, 30)
	plain = say(t, plain, "/search all x")
	if !strings.Contains(screen(plain), "Search is not available") {
		t.Errorf("search without SearchBackend:\n%s", screen(plain))
	}
}

func TestSearchIgnoresStaleResults(t *testing.T) {
	sb := newSearchBackend()
	m := newChatModel(t, sb, 100, 30)
	m, first := updateCmd(t, typeText(t, m, "/search all keys"), keyEnter)
	m, second := updateCmd(t, typeText(t, update(t, m, keyEsc), "/search all alice"), keyEnter)
	m = update(t, m, second())
	m = update(t, m, first())
	if m.overlay.query != "alice" || len(m.overlay.hits) != 2 {
		t.Errorf("stale result shown: query %q, %d hits", m.overlay.query, len(m.overlay.hits))
	}
}

func TestSearchResultsAreSanitisedAndFit(t *testing.T) {
	sb := newSearchBackend()
	sb.extra = []SearchHit{
		{ConversationID: "\x1b]8;;http://evil\x07" + carolID, Text: "evil \x1b[2J\u202e keys \x1b]8;;http://evil\x07link", At: testClock},
		{ConversationID: aliceID, Text: strings.Repeat("前", 300) + " keys " + strings.Repeat("後", 300), At: testClock},
	}
	for i := 0; i < 30; i++ {
		sb.extra = append(sb.extra, SearchHit{ConversationID: bobID, Text: "keys number " + strings.Repeat("x", i), At: testClock})
	}
	for _, size := range [][2]int{{40, 10}, {55, 14}, {80, 24}, {133, 40}} {
		m := newChatModel(t, sb, size[0], size[1])
		m = say(t, m, "/search all keys")
		checkFits(t, m)
		content := m.View().Content
		for _, bad := range []string{"\x1b]8;", "\x1b[2J", "\u202e"} {
			if strings.Contains(content, bad) {
				t.Errorf("%v: view contains %q", size, bad)
			}
		}
		for i := 0; i < 40; i++ {
			m = update(t, m, press(tea.KeyDown, "", 0))
			checkFits(t, m)
		}
		if !strings.Contains(screen(m), "keys number "+strings.Repeat("x", 29)[:min(29, size[0]/4)]) {
			t.Errorf("%v: the last result is not scrolled into view:\n%s", size, screen(m))
		}
		m = update(t, m, press(tea.KeyHome, "", 0))
		checkFits(t, m)
	}
}

func TestSnippetKeepsMatchVisible(t *testing.T) {
	m := newChatModel(t, newFakeBackend(), 80, 24)
	text := strings.Repeat("lorem ipsum ", 30) + "NEEDLE" + strings.Repeat(" dolor", 30)
	for _, width := range []int{12, 20, 40, 70} {
		s := m.snippet(text, "needle", width)
		if !strings.Contains(stripANSI(s), "NEEDLE") && width >= 12 {
			t.Errorf("width %d: match not visible: %q", width, stripANSI(s))
		}
		if w := len([]rune(stripANSI(s))); w > width {
			t.Errorf("width %d: snippet is %d wide", width, w)
		}
	}
	if s := stripANSI(m.snippet("no match here", "zzz", 40)); s != "no match here" {
		t.Errorf("snippet without match: %q", s)
	}
}

func TestHelpOverlayListsEveryCommand(t *testing.T) {
	m := newChatModel(t, newFakeBackend(), 120, 200)
	m = say(t, m, "/help")
	if m.overlay.kind != overlayHelp {
		t.Fatal("/help did not open the overlay")
	}
	s := screen(m)
	for _, c := range commands {
		if c.name == "/group" {
			continue
		}
		if !strings.Contains(s, c.name) {
			t.Errorf("help lacks %s", c.name)
		}
	}
	for _, c := range groupCommands {
		if !strings.Contains(s, c.name) {
			t.Errorf("help lacks %s", c.name)
		}
	}
	for _, title := range []string{"Conversations", "Contacts", "Groups", "Appearance", "Connection", "General", "Keys", "Marks", "Privacy", "typing indicators"} {
		if !strings.Contains(s, title) {
			t.Errorf("help lacks %q", title)
		}
	}
	checkFits(t, m)
}

func TestHelpOverlayScrollsOnSmallTerminals(t *testing.T) {
	for _, size := range [][2]int{{40, 10}, {45, 12}, {70, 20}, {100, 30}} {
		m := newChatModel(t, newFakeBackend(), size[0], size[1])
		m = say(t, m, "/help")
		checkFits(t, m)
		if !strings.Contains(screen(m), "↓ more") {
			t.Errorf("%v: no scroll hint:\n%s", size, screen(m))
		}
		m = update(t, m, press('G', "G", 0))
		checkFits(t, m)
		if !strings.Contains(screen(m), "typing indicators") || strings.Contains(screen(m), "↓ more") {
			t.Errorf("%v: G does not reach the end:\n%s", size, screen(m))
		}
		for i := 0; i < 5; i++ {
			m = update(t, m, press('k', "k", 0))
		}
		checkFits(t, m)
		m = update(t, m, press('q', "q", 0))
		if m.overlay.kind != overlayNone {
			t.Errorf("%v: q did not close help", size)
		}
	}
}
