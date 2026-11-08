package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Aepzie/qchat/internal/client"
)

func altKey(r rune) tea.KeyPressMsg { return press(r, "", tea.ModAlt) }

func normalKey(t *testing.T, m Model, key string) Model {
	t.Helper()
	if m.Mode() != ModeNormal {
		m = do(t, m, keyEsc)
	}
	for _, r := range key {
		m = do(t, m, press(r, string(r), 0))
	}
	return m
}

func withRequest(t *testing.T, m Model, c byte, text string) Model {
	t.Helper()
	return do(t, m, chatEventMsg{IncomingMessage{ContactID: testID(c), UnknownSender: true,
		Message: MessageInfo{ID: string(c) + "1", Text: text, Received: testClock}}})
}

func TestTabSwitchingByKeys(t *testing.T) {
	m := newChatModel(t, newFakeBackend(), 120, 30)
	if m.tab != tabChats {
		t.Fatalf("starts in tab %v", m.tab)
	}
	for i := tabCount - 1; ; i-- {
		m = do(t, m, altKey(rune('1'+i)))
		if m.tab != i {
			t.Fatalf("alt+%d gave tab %v", i+1, m.tab)
		}
		if m.Mode() != ModeInsert {
			t.Fatal("alt+digit left insert mode")
		}
		if i == 0 {
			break
		}
	}
	m = normalKey(t, m, "4")
	if m.tab != tabContacts {
		t.Fatalf("4 gave %v", m.tab)
	}
	m = normalKey(t, m, "]")
	if m.tab != tabFiles {
		t.Fatalf("] gave %v", m.tab)
	}
	m = normalKey(t, m, "[[")
	if m.tab != tabGroups {
		t.Fatalf("[[ gave %v", m.tab)
	}
	m = do(t, m, press(tea.KeyRight, "", tea.ModCtrl))
	if m.tab != tabContacts {
		t.Fatalf("ctrl+right gave %v", m.tab)
	}
	m = do(t, m, press(tea.KeyLeft, "", tea.ModCtrl))
	m = do(t, m, press(tea.KeyLeft, "", tea.ModCtrl))
	m = do(t, m, press(tea.KeyLeft, "", tea.ModCtrl))
	if m.tab != tabChats {
		t.Fatalf("ctrl+left cycling gave %v", m.tab)
	}
	m = do(t, m, press(tea.KeyLeft, "", tea.ModCtrl))
	if m.tab != tabSystem || m.open != systemKey {
		t.Fatalf("ctrl+left did not wrap to System: %v %q", m.tab, m.open)
	}
	m = do(t, m, keyEsc)
	m = do(t, m, press('i', "i", 0))
	m = typeText(t, m, "12")
	if m.tab != tabSystem || m.input.Value() != "12" {
		t.Fatalf("digits in insert mode switched tabs: %v %q", m.tab, m.input.Value())
	}
}

func TestTabSwitchingByMouse(t *testing.T) {
	for _, w := range []int{40, 70, 100, 160} {
		m := newChatModel(t, newFakeBackend(), w, 24)
		_, spans := m.renderTabBar(m.width)
		for i := tabCount - 1; ; i-- {
			s := spans[i]
			if s[1] <= s[0] {
				t.Fatalf("width %d: tab %v has no cells", w, i)
			}
			m = do(t, m, tea.MouseClickMsg{X: (s[0] + s[1]) / 2, Y: 0, Button: tea.MouseLeft})
			if m.tab != i {
				t.Fatalf("width %d: click on %v gave %v", w, i, m.tab)
			}
			if i == 0 {
				break
			}
		}
		m = do(t, m, tea.MouseClickMsg{X: spans[tabFiles][0], Y: 5, Button: tea.MouseLeft})
		if m.tab != tabChats {
			t.Fatalf("width %d: click below the bar switched tabs", w)
		}
	}
}

func TestBadgesAndBanner(t *testing.T) {
	fb := newFakeBackend()
	fb.contacts = append(fb.contacts, ContactInfo{ID: carolID, DisplayName: "Carol", KeyChanged: true})
	m := newChatModel(t, fb, 140, 30)
	if got := m.tabBadge(tabChats); got != "●2" {
		t.Errorf("Chats badge %q", got)
	}
	if got := m.tabBadge(tabContacts); got != "⚠1" {
		t.Errorf("Contacts badge %q", got)
	}
	if m.tabBadge(tabRequests) != "" || strings.Contains(screen(m), "new message request") {
		t.Error("request badge or banner without requests")
	}
	m = withRequest(t, m, 'y', "hi")
	m = withRequest(t, m, 'z', "hello")
	m = withRequest(t, m, 'z', "again")
	if got := m.tabBadge(tabRequests); got != "✦2" {
		t.Errorf("Requests badge %q", got)
	}
	if !strings.Contains(screen(m), "✦ 2 new message requests — press 2") {
		t.Errorf("banner missing:\n%s", screen(m))
	}
	m = do(t, m, altKey('2'))
	if len(m.unseen) != 0 {
		t.Error("visiting Requests did not mark them seen")
	}
	m = do(t, m, altKey('1'))
	if strings.Contains(screen(m), "new message request") {
		t.Error("banner shown after the requests were seen")
	}
	if got := m.tabBadge(tabRequests); got != "✦2" {
		t.Errorf("Requests badge after seen %q", got)
	}
	checkFits(t, m)
}

func TestRequestAcceptFlow(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 120, 30)
	stranger := testID('z')
	m = withRequest(t, m, 'z', "hello from a stranger")
	m = do(t, m, altKey('2'))
	s := screen(m)
	for _, want := range []string{"qc1-zzzz-zzzz", "hello from a stranger", "a accept"} {
		if !strings.Contains(s, want) {
			t.Errorf("request card lacks %q:\n%s", want, s)
		}
	}
	m = normalKey(t, m, "a")
	if m.prompt.kind != promptAcceptName || m.Mode() != ModeInsert || !strings.Contains(screen(m), "name for qc1-zzzz-zzzz") {
		t.Fatalf("a did not ask for a name:\n%s", screen(m))
	}
	m = say(t, m, "Zed \x1b[31m")
	if len(fb.added) != 1 || !strings.HasPrefix(fb.added[0], stranger) {
		t.Fatalf("AddContact not called: %v", fb.added)
	}
	if m.open != stranger || m.conv(requestsKey) != nil || m.tab != tabChats {
		t.Fatalf("after accept: open %q tab %v", m.open, m.tab)
	}
	if !strings.Contains(screen(m), "hello from a stranger") {
		t.Errorf("request messages not moved:\n%s", screen(m))
	}
}

func TestRequestPromptCancel(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 120, 30)
	m = withRequest(t, m, 'z', "hi")
	m = do(t, m, altKey('2'))
	m = normalKey(t, m, "a")
	m = typeText(t, m, "Zed")
	m = do(t, m, keyEsc)
	if m.prompt.kind != promptNone || len(fb.added) != 0 || m.input.Value() != "" {
		t.Fatalf("esc did not cancel: prompt %v added %v", m.prompt.kind, fb.added)
	}
}

func TestRequestDismiss(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 120, 30)
	m = withRequest(t, m, 'y', "first")
	m = withRequest(t, m, 'z', "second")
	m = do(t, m, altKey('2'))
	m = normalKey(t, m, "d")
	cards := m.requestCards()
	if len(cards) != 1 || cards[0].key != testID('z') {
		t.Fatalf("dismiss left %v", cards)
	}
	if strings.Contains(screen(m), "first") {
		t.Errorf("dismissed request still shown:\n%s", screen(m))
	}
	m = normalKey(t, m, "d")
	if m.conv(requestsKey) != nil || len(m.requestCards()) != 0 || len(fb.added) != 0 {
		t.Fatal("dismissing the last request did not remove the requests")
	}
	checkFits(t, m)
}

func TestInvitationAcceptAndDecline(t *testing.T) {
	fb := newFakeBackend()
	inv := testGroupID('e')
	fb.groups = append(fb.groups, GroupInfo{ID: inv, Name: "Evil \x1b]0;x\x07club", Invite: true,
		Members: []GroupMember{{ID: selfID, Self: true}, {ID: carolID}}})
	m := newChatModel(t, fb, 120, 30)
	if !m.unseen[inv] || m.tabBadge(tabRequests) != "✦1" {
		t.Fatalf("invitation not counted: %v %q", m.unseen, m.tabBadge(tabRequests))
	}
	m = do(t, m, altKey('2'))
	s := m.View().Content
	if strings.Contains(s, "\x1b]0;") || strings.Contains(s, "\x07") {
		t.Fatal("hostile group name reached the screen")
	}
	if !strings.Contains(screen(m), "group invitation") {
		t.Errorf("invitation card missing:\n%s", screen(m))
	}
	m = normalKey(t, m, "a")
	if len(fb.changes) != 1 || fb.changes[0] != fmt.Sprintf("%s|%d||", inv, GroupAccept) {
		t.Fatalf("accept: %v", fb.changes)
	}
	m = do(t, m, altKey('2'))
	m = normalKey(t, m, "l")
	if len(fb.changes) != 2 || fb.changes[1] != fmt.Sprintf("%s|%d||", inv, GroupLeave) {
		t.Fatalf("decline: %v", fb.changes)
	}
}

func TestContactQuickActions(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 120, 40)
	m = do(t, m, altKey('4'))
	m = normalKey(t, m, "v")
	if m.overlay.kind != overlayVerify || m.overlay.contactID != aliceID {
		t.Fatalf("v: overlay %v for %q", m.overlay.kind, m.overlay.contactID)
	}
	m = do(t, m, keyEsc)
	m = normalKey(t, m, "Jr")
	if m.open != bobID || m.input.Value() != "/rename " {
		t.Fatalf("r: open %q input %q", m.open, m.input.Value())
	}
	m = do(t, m, keyEsc)
	m = do(t, m, keyEsc)
	m = do(t, m, altKey('4'))
	m = normalKey(t, m, "x")
	if !m.confirm.active {
		t.Fatal("x did not ask to confirm")
	}
	m = do(t, m, press('y', "y", 0))
	if len(fb.removed) != 1 {
		t.Fatalf("x then y did not remove: %v", fb.removed)
	}
}

func TestFilesTabSavePrompt(t *testing.T) {
	fb := newFakeFileBackend()
	m := newChatModel(t, fb, 120, 30)
	m = do(t, m, chatEventMsg{IncomingMessage{ContactID: aliceID, Message: MessageInfo{ID: "f9", Received: testClock,
		File: &FileInfo{Name: "plan.pdf", Size: 2048, State: FileComplete, Done: 1, Total: 1}}}})
	m = do(t, m, altKey('5'))
	if !strings.Contains(screen(m), "plan.pdf") || m.tabBadge(tabFiles) != "" {
		t.Fatalf("Files tab:\n%s", screen(m))
	}
	m = normalKey(t, m, "s")
	if m.prompt.kind != promptSaveDir {
		t.Fatal("s did not ask for a directory")
	}
	m = say(t, m, "")
	if len(fb.saved) != 1 {
		t.Fatalf("SaveFile not called: %v", fb.saved)
	}
	if m.tab != tabFiles {
		t.Errorf("saving left the Files tab: %v", m.tab)
	}
}

func TestSystemTabSummary(t *testing.T) {
	m := connected(t, newTestModel(t, 120, 30))
	m = update(t, m, altKey('6'))
	s := screen(m)
	for _, want := range []string{"● connected", "sealed off", "tor off", "server pin", "Connected to chat.example.org:8443."} {
		if !strings.Contains(s, want) {
			t.Errorf("System tab lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(strings.SplitN(s, "\n", 4)[3], "▌System") {
		t.Error("System still listed as a conversation")
	}
}

func newAnimModel(t *testing.T, width, height int) Model {
	t.Helper()
	m := New(Config{Addr: "a:1", Pin: testPin(), Now: func() time.Time { return testClock }})
	return update(t, m, tea.WindowSizeMsg{Width: width, Height: height})
}

func hasTick(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	switch msg := cmd().(type) {
	case animTickMsg:
		return true
	case tea.BatchMsg:
		for _, c := range msg {
			if hasTick(c) {
				return true
			}
		}
	}
	return false
}

func TestSplashSkipsOnKey(t *testing.T) {
	m := New(Config{Addr: "a:1", Pin: testPin()})
	m, cmd := updateCmd(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	if !m.splash || !m.ticking || cmd == nil {
		t.Fatalf("splash not started: splash=%v ticking=%v", m.splash, m.ticking)
	}
	if strings.Contains(screen(m), "INSERT") {
		t.Error("splash not drawn")
	}
	checkFits(t, m)
	m = update(t, m, press('x', "x", 0))
	if m.splash || m.input.Value() != "" {
		t.Fatalf("key did not skip the splash: splash=%v input=%q", m.splash, m.input.Value())
	}
	if !strings.Contains(screen(m), "INSERT") {
		t.Error("layout not shown after the splash")
	}
}

func TestSplashEndsAfterFrames(t *testing.T) {
	m := newAnimModel(t, 100, 30)
	for i := 0; i < SplashFrames; i++ {
		m = update(t, m, animTickMsg{})
	}
	if m.splash {
		t.Fatal("splash still shown after SplashFrames")
	}
	if m.ticking {
		t.Error("tick loop kept running while idle")
	}
}

func TestAnimationTickStartsAndStops(t *testing.T) {
	m := newAnimModel(t, 100, 30)
	m = update(t, m, press('x', "", 0))
	for m.ticking {
		m = update(t, m, animTickMsg{})
	}
	if _, cmd := updateCmd(t, m, press('y', "y", 0)); hasTick(cmd) {
		t.Fatal("idle model scheduled a tick")
	}
	m, cmd := updateCmd(t, m, event(client.StateChanged{State: client.Connecting, Attempt: 1}))
	if !m.ticking || cmd == nil {
		t.Fatal("connecting did not start the spinner")
	}
	frame := m.frame
	m, cmd = updateCmd(t, m, animTickMsg{})
	if m.frame != frame+1 || cmd == nil {
		t.Fatal("tick did not advance and continue")
	}
	m = connected(t, m)
	m, cmd = updateCmd(t, m, animTickMsg{})
	if m.ticking || cmd != nil {
		t.Fatal("tick loop did not stop once connected")
	}
	if _, cmd := updateCmd(t, m, press('z', "z", 0)); hasTick(cmd) {
		t.Fatal("second loop started while idle")
	}
}

func TestAnimationsOffAndSmallTerminals(t *testing.T) {
	small := newAnimModel(t, 59, 30)
	if small.ticking {
		t.Error("ticking on a 59-column terminal")
	}
	short := newAnimModel(t, 100, 19)
	if short.ticking {
		t.Error("ticking on a 19-row terminal")
	}
	sb := newSettingsBackend()
	m := New(Config{Addr: "a:1", Pin: testPin(), Backend: sb, Now: func() time.Time { return testClock }})
	m = update(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	m = update(t, m, press('x', "", 0))
	for m.ticking {
		m = update(t, m, animTickMsg{})
	}
	m, _ = submit(t, m, "/animations off")
	if !m.animOff {
		t.Fatal("/animations off not applied")
	}
	m, cmd := updateCmd(t, m, event(client.StateChanged{State: client.Connecting, Attempt: 1}))
	if m.ticking || hasTick(cmd) {
		t.Fatal("ticking with animations off")
	}
	if !strings.Contains(screen(m), "◌ connecting") {
		t.Error("static connecting indicator missing")
	}
	m, _ = submit(t, m, "/animations on")
	if m.animOff || !m.ticking {
		t.Fatal("/animations on did not resume the spinner")
	}
	stored := New(Config{Addr: "a:1", Pin: testPin(), Backend: sb})
	stored = update(t, stored, tea.WindowSizeMsg{Width: 100, Height: 30})
	sb.values[SettingAnimations] = "off"
	stored = update(t, stored, stored.loadSettings()())
	if !stored.animOff || stored.splash {
		t.Error("stored ui.animations=off not applied")
	}
}

func TestEveryTabFitsEverySize(t *testing.T) {
	fb := newFakeBackend()
	fb.contacts = append(fb.contacts, ContactInfo{ID: carolID, DisplayName: strings.Repeat("日本語", 20) + "\x1b[2J\u202e", KeyChanged: true, Unread: 1234})
	withBookClub(fb)
	for _, w := range []int{40, 41, 55, 59, 60, 69, 70, 71, 99, 133, 200} {
		for _, h := range []int{10, 11, 15, 16, 20, 24, 40} {
			m := newChatModel(t, fb, w, h)
			m = withRequest(t, m, 'z', strings.Repeat("long \x1b]8;;x\x07", 30))
			m = do(t, m, chatEventMsg{IncomingMessage{ContactID: aliceID, Message: MessageInfo{ID: "f1",
				File: &FileInfo{Name: strings.Repeat("報告", 30), Size: 1 << 20, State: FileReceiving, Done: 3, Total: 9}}}})
			for i := tab(0); i < tabCount; i++ {
				m = do(t, m, altKey(rune('1'+i)))
				checkFits(t, m)
				n := normalKey(t, m, "J")
				checkFits(t, n)
				if strings.Contains(n.View().Content, "\x1b[2J") || strings.Contains(n.View().Content, "\u202e") {
					t.Fatalf("%dx%d tab %v: hostile name reached the screen", w, h, i)
				}
				if got := len(strings.Split(n.View().Content, "\n")); got != h {
					t.Errorf("%dx%d tab %v: %d lines", w, h, i, got)
				}
			}
		}
	}
}
