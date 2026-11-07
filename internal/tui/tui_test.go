package tui

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/transport"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;:?<>=]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)

func stripANSI(s string) string { return ansiPattern.ReplaceAllString(s, "") }

func testPin() transport.Fingerprint {
	var fp transport.Fingerprint
	for i := range fp {
		fp[i] = byte(0x10 + i*7)
	}
	return fp
}

func newTestModel(t *testing.T, width, height int) Model {
	t.Helper()
	clock := time.Date(2026, 11, 7, 14, 2, 11, 0, time.UTC)
	m := New(Config{
		Addr:    "chat.example.org:8443",
		Pin:     testPin(),
		Version: "0.1.0",
		Now:     func() time.Time { return clock },
	})
	return update(t, m, tea.WindowSizeMsg{Width: width, Height: height})
}

func update(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	next, _ := m.Update(msg)
	nm, ok := next.(Model)
	if !ok {
		t.Fatalf("Update returned %T", next)
	}
	return nm
}

func updateCmd(t *testing.T, m Model, msg tea.Msg) (Model, tea.Cmd) {
	t.Helper()
	next, cmd := m.Update(msg)
	return next.(Model), cmd
}

func event(ev client.Event) tea.Msg { return sessionEventMsg{event: ev} }

func press(code rune, text string, mod tea.KeyMod) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: code, Text: text, Mod: mod}
}

var (
	keyEnter = press(tea.KeyEnter, "", 0)
	keyEsc   = press(tea.KeyEscape, "", 0)
	keyTab   = press(tea.KeyTab, "", 0)
	keyCtrlC = press('c', "", tea.ModCtrl)
)

func typeText(t *testing.T, m Model, s string) Model {
	t.Helper()
	for _, r := range s {
		m = update(t, m, press(r, string(r), 0))
	}
	return m
}

func submit(t *testing.T, m Model, s string) (Model, tea.Cmd) {
	t.Helper()
	m = typeText(t, m, s)
	return updateCmd(t, m, keyEnter)
}

func screen(m Model) string { return stripANSI(m.View().Content) }

// checkFits asserts that the view is exactly the terminal height and that
// no line is wider than the terminal.
func checkFits(t *testing.T, m Model) {
	t.Helper()
	content := m.View().Content
	lines := strings.Split(content, "\n")
	if len(lines) > m.height {
		t.Errorf("%dx%d: view has %d lines", m.width, m.height, len(lines))
	}
	for i, line := range lines {
		if w := lipgloss.Width(line); w > m.width {
			t.Errorf("%dx%d: line %d is %d cells wide: %q", m.width, m.height, i, w, stripANSI(line))
		}
	}
}

func connected(t *testing.T, m Model) Model {
	t.Helper()
	m = update(t, m, event(client.StateChanged{State: client.Connecting, Attempt: 1}))
	m = update(t, m, event(client.StateChanged{State: client.Connected, Info: client.ConnectionInfo{
		Addr: "chat.example.org:8443", Fingerprint: testPin(), ProtocolVersion: protocol.Version,
		PingInterval: 15 * time.Second, MaxFrameSize: protocol.MaxFrameSize,
		Transport: client.TransportDescription, ConnectedAt: time.Date(2026, 11, 7, 14, 2, 0, 0, time.UTC),
	}}))
	return update(t, m, event(client.RTT{Duration: 23 * time.Millisecond}))
}

func TestViewIsAltScreenWithMouse(t *testing.T) {
	v := newTestModel(t, 80, 24).View()
	if !v.AltScreen || v.MouseMode != tea.MouseModeCellMotion {
		t.Fatalf("AltScreen=%v MouseMode=%v", v.AltScreen, v.MouseMode)
	}
}

func TestTooSmall(t *testing.T) {
	for _, size := range [][2]int{{39, 30}, {100, 9}, {39, 9}, {31, 5}, {20, 4}, {5, 2}, {1, 1}} {
		m := newTestModel(t, size[0], size[1])
		got := strings.Join(strings.Fields(screen(m)), " ")
		want := "Terminal too small (need 40×10)"
		switch {
		case size[0] < 20 || size[1] < 4:
			want = ""
		case size[0] < 31:
			want = "Terminal too"
		}
		if !strings.Contains(got, want) {
			t.Errorf("%v: view %q lacks %q", size, got, want)
		}
		checkFits(t, m)
	}
	m := newTestModel(t, 40, 10)
	if strings.Contains(screen(m), "too small") {
		t.Error("40x10 reported as too small")
	}
	m = update(t, m, tea.WindowSizeMsg{Width: 30, Height: 10})
	if !strings.Contains(screen(m), "too small") {
		t.Error("resize to 30x10 not reported as too small")
	}
	m = update(t, m, tea.WindowSizeMsg{Width: 90, Height: 25})
	if strings.Contains(screen(m), "too small") || !strings.Contains(screen(m), "qchat") {
		t.Error("resize back did not restore the layout")
	}
}

func TestStatusBarConnectionStates(t *testing.T) {
	m := newTestModel(t, 120, 30)
	top := func() string { return strings.SplitN(screen(m), "\n", 2)[0] }

	if !strings.Contains(top(), "E2E: off") {
		t.Errorf("E2E badge missing: %q", top())
	}
	m = update(t, m, event(client.StateChanged{State: client.Connecting, Attempt: 1}))
	if !strings.Contains(top(), "◌ connecting") || strings.Contains(top(), "TLS 1.3") {
		t.Errorf("connecting status: %q", top())
	}

	m = connected(t, m)
	s := top()
	for _, want := range []string{"qchat", "● connected", "🔒 TLS 1.3 · PQ-hybrid", "pin " + shortFingerprint(testPin()), "Tor: off", "23 ms", "E2E: off"} {
		if !strings.Contains(s, want) {
			t.Errorf("status bar %q lacks %q", s, want)
		}
	}
	if m.State() != client.Connected {
		t.Errorf("State() = %v", m.State())
	}
	if !strings.HasSuffix(strings.TrimRight(s, " "), "E2E: off") {
		t.Errorf("E2E badge not right-aligned: %q", s)
	}

	m = update(t, m, event(client.StateChanged{State: client.Disconnected, Err: client.ErrKeepaliveTimeout, RetryIn: 4 * time.Second}))
	if !strings.Contains(top(), "✕ disconnected") || strings.Contains(top(), "23 ms") {
		t.Errorf("disconnected status: %q", top())
	}
	if !strings.Contains(screen(m), "Connection lost: the server stopped responding. Retrying in 4s.") {
		t.Errorf("disconnect not logged:\n%s", screen(m))
	}
}

func TestStatusBarDropsSegmentsWhenNarrow(t *testing.T) {
	m := connected(t, newTestModel(t, 40, 12))
	top := strings.SplitN(screen(m), "\n", 2)[0]
	for _, want := range []string{"qchat", "● connected", "E2E: off"} {
		if !strings.Contains(top, want) {
			t.Errorf("narrow status bar %q lacks %q", top, want)
		}
	}
	checkFits(t, m)
}

func TestSidebarVisibility(t *testing.T) {
	wide := newTestModel(t, 70, 20)
	s := screen(wide)
	for _, want := range []string{"CONVERSATIONS", "System", "No identity", "messaging is off"} {
		if !strings.Contains(s, want) {
			t.Errorf("sidebar at width 70 lacks %q", want)
		}
	}
	narrow := newTestModel(t, 69, 20)
	if strings.Contains(screen(narrow), "CONVERSATIONS") {
		t.Error("sidebar shown at width 69")
	}
}

func TestUnreadCounter(t *testing.T) {
	m := newTestModel(t, 100, 20)
	m.convs[0].unread = 3
	if !strings.Contains(screen(m), "System") || !strings.Contains(screen(m), " 3 ") {
		t.Errorf("unread counter not rendered:\n%s", screen(m))
	}
	checkFits(t, m)
}

func TestModeSwitching(t *testing.T) {
	m := newTestModel(t, 80, 20)
	if m.Mode() != ModeInsert || !strings.Contains(screen(m), "INSERT") {
		t.Fatal("does not start in insert mode")
	}
	m = update(t, m, keyEsc)
	if m.Mode() != ModeNormal || !strings.Contains(screen(m), "NORMAL") {
		t.Fatal("esc did not enter normal mode")
	}
	m = typeText(t, m, "x")
	if m.input.Value() != "" {
		t.Errorf("normal mode typed into the input: %q", m.input.Value())
	}
	m = typeText(t, m, "i")
	if m.Mode() != ModeInsert {
		t.Fatal("i did not enter insert mode")
	}
	m = typeText(t, m, "q")
	if m.Quitting() || m.input.Value() != "q" {
		t.Fatalf("q in insert mode: quitting=%v value=%q", m.Quitting(), m.input.Value())
	}
	m = update(t, m, keyEsc)
	m = typeText(t, m, ":")
	if m.Mode() != ModeInsert || m.input.Value() != "/" {
		t.Fatalf(": gave mode %v, input %q", m.Mode(), m.input.Value())
	}
	m = update(t, m, keyEsc)
	m, cmd := updateCmd(t, m, press('q', "q", 0))
	if !m.Quitting() || cmd == nil {
		t.Fatal("q in normal mode did not quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("q did not return tea.Quit")
	}
}

func TestCtrlCQuitsInBothModes(t *testing.T) {
	for _, normal := range []bool{false, true} {
		m := newTestModel(t, 80, 20)
		if normal {
			m = update(t, m, keyEsc)
		}
		m, cmd := updateCmd(t, m, keyCtrlC)
		if !m.Quitting() || cmd == nil {
			t.Fatalf("normal=%v: ctrl+c did not quit", normal)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Fatalf("normal=%v: ctrl+c did not return tea.Quit", normal)
		}
	}
}

func TestNormalModeScrolling(t *testing.T) {
	m := newTestModel(t, 80, 20)
	for i := 0; i < 40; i++ {
		m, _ = submit(t, m, fmt.Sprintf("note %d", i))
	}
	if !m.history.AtBottom() {
		t.Fatal("history not at bottom after notes")
	}
	m = update(t, m, keyEsc)
	m = typeText(t, m, "g")
	if !m.history.AtTop() {
		t.Fatal("g did not go to the top")
	}
	if !strings.Contains(screen(m), "newer below") {
		t.Error("scroll hint missing when scrolled up")
	}
	m = typeText(t, m, "j")
	if m.history.YOffset() != 1 {
		t.Fatalf("j: offset %d, want 1", m.history.YOffset())
	}
	m = typeText(t, m, "k")
	if m.history.YOffset() != 0 {
		t.Fatalf("k: offset %d, want 0", m.history.YOffset())
	}
	m = update(t, m, press('d', "", tea.ModCtrl))
	half := m.history.YOffset()
	if half <= 1 {
		t.Fatalf("ctrl+d moved to %d", half)
	}
	m = update(t, m, press('u', "", tea.ModCtrl))
	if m.history.YOffset() != 0 {
		t.Fatalf("ctrl+u: offset %d", m.history.YOffset())
	}
	m = update(t, m, press('g', "G", tea.ModShift))
	if !m.history.AtBottom() {
		t.Fatal("G did not go to the bottom")
	}
	m = update(t, m, tea.MouseWheelMsg{Button: tea.MouseWheelUp})
	if m.history.AtBottom() {
		t.Fatal("mouse wheel did not scroll")
	}
}

func TestNotesStayLocal(t *testing.T) {
	m := newTestModel(t, 90, 24)
	m, _ = submit(t, m, "hello there")
	s := screen(m)
	if !strings.Contains(s, "hello there") || !strings.Contains(s, "local · not sent") {
		t.Fatalf("note not shown as local:\n%s", s)
	}
	if m.input.Value() != "" {
		t.Errorf("input not cleared: %q", m.input.Value())
	}
	m, _ = submit(t, m, "   ")
	if got := len(m.convs[0].entries); got != 2 {
		t.Errorf("blank input created an entry; %d entries", got)
	}
}

func TestNoteIsSanitized(t *testing.T) {
	m := newTestModel(t, 90, 24)
	m = update(t, m, tea.PasteMsg{Content: "evil \x1b]0;pwned\x07\x1b[2J text \u202e"})
	m, _ = updateCmd(t, m, keyEnter)
	last := m.convs[0].entries[len(m.convs[0].entries)-1]
	if strings.ContainsAny(last.text, "\x1b\x07\u202e") {
		t.Fatalf("note kept control characters: %q", last.text)
	}
}

func TestCommands(t *testing.T) {
	m := connected(t, newTestModel(t, 60, 40))

	m, _ = submit(t, m, "/help")
	for _, want := range []string{"/status", "/fingerprint", "/clear", "/quit"} {
		if !strings.Contains(screen(m), want) {
			t.Errorf("/help lacks %q", want)
		}
	}

	m, _ = submit(t, m, "/status")
	s := screen(m)
	for _, want := range []string{"status", "connected since 14:02:00", "chat.example.org:8443", "TLS 1.3 · X25519MLKEM768", "23 ms", "no identity loaded"} {
		if !strings.Contains(s, want) {
			t.Errorf("/status lacks %q:\n%s", want, s)
		}
	}
	compact := strings.Join(strings.Fields(s), "")
	hex := strings.ReplaceAll(testPin().Grouped(), " ", "")
	if !strings.Contains(compact, hex) {
		t.Errorf("/status lacks the full fingerprint")
	}
	m = update(t, m, tea.WindowSizeMsg{Width: 60, Height: 40})
	m, _ = submit(t, m, "/clear")
	if len(m.convs[0].entries) != 0 || strings.Contains(screen(m), "/fingerprint") {
		t.Fatal("/clear did not clear the history")
	}

	m, _ = submit(t, m, "/fingerprint")
	compact = strings.Join(strings.Fields(screen(m)), "")
	if !strings.Contains(compact, testPin().String()) || !strings.Contains(compact, hex) {
		t.Errorf("/fingerprint lacks the fingerprint:\n%s", screen(m))
	}

	m, _ = submit(t, m, "/frobnicate")
	if !strings.Contains(screen(m), "Unknown command /frobnicate") {
		t.Errorf("unknown command not reported:\n%s", screen(m))
	}

	m, cmd := submit(t, m, "/quit")
	if !m.Quitting() || cmd == nil {
		t.Fatal("/quit did not quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("/quit did not return tea.Quit")
	}
}

func TestCommandPalette(t *testing.T) {
	m := newTestModel(t, 80, 24)
	m = typeText(t, m, "/")
	s := screen(m)
	for _, c := range commands[:maxPaletteRows] {
		if !strings.Contains(s, c.name) {
			t.Errorf("palette lacks %s", c.name)
		}
	}
	checkFits(t, m)

	m = update(t, m, keyTab)
	if m.input.Value() != "/help" {
		t.Fatalf("first tab: %q", m.input.Value())
	}
	m = update(t, m, keyTab)
	if m.input.Value() != "/add" {
		t.Fatalf("second tab: %q", m.input.Value())
	}
	m.input.Reset()
	m.resetPalette()
	m = typeText(t, m, "/fi")
	m = update(t, m, keyTab)
	if m.input.Value() != "/fingerprint" {
		t.Fatalf("completion of /fi: %q", m.input.Value())
	}
	m.input.Reset()
	m.resetPalette()

	m = typeText(t, m, "/st")
	m, _ = updateCmd(t, m, keyEnter)
	last := m.convs[0].entries[len(m.convs[0].entries)-1]
	if last.kind != entryOutput || last.title != "status" {
		t.Fatalf("enter on /st ran %+v", last)
	}

	m = typeText(t, m, "/")
	m = update(t, m, press(tea.KeyDown, "", 0))
	for i := 0; i < 6; i++ {
		m = update(t, m, press(tea.KeyDown, "", 0))
	}
	m, _ = updateCmd(t, m, keyEnter)
	last = m.convs[0].entries[len(m.convs[0].entries)-1]
	if last.title != "fingerprint" {
		t.Fatalf("palette selection ran %q", last.title)
	}

	m = typeText(t, m, "/zz")
	if !strings.Contains(screen(m), "no matching command") {
		t.Error("palette does not say that nothing matches")
	}
}

func TestSecurityAlert(t *testing.T) {
	m := newTestModel(t, 100, 40)
	presented := testPin()
	presented[0] ^= 0xff
	m = update(t, m, event(client.StateChanged{State: client.Connecting, Attempt: 1}))
	m = update(t, m, event(client.SecurityAlert{Expected: testPin(), Presented: presented}))
	m = update(t, m, event(client.StateChanged{State: client.Failed, Err: &transport.PinMismatchError{Expected: testPin(), Presented: presented}}))
	s := screen(m)
	for _, want := range []string{"Server key mismatch", "connection blocked", "expected", "presented", "will not reconnect", "╭", "╰", "✕ key mismatch"} {
		if !strings.Contains(s, want) {
			t.Errorf("alert view lacks %q:\n%s", want, s)
		}
	}
	compact := strings.Join(strings.Fields(s), "")
	for _, fp := range []transport.Fingerprint{testPin(), presented} {
		for _, g := range strings.Fields(fp.Grouped())[:8] {
			if !strings.Contains(compact, g) {
				t.Errorf("alert lacks fingerprint group %s", g)
			}
		}
	}
	checkFits(t, m)
	for _, w := range []int{40, 55, 69, 70, 84, 140} {
		m = update(t, m, tea.WindowSizeMsg{Width: w, Height: 30})
		checkFits(t, m)
	}
}

func TestServerErrorIsShown(t *testing.T) {
	m := newTestModel(t, 100, 24)
	m = update(t, m, event(client.ServerError{Code: protocol.ErrCodeRateLimited, Message: "slow down"}))
	if !strings.Contains(screen(m), "Server error RateLimited: slow down.") {
		t.Errorf("server error not shown:\n%s", screen(m))
	}
}

func TestDescribeError(t *testing.T) {
	cases := map[error]string{
		client.ErrHandshakeTimeout:                                           "did not answer",
		fmt.Errorf("x: %w", client.ErrConnectionLost):                        "connection dropped",
		&client.RemoteError{Code: protocol.ErrCodeInternal, Message: "boom"}: "Internal: boom",
		fmt.Errorf("transport: dial: %w", errors.New("connection refused")):  "cannot reach the server (connection refused)",
	}
	for err, want := range cases {
		if got := describeError(err); !strings.Contains(got, want) {
			t.Errorf("describeError(%v) = %q, want it to contain %q", err, got, want)
		}
	}
}

func TestWideRunesNeverOverflow(t *testing.T) {
	notes := []string{
		"emoji 🔒🚀👍🏽 and flags 🇩🇪🇯🇵 mixed with text that keeps going and going",
		"日本語のテキストは幅が二倍です。日本語のテキストは幅が二倍です。日本語のテキストは幅が二倍です。",
		strings.Repeat("x", 300),
		"combining e\u0301 and zero\u200bwidth and tabs\tinside",
	}
	for _, w := range []int{40, 41, 57, 69, 70, 71, 99, 100, 133} {
		for _, h := range []int{10, 11, 17, 30} {
			m := connected(t, newTestModel(t, w, h))
			for _, n := range notes {
				m, _ = submit(t, m, n)
			}
			m = typeText(t, m, notes[0]+notes[1])
			checkFits(t, m)
			m = update(t, m, keyEsc)
			m = typeText(t, m, "g")
			checkFits(t, m)
			m = typeText(t, m, ":")
			checkFits(t, m)
			if got := len(strings.Split(m.View().Content, "\n")); got != h {
				t.Errorf("%dx%d: %d lines, want %d", w, h, got, h)
			}
		}
	}
}

func TestInputGrowsToThreeLines(t *testing.T) {
	m := newTestModel(t, 60, 20)
	m = typeText(t, m, strings.Repeat("word ", 60))
	if h := m.input.Height(); h != maxInputHeight {
		t.Fatalf("input height %d, want %d", h, maxInputHeight)
	}
	checkFits(t, m)
	m, _ = updateCmd(t, m, keyEnter)
	if h := m.input.Height(); h != 1 {
		t.Fatalf("input height after submit %d, want 1", h)
	}
}

func TestInputEditing(t *testing.T) {
	in := newInputLine(newStyles(DefaultTheme()))
	in.SetWidth(30)
	in.insert("hello world")
	in.Update(press(tea.KeyBackspace, "", 0))
	if in.Value() != "hello worl" {
		t.Fatalf("backspace: %q", in.Value())
	}
	in.Update(press('w', "", tea.ModCtrl))
	if in.Value() != "hello " {
		t.Fatalf("ctrl+w: %q", in.Value())
	}
	in.Update(press(tea.KeyHome, "", 0))
	in.Update(press('>', ">", 0))
	if in.Value() != ">hello " {
		t.Fatalf("home+insert: %q", in.Value())
	}
	in.Update(press('j', "", tea.ModCtrl))
	if in.Value() != ">\nhello " || in.Height() != 2 {
		t.Fatalf("newline: %q height %d", in.Value(), in.Height())
	}
	in.Update(press('k', "", tea.ModCtrl))
	if in.Value() != ">\n" {
		t.Fatalf("ctrl+k: %q", in.Value())
	}
}

func TestSessionEventsCommand(t *testing.T) {
	ch := make(chan client.Event, 1)
	m := New(Config{Addr: "a:1", Pin: testPin(), Events: ch})
	cmd := m.Init()
	if cmd == nil {
		t.Fatal("Init returned no command")
	}
	ch <- client.RTT{Duration: time.Millisecond}
	msg := cmd()
	ev, ok := msg.(sessionEventMsg)
	if !ok {
		t.Fatalf("command produced %T", msg)
	}
	m, next := updateCmd(t, m, ev)
	if next == nil || !m.conn.hasRTT {
		t.Fatal("event not handled or listener not re-armed")
	}
	close(ch)
	if _, ok := next().(sessionClosedMsg); !ok {
		t.Fatal("closed channel not reported")
	}
	m, again := updateCmd(t, m, sessionClosedMsg{})
	if again != nil || m.listen() != nil {
		t.Fatal("listener re-armed after the channel closed")
	}
}

func TestSnapshot(t *testing.T) {
	m := connected(t, newTestModel(t, 100, 30))
	m, _ = submit(t, m, "Testing the new client. Notes like this one stay on this machine 🔒")
	m, _ = submit(t, m, "/status")
	m = typeText(t, m, "/f")
	checkFits(t, m)
	t.Logf("snapshot 100x30:\n%s", screen(m))

	a := newTestModel(t, 100, 30)
	presented := testPin()
	presented[3] ^= 0x5a
	a = update(t, a, event(client.StateChanged{State: client.Connecting, Attempt: 1}))
	a = update(t, a, event(client.SecurityAlert{Expected: testPin(), Presented: presented}))
	a = update(t, a, event(client.StateChanged{State: client.Failed, Err: &transport.PinMismatchError{}}))
	a = update(t, a, keyEsc)
	checkFits(t, a)
	t.Logf("alert snapshot 100x30:\n%s", screen(a))
	t.Logf("minimum 40x10:\n%s", screen(connected(t, newTestModel(t, 40, 10))))
}
