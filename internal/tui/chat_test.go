package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"rsc.io/qr"
)

func testID(c byte) string { return idPrefix + strings.Repeat(string(c), idChars) }

var (
	aliceID = testID('a')
	bobID   = testID('b')
	carolID = testID('c')
	selfID  = testID('s')
)

// fakeBackend records calls and answers from canned data.
type fakeBackend struct {
	mu        sync.Mutex
	contacts  []ContactInfo
	history   map[string][]MessageInfo
	sendErr   error
	sendState MessageStatus
	addErr    error
	sent      []string
	added     []string
	renamed   []string
	removed   []string
	marked    map[string]bool
	read      []string
	nextID    int
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		contacts: []ContactInfo{
			{ID: aliceID, ShortID: "qc1-aaaa-aaaa", DisplayName: "Alice", Verified: true},
			{ID: bobID, ShortID: "qc1-bbbb-bbbb", DisplayName: "Bob", Unread: 2},
		},
		history: map[string][]MessageInfo{
			aliceID: {
				{ID: "h1", Text: "hi, it's Alice", Sent: testClock.Add(-time.Hour), Received: testClock.Add(-time.Hour)},
				{ID: "h2", Outgoing: true, Text: "hello Alice", Sent: testClock.Add(-50 * time.Minute), Status: StatusSent},
			},
		},
		sendState: StatusSent,
		marked:    map[string]bool{},
	}
}

var testClock = time.Date(2026, 11, 7, 14, 2, 11, 0, time.UTC)

func (f *fakeBackend) Self() SelfInfo {
	return SelfInfo{DisplayName: "Me", ID: selfID, ShortID: "qc1-ssss-ssss"}
}

func (f *fakeBackend) Contacts() ([]ContactInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ContactInfo(nil), f.contacts...), nil
}

func (f *fakeBackend) History(id string, limit int) ([]MessageInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]MessageInfo(nil), f.history[id]...), nil
}

func (f *fakeBackend) AddContact(_ context.Context, id, name string) (ContactInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added = append(f.added, id+"|"+name)
	if f.addErr != nil {
		return ContactInfo{}, f.addErr
	}
	c := ContactInfo{ID: id, ShortID: shortID(id), DisplayName: name}
	f.contacts = append(f.contacts, c)
	return c, nil
}

func (f *fakeBackend) RenameContact(id, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renamed = append(f.renamed, id+"|"+name)
	return nil
}

func (f *fakeBackend) RemoveContact(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, id)
	return nil
}

func (f *fakeBackend) Send(_ context.Context, id, text string) (MessageInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, id+"|"+text)
	if f.sendErr != nil {
		return MessageInfo{}, f.sendErr
	}
	f.nextID++
	return MessageInfo{ID: fmt.Sprintf("m%d", f.nextID), Outgoing: true, Text: text, Sent: testClock, Status: f.sendState}, nil
}

func testDigits() string {
	var b strings.Builder
	for i := 0; i < safetyDigits; i++ {
		b.WriteByte(byte('0' + (i*7+3)%10))
	}
	return b.String()
}

func (f *fakeBackend) Verification(id string) (VerificationInfo, error) {
	digits := testDigits()
	payload := "qchat-verify:1:" + strings.Repeat("ab", 32) + ":" + strings.Repeat("cd", 32) + ":" + digits
	return VerificationInfo{SafetyNumber: digits, QRPayload: payload}, nil
}

func (f *fakeBackend) MarkVerified(id string, verified bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.marked[id] = verified
	return nil
}

func (f *fakeBackend) MarkRead(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.read = append(f.read, id)
	return nil
}

// drain runs cmd and every command its messages produce, feeding the
// results back into the model.
func drain(t *testing.T, m Model, cmd tea.Cmd) Model {
	t.Helper()
	queue := []tea.Cmd{cmd}
	for steps := 0; len(queue) > 0; steps++ {
		if steps > 1000 {
			t.Fatal("drain did not settle")
		}
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		switch msg := c().(type) {
		case nil:
		case tea.BatchMsg:
			queue = append(queue, msg...)
		case tea.QuitMsg:
		default:
			var next tea.Cmd
			m, next = updateCmd(t, m, msg)
			queue = append(queue, next)
		}
	}
	return m
}

// do sends msg to the model and runs the resulting commands.
func do(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	m, cmd := updateCmd(t, m, msg)
	return drain(t, m, cmd)
}

// say types s and presses enter, running the resulting commands.
func say(t *testing.T, m Model, s string) Model {
	t.Helper()
	return do(t, typeText(t, m, s), keyEnter)
}

func newChatModel(t *testing.T, fb *fakeBackend, width, height int) Model {
	t.Helper()
	m := New(Config{
		Addr:    "chat.example.org:8443",
		Pin:     testPin(),
		Version: "0.2.0",
		Backend: fb,
		Now:     func() time.Time { return testClock },
	})
	m = update(t, m, tea.WindowSizeMsg{Width: width, Height: height})
	return drain(t, m, m.Init())
}

var keyCtrlN = press('n', "", tea.ModCtrl)
var keyCtrlP = press('p', "", tea.ModCtrl)

func sidebarLine(t *testing.T, m Model, name string) string {
	t.Helper()
	for _, l := range strings.Split(screen(m), "\n") {
		if len(l) > 0 && strings.Contains(truncatePlain(l, sidebarWidth), name) {
			return truncatePlain(l, sidebarWidth)
		}
	}
	t.Fatalf("sidebar has no row %q:\n%s", name, screen(m))
	return ""
}

func truncatePlain(s string, n int) string {
	r := []rune(s)
	return string(r[:min(n, len(r))])
}

func TestChatSidebarShowsContacts(t *testing.T) {
	m := newChatModel(t, newFakeBackend(), 100, 24)
	s := screen(m)
	top := strings.SplitN(s, "\n", 2)[0]
	for _, want := range []string{"E2E · no forward secrecy yet", "id qc1-ssss-ssss"} {
		if !strings.Contains(top, want) {
			t.Errorf("status bar %q lacks %q", top, want)
		}
	}
	if !strings.Contains(sidebarLine(t, m, "Alice"), "✓") {
		t.Error("verified marker missing")
	}
	if !strings.Contains(sidebarLine(t, m, "Bob"), " 2 ") {
		t.Error("unread badge missing")
	}
	if strings.Index(s, "System") > strings.Index(s, "Alice") {
		t.Error("System is not the first entry")
	}
	checkFits(t, m)
}

func TestSidebarNavigation(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 100, 24)
	m = do(t, m, keyCtrlN)
	s := screen(m)
	for _, want := range []string{"Alice  qc1-aaaa-aaaa  ✓ verified", "hi, it's Alice", "hello Alice", "✓ sent"} {
		if !strings.Contains(s, want) {
			t.Errorf("Alice's conversation lacks %q:\n%s", want, s)
		}
	}
	m = do(t, m, keyCtrlN)
	if !strings.Contains(screen(m), "unverified — /verify") {
		t.Errorf("Bob's header lacks the unverified warning:\n%s", screen(m))
	}
	if strings.Contains(sidebarLine(t, m, "Bob"), " 2 ") || len(fb.read) == 0 || fb.read[len(fb.read)-1] != bobID {
		t.Errorf("opening Bob did not mark him read (read=%v)", fb.read)
	}
	m = do(t, m, keyCtrlP)
	m = do(t, m, keyCtrlP)
	if m.open != systemKey {
		t.Fatalf("ctrl+p twice: open %q", m.open)
	}

	m = do(t, m, keyEsc)
	m = do(t, m, press('j', "J", tea.ModShift))
	m = do(t, m, press('j', "J", tea.ModShift))
	if m.cursor != bobID || m.open != systemKey {
		t.Fatalf("J moved cursor to %q, open %q", m.cursor, m.open)
	}
	m = do(t, m, press('k', "K", tea.ModShift))
	if !strings.Contains(sidebarLine(t, m, "Alice"), "›") {
		t.Error("cursor row not marked")
	}
	m = do(t, m, keyEnter)
	if m.open != aliceID || m.Mode() != ModeInsert {
		t.Fatalf("enter opened %q in mode %v", m.open, m.Mode())
	}
	checkFits(t, m)
}

func TestIncomingMessageBumpsUnread(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 100, 24)
	m = do(t, m, keyCtrlN)
	m = do(t, m, chatEventMsg{IncomingMessage{ContactID: bobID, Message: MessageInfo{ID: "b1", Text: "ping", Received: testClock}}})
	if !strings.Contains(sidebarLine(t, m, "Bob"), " 3 ") {
		t.Errorf("unread not bumped: %q", sidebarLine(t, m, "Bob"))
	}
	if strings.Contains(screen(m), "ping") {
		t.Error("message for Bob shown in Alice's conversation")
	}
	reads := len(fb.read)
	m = do(t, m, chatEventMsg{IncomingMessage{ContactID: aliceID, Message: MessageInfo{ID: "a9", Text: "are you there?", Received: testClock}}})
	if !strings.Contains(screen(m), "are you there?") || len(fb.read) != reads+1 {
		t.Errorf("message in the open conversation not shown or not marked read:\n%s", screen(m))
	}
	m = do(t, m, chatEventMsg{IncomingMessage{ContactID: aliceID, Message: MessageInfo{ID: "a9", Text: "are you there?"}}})
	if strings.Count(screen(m), "are you there?") != 1 {
		t.Error("duplicate message ID shown twice")
	}
}

func TestSendFlow(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 100, 24)
	m = do(t, m, keyCtrlN)
	m = typeText(t, m, "secret plans")
	m, cmd := updateCmd(t, m, keyEnter)
	if !strings.Contains(screen(m), "… sending") {
		t.Fatalf("pending message not shown as sending:\n%s", screen(m))
	}
	m = drain(t, m, cmd)
	if len(fb.sent) != 1 || fb.sent[0] != aliceID+"|secret plans" {
		t.Fatalf("Send calls: %v", fb.sent)
	}
	if strings.Contains(screen(m), "sending") {
		t.Errorf("still sending after the result:\n%s", screen(m))
	}
	m = do(t, m, chatEventMsg{MessageStatusChanged{ContactID: aliceID, MessageID: "m1", Status: StatusRecipientOffline}})
	if !strings.Contains(screen(m), "⧗ recipient offline · not delivered") {
		t.Errorf("status change not shown:\n%s", screen(m))
	}

	fb.sendErr = errors.New("relay \x1b[31mrefused\x1b[0m")
	m = say(t, m, "second try")
	s := screen(m)
	if !strings.Contains(s, "✕ not sent") || !strings.Contains(s, "relay [31mrefused[0m") {
		t.Errorf("failure not shown:\n%s", s)
	}
	if strings.Contains(m.View().Content, "\x1b[31mrefused") {
		t.Error("escape sequence from the error reached the terminal")
	}

	m = do(t, m, keyCtrlP)
	m = say(t, m, "just a note")
	if len(fb.sent) != 2 || !strings.Contains(screen(m), "local · not sent") {
		t.Errorf("System note was sent: %v", fb.sent)
	}
}

func TestKeyChangeBanner(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 100, 30)
	m = do(t, m, keyCtrlN)
	m = do(t, m, chatEventMsg{ContactKeyChanged{ContactID: aliceID}})
	s := screen(m)
	for _, want := range []string{"⚠ Safety number changed", "╭", "Sending still works", "⚠ key changed — /verify"} {
		if !strings.Contains(s, want) {
			t.Errorf("key change view lacks %q:\n%s", want, s)
		}
	}
	if !strings.Contains(sidebarLine(t, m, "Alice"), "⚠") {
		t.Error("sidebar lacks ⚠")
	}
	m = say(t, m, "still works?")
	if len(fb.sent) != 1 || !strings.Contains(screen(m), "⚠ Safety number changed") {
		t.Errorf("sending with a changed key failed or removed the banner")
	}
	checkFits(t, m)
	for _, h := range []int{10, 12, 16} {
		small := update(t, m, tea.WindowSizeMsg{Width: 50, Height: h})
		if !strings.Contains(screen(small), "Safety number changed") {
			t.Errorf("50x%d: banner missing:\n%s", h, screen(small))
		}
		checkFits(t, small)
	}

	m = say(t, m, "/verify")
	m = do(t, m, keyEsc)
	if !strings.Contains(screen(m), "⚠ Safety number changed") {
		t.Error("closing /verify without a decision cleared the banner")
	}
	m = say(t, m, "/verify")
	m = do(t, m, press('v', "v", 0))
	m = do(t, m, keyEsc)
	s = screen(m)
	if strings.Contains(s, "Safety number changed ") || strings.Contains(sidebarLine(t, m, "Alice"), "⚠") || !fb.marked[aliceID] {
		t.Errorf("verification did not clear the warning:\n%s", s)
	}
	if !strings.Contains(s, "You marked Alice as verified.") {
		t.Errorf("verification not logged:\n%s", s)
	}
}

func TestParseAddArgs(t *testing.T) {
	body := strings.Repeat("abcd", 13)
	var grouped []string
	for i := 0; i < len(body); i += 4 {
		grouped = append(grouped, body[i:i+4])
	}
	ok := []struct {
		args     []string
		id, name string
	}{
		{[]string{"qc1-" + body}, "qc1-" + body, ""},
		{[]string{"QC1-" + strings.ToUpper(body), "Alice", "Smith"}, "qc1-" + body, "Alice Smith"},
		{[]string{"qc1-" + strings.Join(grouped, "-"), "Bob"}, "qc1-" + body, "Bob"},
		{append(append([]string{"qc1-" + grouped[0]}, grouped[1:]...), "Carol"), "qc1-" + body, "Carol"},
	}
	for _, c := range ok {
		id, name, err := parseAddArgs(c.args)
		if err != nil || id != c.id || name != c.name {
			t.Errorf("parseAddArgs(%q) = %q, %q, %v", c.args, id, name, err)
		}
	}
	bad := map[string][]string{
		"usage":           nil,
		"start with qc1-": {"qc2-" + body},
		"has 51":          {"qc1-" + body[1:]},
		"has 53":          {"qc1-" + body + "a"},
		"\"1\" is not":    {"qc1-" + body[1:] + "1"},
		"\"!\" is not":    {"qc1-" + body[1:] + "!"},
	}
	for want, args := range bad {
		if _, _, err := parseAddArgs(args); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("parseAddArgs(%q) error %v, want %q", args, err, want)
		}
	}
}

func TestAddCommand(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 100, 24)
	m = say(t, m, "/add")
	m = say(t, m, "/add qc1-tooshort")
	m = say(t, m, "/add "+aliceID)
	m = say(t, m, "/add "+selfID)
	s := screen(m)
	for _, want := range []string{"usage: /add <qc1-id> [name]", "this one has 8", "Already in your contacts as Alice", "That is your own ID"} {
		if !strings.Contains(s, want) {
			t.Errorf("/add errors lack %q:\n%s", want, s)
		}
	}
	if len(fb.added) != 0 {
		t.Fatalf("invalid /add reached the backend: %v", fb.added)
	}
	m = say(t, m, "/add "+carolID+" Carol C")
	if len(fb.added) != 1 || fb.added[0] != carolID+"|Carol C" || m.open != carolID {
		t.Fatalf("added %v, open %q", fb.added, m.open)
	}
	if !strings.Contains(screen(m), "Added Carol C") {
		t.Errorf("add not confirmed:\n%s", screen(m))
	}
	fb.addErr = errors.New("not found on the relay")
	m = say(t, m, "/add "+testID('d'))
	if !strings.Contains(screen(m), "Cannot add qc1-dddd-dddd: not found on the relay.") {
		t.Errorf("add failure not shown:\n%s", screen(m))
	}
}

func TestMessageRequests(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 100, 30)
	stranger := testID('z')
	m = do(t, m, chatEventMsg{IncomingMessage{ContactID: stranger, UnknownSender: true, Message: MessageInfo{ID: "z1", Text: "hello from a stranger", Received: testClock}}})
	if !strings.Contains(sidebarLine(t, m, "Message req"), " 1 ") {
		t.Errorf("request not counted: %q", sidebarLine(t, m, "Message req"))
	}
	m = do(t, m, keyCtrlN)
	s := screen(m)
	for _, want := range []string{"# Message requests", "hello from a stranger", "type /add and press tab", "qc1-zzzz zzzz"} {
		if !strings.Contains(s, want) {
			t.Errorf("requests view lacks %q:\n%s", want, s)
		}
	}
	m = say(t, m, "can I reply?")
	if len(fb.sent) != 0 || !strings.Contains(screen(m), "cannot be answered") {
		t.Error("reply to a request was not refused")
	}
	m = typeText(t, m, "/add ")
	m = update(t, m, keyTab)
	if m.input.Value() != "/add "+stranger+" " {
		t.Fatalf("tab completion: %q", m.input.Value())
	}
	m = say(t, m, "Zed")
	if m.open != stranger || m.conv(requestsKey) != nil {
		t.Fatalf("after /add: open %q, requests %v", m.open, m.conv(requestsKey) != nil)
	}
	if !strings.Contains(screen(m), "hello from a stranger") {
		t.Errorf("request messages not moved:\n%s", screen(m))
	}
}

func TestVerifyOverlay(t *testing.T) {
	m := newChatModel(t, newFakeBackend(), 100, 40)
	m = do(t, m, keyCtrlN)
	m = say(t, m, "/verify")
	if m.overlay.kind != overlayVerify {
		t.Fatal("overlay not open")
	}
	s := screen(m)
	for _, row := range groupDigits(testDigits(), 4) {
		if !strings.Contains(s, row) {
			t.Errorf("overlay lacks %q:\n%s", row, s)
		}
	}
	code := m.overlay.code
	if code == nil {
		t.Fatal("no QR code")
	}
	qw, _ := qrSize(code, 4)
	if !strings.Contains(s, strings.Repeat("█", qw)) || !strings.ContainsAny(s, "▀▄") {
		t.Errorf("QR block missing:\n%s", s)
	}
	checkFits(t, m)

	small := update(t, m, tea.WindowSizeMsg{Width: 60, Height: 20})
	s = screen(small)
	if strings.Contains(s, "▀") || !strings.Contains(s, "too small for the QR") {
		t.Errorf("60x20 overlay should drop the QR code:\n%s", s)
	}
	for _, row := range groupDigits(testDigits(), 4) {
		if !strings.Contains(s, row) {
			t.Errorf("60x20 overlay lacks %q", row)
		}
	}
	checkFits(t, small)

	m = do(t, m, press('u', "u", 0))
	if !strings.Contains(screen(m), "not verified") {
		t.Errorf("u did not mark unverified:\n%s", screen(m))
	}
	m = do(t, m, keyEsc)
	if m.overlay.kind != overlayNone || !strings.Contains(screen(m), "unverified — /verify") {
		t.Errorf("esc did not close or state not updated:\n%s", screen(m))
	}

	sys := newChatModel(t, newFakeBackend(), 100, 40)
	sys = say(t, sys, "/verify")
	if sys.overlay.kind != overlayNone || !strings.Contains(screen(sys), "Open a contact first") {
		t.Error("/verify in System did not explain")
	}
}

func TestQRMatchesCode(t *testing.T) {
	code := encodeQR("qc1-test", qr.M)
	lines := qrLines(code, 4)
	n := code.Size + 8
	if len(lines) != (n+1)/2 {
		t.Fatalf("%d lines for %d modules", len(lines), n)
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			ch := []rune(lines[y/2])[x]
			light := !code.Black(x-4, y-4)
			var got bool
			if y%2 == 0 {
				got = ch == '█' || ch == '▀'
			} else {
				got = ch == '█' || ch == '▄'
			}
			if got != light {
				t.Fatalf("module %d,%d: light=%v, drawn %q", x, y, light, ch)
			}
		}
	}
}

func TestWhoami(t *testing.T) {
	m := newChatModel(t, newFakeBackend(), 100, 40)
	m = say(t, m, "/whoami")
	s := screen(m)
	if !strings.Contains(s, groupID(selfID)[:24]) || !strings.Contains(s, "█") {
		t.Errorf("whoami lacks ID or QR:\n%s", s)
	}
	checkFits(t, m)
}

func TestRemoveConfirmation(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 100, 24)
	m = do(t, m, keyCtrlN)
	m = say(t, m, "/remove")
	if !strings.Contains(screen(m), "Remove Alice from your contacts?") || !strings.Contains(screen(m), "y/N") {
		t.Fatalf("no confirmation:\n%s", screen(m))
	}
	m = do(t, m, press('n', "n", 0))
	if len(fb.removed) != 0 || m.conv(aliceID) == nil || !strings.Contains(screen(m), "Kept Alice.") {
		t.Fatal("n did not keep the contact")
	}
	m = say(t, m, "/remove")
	m = do(t, m, press('y', "y", 0))
	if len(fb.removed) != 1 || m.conv(aliceID) != nil || m.open != systemKey {
		t.Fatalf("y did not remove: removed=%v open=%q", fb.removed, m.open)
	}
	if !strings.Contains(screen(m), "Removed Alice") {
		t.Errorf("removal not logged:\n%s", screen(m))
	}
}

func TestRename(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 100, 24)
	m = do(t, m, keyCtrlN)
	m = say(t, m, "/rename Alice \u202eB")
	if len(fb.renamed) != 1 || !strings.Contains(screen(m), "Renamed to Alice B") {
		t.Fatalf("rename: %v\n%s", fb.renamed, screen(m))
	}
}

func TestMaliciousContactData(t *testing.T) {
	fb := newFakeBackend()
	fb.contacts = append(fb.contacts, ContactInfo{
		ID:          carolID,
		DisplayName: "\x1b[2J\x1b]0;pwned\x07Mallory\u202eyrollaM\nsecond line" + strings.Repeat("x", 200),
	})
	m := newChatModel(t, fb, 100, 24)
	m = do(t, m, chatEventMsg{IncomingMessage{ContactID: carolID, Message: MessageInfo{ID: "c1", Text: "evil \x1b[31mred\x1b[0m \u2066isolate\u2069 \x1b]8;;http://x\x07link", Received: testClock}}})
	m = do(t, m, keyCtrlP)
	content := m.View().Content
	for _, bad := range []string{"\x1b[2J", "\x1b]0;", "\x07", "\u202e", "\u2066", "\x1b[31mred", "\x1b]8;"} {
		if strings.Contains(content, bad) {
			t.Errorf("view contains %q", bad)
		}
	}
	if !strings.Contains(screen(m), "Mallory") || !strings.Contains(sidebarLine(t, m, "Mallory"), "…") {
		t.Errorf("long name not truncated with an ellipsis:\n%s", screen(m))
	}
	checkFits(t, m)
}

func TestChatWidthInvariant(t *testing.T) {
	fb := newFakeBackend()
	fb.contacts = append(fb.contacts, ContactInfo{ID: carolID, DisplayName: strings.Repeat("日本語", 20), KeyChanged: true, Unread: 1234})
	for _, w := range []int{40, 41, 55, 69, 70, 71, 99, 100, 133} {
		for _, h := range []int{10, 11, 17, 24, 40} {
			m := newChatModel(t, fb, w, h)
			m = do(t, m, chatEventMsg{IncomingMessage{ContactID: testID('z'), UnknownSender: true, Message: MessageInfo{ID: "z", Text: strings.Repeat("long ", 40)}}})
			checkFits(t, m)
			for i := 0; i < 3; i++ {
				m = do(t, m, keyCtrlN)
				checkFits(t, m)
			}
			m = say(t, m, "a message that wraps "+strings.Repeat("🔒", 30))
			checkFits(t, m)
			m = say(t, m, "/verify")
			checkFits(t, m)
			m = do(t, m, keyEsc)
			m = say(t, m, "/whoami")
			checkFits(t, m)
			m = do(t, m, keyEsc)
			m = say(t, m, "/remove")
			checkFits(t, m)
			if got := len(strings.Split(m.View().Content, "\n")); got != h {
				t.Errorf("%dx%d: %d lines", w, h, got)
			}
		}
	}
}

func TestChatSnapshots(t *testing.T) {
	fb := newFakeBackend()
	m := newChatModel(t, fb, 100, 30)
	m = do(t, m, keyCtrlN)
	m = do(t, m, chatEventMsg{IncomingMessage{ContactID: aliceID, Message: MessageInfo{ID: "a2", Text: "Did you get the keys?", Received: testClock, ClockSkew: true}}})
	m = say(t, m, "Yes, comparing safety numbers now.")
	fb.sendState = StatusRecipientOffline
	m = say(t, m, "Are you still online?")
	m = do(t, m, chatEventMsg{IncomingMessage{ContactID: bobID, Message: MessageInfo{ID: "b9", Text: "hey"}}})
	checkFits(t, m)
	t.Logf("conversation 100x30:\n%s", screen(m))

	v := update(t, m, tea.WindowSizeMsg{Width: 100, Height: 40})
	v = say(t, v, "/verify")
	checkFits(t, v)
	t.Logf("verify 100x40:\n%s", screen(v))
}

func TestCreateProfile(t *testing.T) {
	m := NewCreateProfile(CreateProfileConfig{})
	step := func(msg tea.Msg) tea.Cmd {
		next, cmd := m.Update(msg)
		m = next.(CreateProfileModel)
		return cmd
	}
	typeIn := func(s string) {
		for _, r := range s {
			step(press(r, string(r), 0))
		}
	}
	view := func() string { return stripANSI(m.View().Content) }
	step(tea.WindowSizeMsg{Width: 80, Height: 30})
	step(keyEnter)
	step(keyEnter)
	step(keyEnter)
	if !strings.Contains(view(), "Enter a display name") {
		t.Fatalf("empty name accepted:\n%s", view())
	}
	typeIn("Me")
	step(keyTab)
	typeIn("short")
	if !strings.Contains(view(), "7 more characters needed") {
		t.Errorf("live length hint missing:\n%s", view())
	}
	step(keyTab)
	step(keyEnter)
	if !strings.Contains(view(), "at least 12 characters") || m.focus != 1 {
		t.Errorf("short passphrase accepted:\n%s", view())
	}
	typeIn(" but longer now")
	if !strings.Contains(view(), "✓ long enough") {
		t.Errorf("no long-enough hint:\n%s", view())
	}
	step(keyTab)
	typeIn("short but wrong!")
	if !strings.Contains(view(), "does not match") {
		t.Errorf("no live mismatch hint:\n%s", view())
	}
	step(keyEnter)
	if !strings.Contains(view(), "do not match") || m.confirm.runes() != 0 {
		t.Errorf("mismatch accepted or confirm not wiped:\n%s", view())
	}
	if strings.Contains(m.View().Content, "short but") || strings.Contains(m.View().Content, "longer now") {
		t.Fatal("passphrase rendered")
	}
	step(tea.PasteMsg{Content: "short but longer now"})
	if !strings.Contains(view(), "✓ matches") {
		t.Errorf("no match hint:\n%s", view())
	}
	backing := m.pass.value[:cap(m.pass.value)]
	cmd := step(keyEnter)
	if cmd == nil {
		t.Fatal("valid form not submitted")
	}
	got, ok := cmd().(ProfileSubmitted)
	if !ok || got.DisplayName != "Me" || string(got.Passphrase) != "short but longer now" {
		t.Fatalf("submitted %+v", got)
	}
	if res, done := m.Result(); !done || res.DisplayName != "Me" {
		t.Fatal("Result not set")
	}
	for _, r := range backing {
		if r != 0 {
			t.Fatal("passphrase buffer not wiped")
		}
	}
	small, _ := NewCreateProfile(CreateProfileConfig{}).Update(tea.WindowSizeMsg{Width: 30, Height: 10})
	if !strings.Contains(stripANSI(small.(CreateProfileModel).View().Content), "too small") {
		t.Error("small terminal not handled")
	}
}

func TestUnlockRetryAndRateLimit(t *testing.T) {
	now := testClock
	var tried []string
	m := NewUnlock(UnlockConfig{
		Now: func() time.Time { return now },
		Unlock: func(p []byte) error {
			tried = append(tried, string(p))
			if string(p) == "correct horse" {
				return nil
			}
			return ErrWrongPassphrase
		},
	})
	step := func(msg tea.Msg) {
		next, cmd := m.Update(msg)
		m = next.(UnlockModel)
		for cmd != nil {
			out := cmd()
			cmd = nil
			if _, tick := out.(unlockTickMsg); tick || out == nil {
				continue
			}
			next, cmd = m.Update(out)
			m = next.(UnlockModel)
		}
	}
	attempt := func(p string) {
		for _, r := range p {
			step(press(r, string(r), 0))
		}
		step(keyEnter)
	}
	view := func() string { return stripANSI(m.View().Content) }
	step(tea.WindowSizeMsg{Width: 80, Height: 24})
	attempt("wrong")
	if !strings.Contains(view(), "Wrong passphrase") || m.Unlocked() {
		t.Fatalf("wrong passphrase not reported:\n%s", view())
	}
	if strings.Contains(m.View().Content, "wrong") {
		t.Error("passphrase rendered")
	}
	for i := 0; i < 4; i++ {
		attempt("wrong")
	}
	if m.Failures() != 5 || !strings.Contains(view(), "Too many attempts. Try again in 5s") {
		t.Fatalf("no rate limit after 5 failures:\n%s", view())
	}
	attempt("correct horse")
	if len(tried) != 5 || m.Unlocked() {
		t.Fatal("attempt allowed during the delay")
	}
	now = now.Add(6 * time.Second)
	step(unlockTickMsg{})
	step(keyEnter)
	if !m.Unlocked() || tried[len(tried)-1] != "correct horse" {
		t.Fatalf("unlock after the delay failed: tried %q\n%s", tried, view())
	}
}
