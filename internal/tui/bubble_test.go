package tui

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"charm.land/lipgloss/v2"
)

var bubbleNow = time.Date(2026, 11, 7, 14, 30, 0, 0, time.UTC)

// strayEscape matches an escape sequence that is not SGR.
var strayEscape = regexp.MustCompile("\x1b(?:[^\\[]|\\[[0-9;:]*[^0-9;:m])")

func msgAt(at time.Time, from, sender, text string, outgoing bool) entry {
	return entry{kind: entryMessage, at: at, from: from, sender: sender, text: sanitizeText(text), outgoing: outgoing}
}

func plainLines(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = stripANSI(l)
	}
	return out
}

func checkWidth(t *testing.T, name string, lines []string, width int) {
	t.Helper()
	for i, l := range lines {
		if w := lipgloss.Width(l); w > width {
			t.Errorf("%s: line %d is %d cells wide, pane %d: %q", name, i, w, width, stripANSI(l))
		}
		if strayEscape.MatchString(l) {
			t.Errorf("%s: line %d carries a non-SGR escape: %q", name, i, l)
		}
	}
}

func TestBubbleAlignment(t *testing.T) {
	st := newStyles(DefaultTheme())
	const width = 80
	own := plainLines(renderBubble(st, msgAt(bubbleNow, "you", "", "hello there", true), false, width, renderOpts{}))
	if len(own) < 4 {
		t.Fatalf("own bubble too short: %q", own)
	}
	for _, l := range own[:3] {
		if lipgloss.Width(l) != width || !strings.HasPrefix(l, "    ") {
			t.Errorf("own bubble line not right-aligned: %q", l)
		}
	}
	if !strings.HasSuffix(own[0], "╮") || !strings.Contains(own[1], "│ hello there │") {
		t.Errorf("own bubble shape: %q", own)
	}

	peer := plainLines(renderBubble(st, msgAt(bubbleNow, "Bob", "", "hi you", false), false, width, renderOpts{}))
	if !strings.HasPrefix(peer[0], "    ╭") || !strings.HasPrefix(peer[1], "(B) │ hi you") || !strings.HasPrefix(peer[2], "    ╰") {
		t.Errorf("peer bubble not left-aligned behind its avatar: %q", peer)
	}
	if lipgloss.Width(strings.TrimRight(peer[1], " ")) > width*7/10+4 {
		t.Errorf("peer bubble wider than 70%%: %q", peer[1])
	}

	long := plainLines(renderBubble(st, msgAt(bubbleNow, "Bob", "", strings.Repeat("word ", 60), false), false, width, renderOpts{}))
	for _, l := range long {
		if w := lipgloss.Width(strings.TrimRight(l, " ")); w > 4+max(width*7/10, minBubbleWidth) {
			t.Errorf("long bubble exceeds the maximum width: %d %q", w, l)
		}
	}
}

func TestBubbleCompactOnNarrowPanes(t *testing.T) {
	st := newStyles(DefaultTheme())
	lines := plainLines(renderBubble(st, msgAt(bubbleNow, "Bob", "", "narrow", false), false, compactWidth-1, renderOpts{}))
	if strings.Contains(strings.Join(lines, "\n"), "╭") || !strings.Contains(lines[0], "Bob") {
		t.Errorf("narrow pane did not fall back to compact lines: %q", lines)
	}
}

func TestGroupedMessages(t *testing.T) {
	st := newStyles(DefaultTheme())
	bob, carol := "qc1-"+strings.Repeat("b", 52), "qc1-"+strings.Repeat("c", 52)
	entries := []entry{
		msgAt(bubbleNow, "Bob", bob, "one", false),
		msgAt(bubbleNow.Add(time.Minute), "Bob", bob, "two", false),
		msgAt(bubbleNow.Add(2*time.Minute), "Bob", bob, "three", false),
		msgAt(bubbleNow.Add(3*time.Minute), "Carol", carol, "four", false),
		msgAt(bubbleNow.Add(time.Hour), "Carol", carol, "five", false),
	}
	text := strings.Join(plainLines(renderConversation(st, entries, 80, renderOpts{Now: bubbleNow})), "\n")
	if n := strings.Count(text, "Bob"); n != 1 {
		t.Errorf("Bob named %d times, want once:\n%s", n, text)
	}
	if n := strings.Count(text, "(B)"); n != 1 {
		t.Errorf("Bob's avatar drawn %d times, want once:\n%s", n, text)
	}
	if n := strings.Count(text, "Carol"); n != 2 {
		t.Errorf("Carol named %d times, want twice (an hour apart):\n%s", n, text)
	}
	if strings.Contains(text, "13:31\n\n") {
		t.Errorf("blank line inside a group:\n%s", text)
	}
	if !continues(entries[0], entries[1]) || continues(entries[2], entries[3]) || continues(entries[3], entries[4]) {
		t.Error("continues misjudges groups")
	}
	if c := avatarColor(st.theme, bob); c == nil {
		t.Error("no avatar colour")
	}
}

func TestStatusIcons(t *testing.T) {
	st := newStyles(DefaultTheme())
	base := msgAt(bubbleNow, "you", "", "x", true)
	with := func(f func(*entry)) entry {
		e := base
		f(&e)
		return e
	}
	cases := []struct {
		name string
		e    entry
		opts renderOpts
		want []string
	}{
		{"sending", with(func(e *entry) { e.status = StatusSending }), renderOpts{}, []string{"14:30 ◌ sending"}},
		{"spinner", with(func(e *entry) { e.status = StatusSending }), renderOpts{Animate: true, Frame: 3}, []string{spinnerFrame(3) + " sending"}},
		{"sealed", with(func(e *entry) { e.status, e.route = StatusSent, RouteSealed }), renderOpts{}, []string{"✓ sealed"}},
		{"identified", with(func(e *entry) { e.status, e.route = StatusSent, RouteIdentified }), renderOpts{}, []string{"✓ identified"}},
		{"delivered", with(func(e *entry) { e.status, e.route, e.delivered = StatusSent, RouteSealed, true }), renderOpts{}, []string{"✓✓ delivered"}},
		{"offline", with(func(e *entry) { e.status = StatusRecipientOffline }), renderOpts{}, []string{"⧗ recipient offline"}},
		{"failed", with(func(e *entry) { e.status, e.errText = StatusFailed, "relay refused" }), renderOpts{}, []string{"✕ not sent", "relay refused"}},
		{"timer", with(func(e *entry) { e.status, e.ttl = StatusSent, 24*time.Hour }), renderOpts{}, []string{"⏱ 1d"}},
		{"skew", msgAt(bubbleNow, "Bob", "", "x", false), renderOpts{}, []string{"14:30"}},
	}
	cases[len(cases)-1].e.skew = true
	cases[len(cases)-1].want = append(cases[len(cases)-1].want, "◷ sender clock off")
	for _, tc := range cases {
		text := strings.Join(plainLines(renderBubble(st, tc.e, false, 80, tc.opts)), "\n")
		for _, w := range tc.want {
			if !strings.Contains(text, w) {
				t.Errorf("%s: lacks %q:\n%s", tc.name, w, text)
			}
		}
	}
	narrow := with(func(e *entry) { e.status, e.ttl, e.skew = StatusRecipientOffline, time.Hour, true })
	checkWidth(t, "narrow meta", renderBubble(st, narrow, false, compactWidth, renderOpts{}), compactWidth)
	sealed := renderBubble(st, with(func(e *entry) { e.status, e.route = StatusSent, RouteSealed }), false, 80, renderOpts{})
	if !strings.Contains(strings.Join(sealed, ""), st.accent.Render("✓ sealed")) {
		t.Error("sealed mark not in the accent colour")
	}
}

func TestDateSeparators(t *testing.T) {
	st := newStyles(DefaultTheme())
	for _, tc := range []struct {
		at   time.Time
		want string
	}{
		{bubbleNow.Add(-time.Hour), "Today"},
		{bubbleNow.Add(-24 * time.Hour), "Yesterday"},
		{time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC), "Mon 2 Mar"},
		{time.Date(2025, 3, 2, 9, 0, 0, 0, time.UTC), "Sun 2 Mar 2025"},
	} {
		if got := dateLabel(tc.at, bubbleNow); got != tc.want {
			t.Errorf("dateLabel(%v) = %q, want %q", tc.at, got, tc.want)
		}
	}
	entries := []entry{
		msgAt(bubbleNow.Add(-24*time.Hour), "Bob", "", "old", false),
		{kind: entrySystem, at: bubbleNow.Add(-time.Hour), text: "a notice"},
		msgAt(bubbleNow, "Bob", "", "new", false),
	}
	for _, width := range []int{1, 5, 12, 40, 100} {
		lines := renderConversation(st, entries, width, renderOpts{Now: bubbleNow})
		checkWidth(t, fmt.Sprintf("separators %d", width), lines, width)
	}
	text := plainLines(renderConversation(st, entries, 60, renderOpts{Now: bubbleNow}))
	var rules []string
	for _, l := range text {
		if strings.HasPrefix(l, "──") {
			if lipgloss.Width(l) != 60 {
				t.Errorf("rule does not span the pane: %q", l)
			}
			rules = append(rules, strings.Trim(l, "─ "))
		}
	}
	if strings.Join(rules, ",") != "Yesterday,Today" {
		t.Errorf("rules %q, want Yesterday and Today:\n%s", rules, strings.Join(text, "\n"))
	}
}

func TestNoticesAreCentred(t *testing.T) {
	st := newStyles(DefaultTheme())
	for _, tc := range []struct {
		kind entryKind
		icon string
	}{{entrySystem, "•"}, {entryGood, "●"}, {entryWarn, "◌"}, {entryError, "✕"}} {
		lines := plainLines(renderNotice(st, entry{kind: tc.kind, text: "short"}, 40))
		if len(lines) != 1 || lines[0] != strings.Repeat(" ", 16)+tc.icon+" short" {
			t.Errorf("kind %d: %q", tc.kind, lines)
		}
	}
}

func TestKeyChangeBannerBox(t *testing.T) {
	st := newStyles(DefaultTheme())
	still := renderKeyChangeBanner(st, "Bob", 60, renderOpts{})
	text := strings.Join(plainLines(still), "\n")
	if !strings.Contains(text, "⚠ KEY CHANGED — verify with /verify") || !strings.Contains(text, "Bob") || !strings.HasPrefix(text, "╭") {
		t.Errorf("banner:\n%s", text)
	}
	a := renderKeyChangeBanner(st, "Bob", 60, renderOpts{Animate: true, Frame: 0})
	b := renderKeyChangeBanner(st, "Bob", 60, renderOpts{Animate: true, Frame: pulseFrames / 2})
	if strings.Join(a, "") == strings.Join(b, "") {
		t.Error("banner does not flash")
	}
	if strings.Join(still, "") != strings.Join(renderKeyChangeBanner(st, "Bob", 60, renderOpts{Frame: 7}), "") {
		t.Error("banner changes with the frame while animations are off")
	}
	for width := 1; width <= 100; width++ {
		checkWidth(t, fmt.Sprintf("banner %d", width), renderKeyChangeBanner(st, "Bob\x1b[2J 名前", width, renderOpts{Animate: true, Frame: width}), width)
	}
}

func TestFileCard(t *testing.T) {
	st := newStyles(DefaultTheme())
	files := []FileInfo{
		{Name: "report.pdf", Size: 3 << 20, State: FileSending, Done: 16, Total: 64},
		{Name: "photo.jpg", Size: 2048, State: FileComplete, Done: 4, Total: 4},
		{Name: "broken.zip", Size: 10, State: FileFailed},
		{Name: "報告書📄ファイル名がとても長い.pdf", Size: 1 << 30, State: FileReceiving, Done: 3, Total: 4},
		{Name: strings.Repeat("x", 200), Size: 1, State: FileExpired},
	}
	for _, f := range files {
		for _, width := range []int{1, 8, 15, 16, 20, 30, 48, 80} {
			lines := renderFileCard(st, f, 2, width)
			checkWidth(t, fmt.Sprintf("%s at %d", f.Name, width), lines, width)
		}
	}
	text := strings.Join(plainLines(renderFileCard(st, files[0], 1, 40)), "\n")
	for _, want := range []string{"📄 report.pdf", "file 1 · 3.0 MiB · sending 16/64", "█", "░", " 25%", "╭", "╯"} {
		if !strings.Contains(text, want) {
			t.Errorf("sending card lacks %q:\n%s", want, text)
		}
	}
	done := strings.Join(plainLines(renderFileCard(st, files[1], 3, 40)), "\n")
	if !strings.Contains(done, "100%") || !strings.Contains(done, "/save 3") || strings.Contains(done, "░") {
		t.Errorf("complete card:\n%s", done)
	}
	failed := strings.Join(plainLines(renderFileCard(st, files[2], 0, 40)), "\n")
	if !strings.Contains(failed, "failed") || strings.Contains(failed, "/save") {
		t.Errorf("failed card:\n%s", failed)
	}
	for _, pct := range []int{0, 1, 50, 99, 100} {
		bar := stripANSI(progressBar(st, FileInfo{State: FileReceiving, Done: pct, Total: 100}, 30))
		if lipgloss.Width(bar) != 30 || !strings.HasSuffix(bar, fmt.Sprintf("%d%%", pct)) {
			t.Errorf("bar at %d%%: %q", pct, bar)
		}
	}
}

func TestFadeIn(t *testing.T) {
	st := newStyles(DefaultTheme())
	e := msgAt(bubbleNow, "Bob", "", "fresh news", false)
	e.fresh, e.arrival = true, 10
	settled := renderEntryIn(st, e, nil, 60, renderOpts{Animate: true, Frame: 10 + fadeFrames})
	static := renderEntryIn(st, e, nil, 60, renderOpts{})
	if strings.Join(settled, "\n") != strings.Join(static, "\n") {
		t.Error("entry still fading after fadeFrames")
	}
	var prev string
	for step := 0; step < fadeFrames; step++ {
		lines := renderEntryIn(st, e, nil, 60, renderOpts{Animate: true, Frame: 10 + step})
		if strings.Join(plainLines(lines), "\n") != strings.Join(plainLines(static), "\n") {
			t.Fatalf("step %d changes the layout", step)
		}
		sample := lipgloss.NewStyle().Foreground(fade(st.theme.Faint, st.theme.Text, step, fadeFrames)).Render("x")
		want := sample[:strings.Index(sample, "x")] + "(B) "
		joined := strings.Join(lines, "\n")
		if !strings.Contains(joined, want) {
			t.Errorf("step %d not drawn in the faded colour", step)
		}
		if joined == prev {
			t.Errorf("step %d equals the previous step", step)
		}
		prev = joined
	}
	if r1, g1, b1 := rgb8(fadeColor(st.theme, 0)); [3]float64{r1, g1, b1} != func() [3]float64 { r, g, b := rgb8(st.theme.Faint); return [3]float64{r, g, b} }() {
		t.Error("fade does not start at the faint colour")
	}
	entries := []entry{msgAt(bubbleNow, "Bob", "", "old", false), e}
	if !conversationAnimating(entries, renderOpts{Animate: true, Frame: 11}) || firstAnimated(entries, renderOpts{Animate: true, Frame: 11}) != 1 {
		t.Error("fading entry not reported as animating")
	}
	if conversationAnimating(entries, renderOpts{Animate: true, Frame: 10 + fadeFrames}) || conversationAnimating(entries, renderOpts{Frame: 11}) {
		t.Error("settled or static conversation reported as animating")
	}
}

func TestRenderTailMatchesWhole(t *testing.T) {
	st := newStyles(DefaultTheme())
	bob := "qc1-" + strings.Repeat("b", 52)
	entries := []entry{
		msgAt(bubbleNow.Add(-24*time.Hour), "Bob", bob, "old", false),
		{kind: entrySystem, at: bubbleNow, text: "notice"},
		msgAt(bubbleNow, "Bob", bob, "one", false),
		msgAt(bubbleNow.Add(time.Minute), "Bob", bob, "two", false),
		msgAt(bubbleNow.Add(2*time.Minute), "you", "", "mine", true),
		{kind: entryMessage, at: bubbleNow.Add(3 * time.Minute), from: "Bob", sender: bob, file: &FileInfo{Name: "a.txt", State: FileComplete}},
	}
	opts := renderOpts{Now: bubbleNow}
	whole := renderConversation(st, entries, 70, opts)
	for from := 0; from <= len(entries); from++ {
		head := renderConversation(st, entries[:from], 70, opts)
		got := append(head, renderTail(st, entries, from, 70, opts)...)
		if strings.Join(got, "\n") != strings.Join(whole, "\n") {
			t.Errorf("split at %d differs:\n%s\n---\n%s", from, strings.Join(plainLines(got), "\n"), strings.Join(plainLines(whole), "\n"))
		}
	}
	if !strings.Contains(strings.Join(plainLines(whole), "\n"), "/save 1") {
		t.Error("file not numbered")
	}
}

func TestConversationFitsEveryWidth(t *testing.T) {
	st := newStyles(DefaultTheme())
	bodies := []string{
		"hi",
		"",
		"emoji 👩‍👩‍👧‍👦🎉🇩🇪 and more 😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀",
		"漢字かな交じり文の長いメッセージです。漢字かな交じり文の長いメッセージです。",
		strings.Repeat("supercalifragilistic", 12),
		"**bold** _it_ `code` [link](https://example.org)\n\n> quote\n\n- a\n- b\n\n```\ncode block that is rather long " + strings.Repeat("x", 80) + "\n```",
		"escape \x1b[2J\x1b]8;;http://evil\x07link\x1b]8;;\x07 \u202Ebidi\u202C tab\there",
		"# heading\n\n1. one\n2. two",
	}
	bob, carol := "qc1-"+strings.Repeat("b", 52), "qc1-"+strings.Repeat("c", 52)
	var entries []entry
	for i, body := range bodies {
		at := bubbleNow.Add(time.Duration(i) * time.Minute)
		entries = append(entries,
			msgAt(at, "you", "", body, true),
			msgAt(at, "Bob 🎉 名前", bob, body, false),
			msgAt(at, "Carol", carol, body, false),
			entry{kind: entrySystem, at: at, text: sanitizeText(body)},
			entry{kind: entryError, at: at, text: sanitizeText(body)},
		)
	}
	entries[0].status, entries[0].errText = StatusFailed, sanitizeText(strings.Repeat("reason ", 30))
	entries[5].status, entries[5].ttl, entries[5].skew = StatusSending, time.Hour, true
	entries = append(entries,
		entry{kind: entryMessage, at: bubbleNow, from: "you", outgoing: true, status: StatusSent, file: &FileInfo{Name: "漢字📄" + strings.Repeat("n", 90), Size: 5 << 20, State: FileSending, Done: 1, Total: 3}},
		entry{kind: entryMessage, at: bubbleNow, from: "Bob", sender: bob, file: &FileInfo{Name: "f.bin", State: FileFailed}},
		entry{kind: entryNote, at: bubbleNow, text: "a note"},
		entry{kind: entryOutput, at: bubbleNow, title: "out", rows: []row{{"key", "value 😀 " + strings.Repeat("v", 50)}}},
		entry{kind: entryAlert, at: bubbleNow, addr: "relay.example:443"},
	)
	for i := range entries {
		entries[i].fresh = i%3 == 0
	}
	for width := 1; width <= 120; width++ {
		opts := renderOpts{Animate: width%2 == 0, Frame: width % 7, Now: bubbleNow, Group: width%3 == 0}
		checkWidth(t, fmt.Sprintf("width %d", width), renderConversation(st, entries, width, opts), width)
	}
	for _, th := range []Theme{DefaultTheme(), {Name: "bare"}} {
		lines := renderConversation(newStyles(th), entries[:10], 50, renderOpts{Now: bubbleNow})
		checkWidth(t, "theme "+th.Name, lines, 50)
	}
	plain := st
	plain.markdown = false
	checkWidth(t, "plain", renderConversation(plain, entries, 47, renderOpts{Now: bubbleNow}), 47)
}

func TestFilledBubbleKeepsFill(t *testing.T) {
	st := newStyles(DefaultTheme())
	fill, _ := bubbleColors(st.theme, true)
	bg := backgroundSGR(fill)
	lines := renderBubble(st, msgAt(bubbleNow, "you", "", "**bold** and `code` text", true), false, 80, renderOpts{})
	for _, l := range lines[1 : len(lines)-2] {
		if !strings.Contains(l, bg) {
			t.Errorf("interior line lacks the fill: %q", l)
		}
	}
	const in = "a[1mb[0mc[mD[38;2;0;0;0me"
	if got, want := keepBackground(in, "BG"), "a[1mb[0mBGc[mBGD[38;2;0;0;0me"; got != want {
		t.Errorf("keepBackground = %q, want %q", got, want)
	}
}
