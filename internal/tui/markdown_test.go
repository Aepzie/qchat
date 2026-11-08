package tui

import (
	"html"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
)

// renderPlain renders body through the Markdown pipeline at width and
// returns the lines without escape sequences.
func renderPlain(t *testing.T, body string, width int) []string {
	t.Helper()
	st := newStyles(DefaultTheme())
	lines := renderBody(sanitizeText(body), width, st)
	out := make([]string, len(lines))
	for i, l := range lines {
		if w := lipgloss.Width(l); w > width {
			t.Errorf("line %d is %d cells wide at width %d: %q", i, w, width, stripANSI(l))
		}
		out[i] = stripANSI(l)
	}
	return out
}

func TestSafeMarkdownSubset(t *testing.T) {
	// want is the normalised document with character references resolved;
	// literal marks inputs whose output must not contain raw syntax.
	cases := []struct {
		in, want string
		literal  bool
	}{
		{"plain text", "plain text", false},
		{"*em* and **strong** and `code`", "*em* and **strong** and `code`", false},
		{"[site](https://example.org)", "site [https://example.org]", true},
		{"![a cat](http://x/cat.png)", "[image: a cat]", true},
		{"<b>bold</b>", "<b>bold</b>", true},
		{"# Title", "**Title**", false},
		{"a & b &amp; &#27;", "a & b & ", true},
		{"```go\nfmt.Println(1)\n```", "```\nfmt.Println(1)\n```", false},
		{"- one\n- two", "- one\n- two", false},
		{"1. one\n2. two", "1. one\n2. two", false},
		{"> quoted\n> text", "> quoted\\\n> text", false},
		{"line one\nline two", "line one\\\nline two", false},
		{"| a | b |\n|---|---|\n| 1 | 2 |", "| a | b |\\\n|---|---|\\\n| 1 | 2 |", true},
		{"<https://auto.example>", "https://auto.example", true},
		{"``a`b``", "``a`b``", false},
		{"`a & b`", "`a & b`", false},
	}
	for _, c := range cases {
		got := safeMarkdown(c.in)
		if html.UnescapeString(got) != c.want {
			t.Errorf("safeMarkdown(%q)\n got %q\nwant %q", c.in, html.UnescapeString(got), c.want)
		}
		if c.literal && strings.ContainsAny(got, "[]<>:/|*_`!") {
			t.Errorf("safeMarkdown(%q) = %q keeps raw syntax", c.in, got)
		}
	}
}

func TestMarkdownRendering(t *testing.T) {
	got := strings.Join(renderPlain(t, "Hello **world**, see `x := 1`\n\n- first\n- second\n\n> quoted", 60), "\n")
	for _, want := range []string{"Hello world, see x := 1", "• first", "• second", "│ quoted"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendering lacks %q:\n%s", want, got)
		}
	}
	for _, bad := range []string{"**", "`", "> quoted"} {
		if strings.Contains(got, bad) {
			t.Errorf("rendering still shows %q:\n%s", bad, got)
		}
	}

	got = strings.Join(renderPlain(t, "see [the docs](https://example.org/a) and ![logo](https://example.org/l.png)", 80), "\n")
	if !strings.Contains(got, "the docs [https://example.org/a]") || !strings.Contains(got, "[image: logo]") || strings.Contains(got, "l.png") {
		t.Errorf("links and images:\n%s", got)
	}

	got = strings.Join(renderPlain(t, "first line\nsecond line", 80), "\n")
	if got != "first line\nsecond line" {
		t.Errorf("line breaks not kept: %q", got)
	}

	got = strings.Join(renderPlain(t, "```\n  indented code\n```", 40), "\n")
	if !strings.Contains(got, "indented code") {
		t.Errorf("code block:\n%s", got)
	}
}

func TestMarkdownIsHarmless(t *testing.T) {
	bodies := []string{
		"\x1b]8;;http://evil\x07click me\x1b]8;;\x07",
		"[x](javascript:alert(1))",
		"[x](http://evil \"title\")",
		"<a href=\"http://evil\">x</a>",
		"<script>alert(1)</script>",
		"&#27;[2J&#x1b;]8;;http://evil&#7;x&#155;31m",
		"http://bare.example www.bare.example user@mail.example",
		"\u202eevil\u2066 `\x1b[31m` **\x1b[2J**",
		"```\n\x1b]0;title\x07\n```",
		"![\x1b]8;;http://evil\x07alt](javascript:x)",
		"[a](<\x1b[2J>)",
	}
	for _, body := range bodies {
		st := newStyles(DefaultTheme())
		for _, width := range []int{8, 20, 80} {
			raw := strings.Join(renderBody(sanitizeText(body), width, st), "\n")
			for _, bad := range []string{"\x1b]", "\x1b[2J", "\x07", "\u009b", "\u202e", "\u2066", "\x1bP", "\x1b_"} {
				if strings.Contains(raw, bad) {
					t.Errorf("%q at %d renders %q: %q", body, width, bad, raw)
				}
			}
			if s := keepSGR(raw); s != raw {
				t.Errorf("%q at %d contains escape sequences other than SGR: %q", body, width, raw)
			}
			for i, l := range strings.Split(raw, "\n") {
				if w := lipgloss.Width(l); w > width {
					t.Errorf("%q at %d: line %d is %d cells", body, width, i, w)
				}
			}
		}
	}
	got := strings.Join(renderPlain(t, "[x](javascript:alert(1))", 80), "\n")
	if got != "x [javascript:alert(1)]" {
		t.Errorf("javascript link rendered as %q", got)
	}
	got = strings.Join(renderPlain(t, "<a href=\"http://evil\">x</a>", 80), "\n")
	if got != "<a href=\"http://evil\">x</a>" {
		t.Errorf("HTML rendered as %q", got)
	}
}

func TestKeepSGR(t *testing.T) {
	in := "a\x1b[1;38;2;1;2;3mb\x1b[0m\x1b]8;;http://x\x07c\x1b]8;;\x1b\\d\x1b[2Je\x1b[?25lf\x07\x00g\x1bPq\x1b\\h\x1b"
	want := "a\x1b[1;38;2;1;2;3mb\x1b[0mcdefgh"
	if got := keepSGR(in); got != want {
		t.Errorf("keepSGR = %q, want %q", got, want)
	}
}

func TestMarkdownFallsBackToPlainText(t *testing.T) {
	long := strings.Repeat("**x** ", maxMarkdownBytes/6+10)
	got := renderPlain(t, long, 60)
	if !strings.Contains(got[0], "**x**") {
		t.Errorf("long body was rendered as Markdown: %q", got[0])
	}

	st := newStyles(DefaultTheme())
	st.markdown = false
	lines := renderBody("**bold**", 40, st)
	if len(lines) != 1 || stripANSI(lines[0]) != "**bold**" {
		t.Errorf("markdown off: %q", lines)
	}
}

func TestMarkdownCommandAndSetting(t *testing.T) {
	sb := newSettingsBackend()
	sb.history[aliceID] = []MessageInfo{{ID: "md", Text: "this is **important**", Sent: testClock, Received: testClock}}
	m := newChatModel(t, sb, 100, 30)
	m = do(t, m, keyCtrlN)
	if !strings.Contains(screen(m), "this is important") {
		t.Fatalf("markdown not rendered by default:\n%s", screen(m))
	}
	m = say(t, m, "/markdown off")
	if !strings.Contains(screen(m), "this is **important**") || m.st.markdown {
		t.Fatalf("/markdown off:\n%s", screen(m))
	}
	if strings.Join(sb.writes, ",") != SettingMarkdown+"=off" {
		t.Errorf("writes %v", sb.writes)
	}
	m = say(t, m, "/markdown")
	if !strings.Contains(screen(m), "Markdown is off") {
		t.Errorf("/markdown without argument:\n%s", screen(m))
	}
	m = say(t, m, "/markdown maybe")
	if !strings.Contains(screen(m), "usage: /markdown on|off") {
		t.Errorf("bad argument:\n%s", screen(m))
	}
	m = say(t, m, "/theme fjord")
	if m.st.markdown {
		t.Error("switching themes turned Markdown back on")
	}
	m = typeText(t, m, "/markdown o")
	m = update(t, m, keyTab)
	if m.input.Value() != "/markdown on" {
		t.Errorf("completion: %q", m.input.Value())
	}
	m = do(t, m, keyEnter)
	if !m.st.markdown {
		t.Error("/markdown on did not turn it on")
	}

	sb2 := newSettingsBackend()
	sb2.values[SettingMarkdown] = "off"
	m2 := newChatModel(t, sb2, 80, 24)
	if m2.st.markdown {
		t.Error("stored ui.markdown=off not applied")
	}
}

func TestMarkdownWidthInvariant(t *testing.T) {
	fb := newFakeBackend()
	fb.history[aliceID] = []MessageInfo{
		{ID: "1", Text: "# Heading\n\nSome **bold** and *italic* text with `inline code` and a [link](https://example.org/a/very/long/path/that/does/not/fit/anywhere/at/all)", Sent: testClock},
		{ID: "2", Text: "```\n" + strings.Repeat("x", 300) + "\nshort\n" + strings.Repeat("日本", 60) + "\n```", Sent: testClock},
		{ID: "3", Text: "- a\n  - nested **item** with " + strings.Repeat("words ", 30) + "\n- b\n\n1. one\n2. two\n\n> quote " + strings.Repeat("🔒", 40), Sent: testClock},
		{ID: "4", Text: "![img](x) <b>html</b> " + strings.Repeat("a", 200), Sent: testClock},
	}
	for _, w := range []int{40, 41, 55, 69, 70, 99, 133} {
		for _, h := range []int{10, 17, 40} {
			m := newChatModel(t, fb, w, h)
			m = do(t, m, keyCtrlN)
			checkFits(t, m)
			for _, th := range Themes() {
				m.setTheme(th)
				checkFits(t, m)
			}
		}
	}
}

func TestMarkdownSnapshot(t *testing.T) {
	fb := newFakeBackend()
	fb.history[aliceID] = []MessageInfo{
		{ID: "1", Text: "Plan for **Friday**:\n\n1. pick up the `keys`\n2. call *Bob*\n\n> bring the [map](https://maps.example/x)", Sent: testClock, Received: testClock},
		{ID: "2", Outgoing: true, Text: "```\nsafety number 12345\n```", Sent: testClock, Status: StatusSent},
	}
	m := newChatModel(t, fb, 90, 26)
	m = do(t, m, keyCtrlN)
	checkFits(t, m)
	t.Logf("markdown 90x26:\n%s", screen(m))
}
