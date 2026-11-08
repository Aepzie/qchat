package tui

import (
	"fmt"
	"html"
	"strings"
	"testing"
	"time"

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
		got, ok := safeMarkdown(c.in)
		if !ok {
			t.Errorf("safeMarkdown(%q) fell back to plain text", c.in)
		}
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

func TestMarkdownHostileNestingFallsBack(t *testing.T) {
	bodies := map[string]string{
		"block quotes":   strings.Repeat(">", 3000) + "a" + strings.Repeat("\nb", 2595),
		"nested lists":   strings.Repeat("- ", 1500) + "a" + strings.Repeat("\nb", 2595),
		"ordered lists":  strings.Repeat("1. ", 1000) + "a" + strings.Repeat("\nb", 2595),
		"quoted lists":   strings.Repeat("> - ", 700) + "a" + strings.Repeat("\nb", 2595),
		"lazy at nine":   strings.Repeat("> ", 9) + "a\nb",
		"many nodes":     strings.Repeat("*a* ", 1500),
		"prefix blow-up": strings.Repeat("> ", 8) + "a" + strings.Repeat("\nb", 3500),
	}
	for name, body := range bodies {
		body = sanitizeText(body)
		if len(body) >= maxMarkdownBytes {
			t.Fatalf("%s: body of %d bytes would not reach the renderer", name, len(body))
		}
		r := newMarkdownRenderer(DefaultTheme())
		start := time.Now()
		lines, ok := r.render(body, 80)
		if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
			t.Errorf("%s: rendering took %v", name, elapsed)
		}
		if ok || lines != nil {
			t.Errorf("%s: rendered as Markdown (%d lines), want plain text", name, len(lines))
		}
		start = time.Now()
		if _, ok := r.render(body, 80); ok || time.Since(start) > 50*time.Millisecond {
			t.Errorf("%s: cached fallback not used", name)
		}
	}

	deep := strings.Repeat("> ", maxMarkdownNesting) + "deep but fine"
	if got := strings.Join(renderPlain(t, deep, 80), "\n"); !strings.Contains(got, "deep but fine") || strings.Contains(got, ">") {
		t.Errorf("nesting at the limit not rendered: %q", got)
	}
	nested := "- a\n  - b\n    - c\n      - d"
	if got := strings.Join(renderPlain(t, nested, 80), "\n"); strings.Contains(got, "- ") || !strings.Contains(got, "d") {
		t.Errorf("nested list not rendered: %q", got)
	}
}

func TestMarkdownOutputLimits(t *testing.T) {
	r := newMarkdownRenderer(DefaultTheme())
	many := strings.Repeat("*x*\n\n", maxMarkdownLines/2+20)
	if _, ok := r.render(sanitizeText(many), 80); ok {
		t.Error("body rendering to more than maxMarkdownLines lines was rendered")
	}
	if _, ok := r.render("*x*\n\n*y*", 80); !ok {
		t.Error("short body not rendered")
	}
}

func TestMarkdownLinkReferenceDefinitionsStayVisible(t *testing.T) {
	got := strings.Join(renderPlain(t, "see [the docs] or [x][docs]\n\n[docs]: https://example.org/a \"T\"\n[the docs]: <https://evil.example>", 80), "\n")
	for _, want := range []string{"see [the docs] or [x][docs]", "[docs]: https://example.org/a \"T\"", "[the docs]: https://evil.example"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendering lacks %q:\n%s", want, got)
		}
	}
	doc, ok := safeMarkdown("[a]: /u")
	if !ok || strings.ContainsAny(doc, "[]:") {
		t.Errorf("definition not escaped: %q, %v", doc, ok)
	}
}

func TestMarkdownKeepsLineBreaks(t *testing.T) {
	got := strings.Join(renderPlain(t, "**first** line\nsecond line\n\n> quoted\n> twice", 80), "\n")
	for _, want := range []string{"first line\nsecond line", "│ quoted\n│ twice"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendering lacks %q:\n%s", want, got)
		}
	}
}

func TestMarkdownCacheIsBounded(t *testing.T) {
	r := newMarkdownRenderer(DefaultTheme())
	for i := 0; i < maxMarkdownCache+50; i++ {
		width := 20 + i%7
		if _, ok := r.render(fmt.Sprintf("**%d**", i), width); !ok {
			t.Fatalf("body %d not rendered", i)
		}
		if len(r.renderers) > maxMarkdownWidths {
			t.Fatalf("%d renderers kept", len(r.renderers))
		}
	}
	if r.order.Len() > maxMarkdownCache || len(r.cache) != r.order.Len() {
		t.Errorf("cache holds %d entries, order %d", len(r.cache), r.order.Len())
	}
	total := 0
	for el := r.order.Front(); el != nil; el = el.Next() {
		total += el.Value.(*markdownEntry).size
	}
	if total != r.cacheBytes || total > maxMarkdownCacheBytes {
		t.Errorf("cache accounts %d bytes, entries hold %d", r.cacheBytes, total)
	}
	if _, ok := r.cache[markdownKey{width: 20, body: "**0**"}]; ok {
		t.Error("oldest entry not evicted")
	}
	if last := r.renderers[len(r.renderers)-1].width; last != 20+(maxMarkdownCache+49)%7 {
		t.Errorf("most recent width %d not kept last", last)
	}

	r.remember(markdownKey{width: 1, body: "big"}, []string{strings.Repeat("x", maxMarkdownCacheEntry)})
	if _, ok := r.cache[markdownKey{width: 1, body: "big"}]; ok {
		t.Error("oversized entry cached")
	}
	huge := strings.Repeat("y", maxMarkdownCacheEntry/2)
	for i := 0; i < 2*maxMarkdownCacheBytes/len(huge); i++ {
		r.remember(markdownKey{width: i, body: "huge"}, []string{huge})
		if r.cacheBytes > maxMarkdownCacheBytes {
			t.Fatalf("cache holds %d bytes", r.cacheBytes)
		}
	}
}

func TestKeepSGRAllowList(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a\x1b[1;3;4;22;23;24;39;49mb", "a\x1b[1;3;4;22;23;24;39;49mb"},
		{"\x1b[31;42;97;107m\x1b[38;5;12;48;2;1;2;3m\x1b[mx", "\x1b[31;42;97;107m\x1b[38;5;12;48;2;1;2;3m\x1b[mx"},
		{"\x1b[8mhidden\x1b[0m", "hidden\x1b[0m"},
		{"\x1b[5m\x1b[7m\x1b[9m\x1b[1;8mx", "x"},
		{"\x1b[38;5;300m\x1b[38;2;1;2m\x1b[38m\x1b[38:2:1:2:3m\x1b[0001mx", "x"},
		{"a\x1b(Bb\x1b7c\x1bé", "a(Bb7cé"},
		{"ok\xff\xfe\xc3\x28 \xef\xbf\xbd", "ok( \ufffd"},
		{"\u00ad\u200b\u2028\u2029\U000e0041\u200d\ufe0f", "\u200d\ufe0f"},
	}
	for _, c := range cases {
		if got := keepSGR(c.in); got != c.want {
			t.Errorf("keepSGR(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
