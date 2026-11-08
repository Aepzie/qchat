package tui

import (
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// fuzzRenderBudget is how long one fuzz input may take to render. It is far
// above the normal cost so that instrumentation and slow machines do not
// cause false alarms, and far below a stall.
const fuzzRenderBudget = time.Second

func FuzzRenderMarkdown(f *testing.F) {
	seeds := []string{
		"plain",
		"Hello **world**, `code` and *em*\n\n- a\n  - b\n\n> quote",
		"[x](javascript:alert(1)) ![a](b) <b>x</b> <https://a.example>",
		"[ref]: https://example.org\n\nsee [ref]",
		"```\n\x1b]8;;http://evil\x07x\n```",
		"&#27;[2J&#x1b;]8;;x&#7;",
		strings.Repeat(">", 300) + "a" + strings.Repeat("\nb", 200),
		strings.Repeat("- ", 200) + "a" + strings.Repeat("\nb", 200),
		strings.Repeat("> - 1. ", 50) + "x",
		strings.Repeat("*a* ", 600),
		"\U0001f468\U0000200d\U0001f469 \U00002764\U0000fe0f \U0000202e",
	}
	for i, s := range seeds {
		f.Add(s, uint8(i*13))
	}
	f.Fuzz(func(t *testing.T, raw string, w uint8) {
		body := sanitizeText(raw)
		width := minMarkdownWidth + int(w)%120
		r := newMarkdownRenderer(DefaultTheme())
		start := time.Now()
		lines, ok := r.render(body, width)
		if elapsed := time.Since(start); elapsed > fuzzRenderBudget {
			t.Fatalf("rendering %d bytes at width %d took %v", len(body), width, elapsed)
		}
		if !ok {
			if lines != nil {
				t.Fatal("fallback returned lines")
			}
			return
		}
		if len(lines) > maxMarkdownLines {
			t.Fatalf("%d lines", len(lines))
		}
		for _, line := range lines {
			checkOnlySGR(t, line)
		}
	})
}

// checkOnlySGR fails unless line holds only drawable text and allowed SGR
// sequences.
func checkOnlySGR(t *testing.T, line string) {
	t.Helper()
	if !utf8.ValidString(line) {
		t.Fatalf("invalid UTF-8: %q", line)
	}
	for i := 0; i < len(line); {
		if line[i] == 0x1b {
			n, sgr := escapeLength(line[i:])
			if !sgr || !allowedSGR(line[i+2:i+n-1]) {
				t.Fatalf("escape sequence %q in %q", line[i:i+n], line)
			}
			i += n
			continue
		}
		r, size := utf8.DecodeRuneInString(line[i:])
		if r == '\n' || !drawableRune(r) {
			t.Fatalf("character %U in %q", r, line)
		}
		i += size
	}
}

func FuzzSanitizeText(f *testing.F) {
	seeds := []string{
		"plain",
		"a\r\nb\rc\td",
		"\x1b[31m\x07\x00\x7f\U00000085\U0000009b",
		"\U0000202e\U00002066\U0000061c\U0000200e\U0000200f",
		"\U000000ad\U0000200b\U00002060\U0000feff\U00002028\U00002029",
		"\U0001f3f4\U000e0067\U000e0062\U000e007f",
		"\U0001f468\U0000200d\U0001f469 \U00002764\U0000fe0f",
		"\xff\xfe\xc3",
		strings.Repeat("\t", maxEntryText/4+3),
		strings.Repeat("a", maxEntryText-1) + "\U0001f512",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		out := sanitizeText(raw)
		if len(out) > maxEntryText {
			t.Fatalf("%d bytes", len(out))
		}
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8: %q", out)
		}
		for _, r := range out {
			switch {
			case r == '\n':
			case r == '\r', r == '\t':
				t.Fatalf("%U kept", r)
			case r == 0x200d:
			case unicode.IsControl(r), unicode.Is(unicode.Bidi_Control, r), unicode.Is(unicode.Cf, r):
				t.Fatalf("%U kept", r)
			case r == 0x2028, r == 0x2029, r >= 0xe0000 && r <= 0xe007f:
				t.Fatalf("%U kept", r)
			}
		}
		if again := sanitizeText(out); again != out {
			t.Fatalf("not idempotent: %q then %q", out, again)
		}
	})
}
