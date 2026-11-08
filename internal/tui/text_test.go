package tui

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestSanitizeText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a\r\nb\rc\nd\te", "a\nb\nc\nd    e"},
		{"\x1b[31mred\x07\x00\U00000085", "[31mred"},
		{"\U0000202eevil\U00002066\U0000061c\U0000200e", "evil"},
		{"soft\U000000adhy\U0000200bphen\U00002060\U0000feff\U0000180e", "softhyphen"},
		{"line\U00002028para\U00002029end", "lineparaend"},
		{"flag\U0001f3f4\U000e0067\U000e0062\U000e007f", "flag\U0001f3f4"},
		{"\U0001f468\U0000200d\U0001f469\U0000200d\U0001f467 \U00002764\U0000fe0f \U00000915\U0000094d\U00000937", "\U0001f468\U0000200d\U0001f469\U0000200d\U0001f467 \U00002764\U0000fe0f \U00000915\U0000094d\U00000937"},
		{"bad\xffutf8", "bad\U0000fffdutf8"},
	}
	for _, c := range cases {
		if got := sanitizeText(c.in); got != c.want {
			t.Errorf("sanitizeText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeTextCapIsExact(t *testing.T) {
	for _, tail := range []string{"\U000000e9", "\U000065e5", "\U0001f512", "\t", "\r\n", "ab"} {
		for pad := 0; pad < 5; pad++ {
			in := strings.Repeat("a", maxEntryText-pad) + tail + strings.Repeat("z", 10)
			got := sanitizeText(in)
			if len(got) > maxEntryText || !utf8.ValidString(got) {
				t.Errorf("tail %q pad %d: %d bytes, valid %v", tail, pad, len(got), utf8.ValidString(got))
			}
			if len(got) < maxEntryText-pad {
				t.Errorf("tail %q pad %d: cut too early at %d bytes", tail, pad, len(got))
			}
		}
	}
}

func TestTailWithin(t *testing.T) {
	cases := []struct {
		in    string
		width int
		want  string
	}{
		{"hello world", 5, "world"},
		{"\U000065e5\U0000672c\U00008a9e\U000030c6\U000030ad\U000030b9\U000030c8", 5, "\U000030b9\U000030c8"},
		{"abc", 10, "abc"},
		{"abc", 0, ""},
		{"x\U00002764\U0000fe0f\U00002764\U0000fe0f", 3, "\U00002764\U0000fe0f"},
	}
	for _, c := range cases {
		if got := tailWithin(c.in, c.width); got != c.want {
			t.Errorf("tailWithin(%q, %d) = %q, want %q", c.in, c.width, got, c.want)
		}
	}

	long := strings.Repeat("\U00002764\U0000fe0f\U00000301\U00000301", 2000)
	start := time.Now()
	got := tailWithin(long, 60)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("tailWithin on %d bytes took %v", len(long), elapsed)
	}
	if w := widthOf([]rune(got)); w > 60 {
		t.Errorf("tail is %d cells wide", w)
	}
}
