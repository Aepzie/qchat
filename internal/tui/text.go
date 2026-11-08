package tui

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"charm.land/lipgloss/v2"
)

// maxEntryText bounds the length of any single history entry, so pasted or
// hostile input cannot make rendering arbitrarily slow.
const maxEntryText = 8 << 10

// tabSpaces is what a tab becomes in sanitised text.
const tabSpaces = "    "

// sanitizeText makes s safe to draw: control characters (including ESC,
// which starts terminal escape sequences), bidirectional formatting
// characters (which can visually reorder text) and other invisible format
// characters are removed (see drawableRune), tabs become spaces, CRLF and CR
// become LF, and the result is capped at exactly maxEntryText bytes on a
// rune boundary. Invalid UTF-8 becomes U+FFFD.
func sanitizeText(s string) string {
	var b strings.Builder
	b.Grow(min(len(s), maxEntryText))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == '\r':
			r = '\n'
			if i < len(s) && s[i] == '\n' {
				i++
			}
		case r == '\n':
		case r == '\t':
			if b.Len()+len(tabSpaces) > maxEntryText {
				return b.String()
			}
			b.WriteString(tabSpaces)
			continue
		case !drawableRune(r):
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxEntryText {
			return b.String()
		}
		b.WriteRune(r)
	}
	return b.String()
}

// drawableRune reports whether r may reach the terminal. It rejects control
// characters, bidirectional formatting characters, line and paragraph
// separators, tag characters and every other format (Cf) character except
// the zero width joiner, which emoji sequences need. Variation selectors are
// nonspacing marks, not format characters, so they are kept.
func drawableRune(r rune) bool {
	switch {
	case r == 0x200d:
		return true
	case r == 0x2028, r == 0x2029, r >= 0xe0000 && r <= 0xe007f:
		return false
	case unicode.IsControl(r), unicode.Is(unicode.Bidi_Control, r), unicode.Is(unicode.Cf, r):
		return false
	}
	return true
}

// wrapLines wraps plain text to width cells, breaking words longer than a
// line, and returns the lines. Width is measured with lipgloss, so wide
// runes and emoji are accounted for.
func wrapLines(s string, width int) []string {
	width = max(width, 1)
	if s == "" {
		return []string{""}
	}
	return strings.Split(lipgloss.Wrap(s, width, ""), "\n")
}

// truncate shortens plain text to at most width cells, ending it with an
// ellipsis when something was cut.
func truncate(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		w := lipgloss.Width(string(r))
		if used+w > width-1 {
			break
		}
		b.WriteRune(r)
		used += w
	}
	b.WriteString("…")
	return b.String()
}

// padRight pads styled text with spaces, drawn in style, up to width cells.
func padRight(s string, width int, style lipgloss.Style) string {
	gap := width - lipgloss.Width(s)
	if gap <= 0 {
		return s
	}
	return s + style.Render(strings.Repeat(" ", gap))
}

// clamp guarantees that s has at most height lines, none wider than width
// cells. It is the last step of every render, a safety net against layout
// arithmetic mistakes.
func clamp(s string, width, height int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	limit := lipgloss.NewStyle().MaxWidth(width)
	for i, line := range lines {
		if lipgloss.Width(line) > width {
			lines[i] = limit.Render(line)
		}
	}
	return strings.Join(lines, "\n")
}
