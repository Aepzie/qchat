package tui

import (
	"strings"
	"unicode"

	"charm.land/lipgloss/v2"
)

// maxEntryText bounds the length of any single history entry, so pasted or
// hostile input cannot make rendering arbitrarily slow.
const maxEntryText = 8 << 10

// sanitizeText makes s safe to draw: control characters (including ESC,
// which starts terminal escape sequences) and bidirectional formatting
// characters (which can visually reorder text) are removed, tabs become
// spaces, CRLF and CR become LF, and the result is capped at maxEntryText
// bytes on a rune boundary.
func sanitizeText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var b strings.Builder
	b.Grow(min(len(s), maxEntryText))
	for _, r := range s {
		if b.Len() >= maxEntryText {
			break
		}
		switch {
		case r == '\n':
			b.WriteRune(r)
		case r == '\r':
			b.WriteByte('\n')
		case r == '\t':
			b.WriteString("    ")
		case unicode.IsControl(r), unicode.Is(unicode.Bidi_Control, r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
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
