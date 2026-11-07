package tui

import (
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// promptWidth is the width of the prompt column of the input.
const promptWidth = 2

// inputLine is a small multi-line text editor: the message input at the
// bottom of the screen. Text wraps at word boundaries; the input shows at
// most maxInputHeight rows and scrolls to keep the cursor visible.
//
// It is self-contained rather than built on bubbles/textarea, which pulls in
// a clipboard dependency this module does not carry.
type inputLine struct {
	value       []rune
	cursor      int
	width       int
	maxRunes    int
	placeholder string
	focused     bool
	offset      int
	st          styles
}

// span is one visual row: value[start:end].
type span struct{ start, end int }

func newInputLine(st styles) inputLine {
	return inputLine{
		maxRunes:    4000,
		placeholder: "Type a note or /help",
		focused:     true,
		width:       20,
		st:          st,
	}
}

// Value returns the text.
func (in *inputLine) Value() string { return string(in.value) }

// SetValue replaces the text and moves the cursor to the end.
func (in *inputLine) SetValue(s string) {
	in.value = []rune(s)
	if len(in.value) > in.maxRunes {
		in.value = in.value[:in.maxRunes]
	}
	in.cursor = len(in.value)
}

// Reset clears the text.
func (in *inputLine) Reset() {
	in.value = nil
	in.cursor = 0
	in.offset = 0
}

// Focus shows the cursor.
func (in *inputLine) Focus() { in.focused = true }

// Blur hides the cursor.
func (in *inputLine) Blur() { in.focused = false }

// SetWidth sets the total width including the prompt.
func (in *inputLine) SetWidth(w int) { in.width = max(w, promptWidth+2) }

// textWidth is the wrap width. One column is kept free so the cursor can
// sit after the last character of a full row.
func (in *inputLine) textWidth() int { return in.width - promptWidth - 1 }

// Height returns the number of rows the input occupies.
func (in *inputLine) Height() int {
	return min(len(in.rows()), maxInputHeight)
}

// rows splits the value into visual rows, wrapping at spaces where
// possible and breaking long words otherwise. Explicit newlines start a new
// row and are not part of any span.
func (in *inputLine) rows() []span {
	limit := max(in.textWidth(), 1)
	var out []span
	start, used, lastSpace := 0, 0, -1
	for i := 0; i < len(in.value); i++ {
		r := in.value[i]
		if r == '\n' {
			out = append(out, span{start, i})
			start, used, lastSpace = i+1, 0, -1
			continue
		}
		w := runeWidth(r)
		if used+w > limit && i > start {
			breakAt := i
			if lastSpace >= start {
				breakAt = lastSpace + 1
			}
			out = append(out, span{start, breakAt})
			start = breakAt
			used = widthOf(in.value[start:i])
			lastSpace = -1
			for j := start; j < i; j++ {
				if in.value[j] == ' ' {
					lastSpace = j
				}
			}
			if used+w > limit && i > start {
				out = append(out, span{start, i})
				start, used, lastSpace = i, 0, -1
			}
		}
		if r == ' ' {
			lastSpace = i
		}
		used += w
	}
	return append(out, span{start, len(in.value)})
}

// cursorRow returns the index of the row holding the cursor and the
// cursor's column within it.
func (in *inputLine) cursorRow(rows []span) (int, int) {
	for i, r := range rows {
		last := i == len(rows)-1
		if in.cursor >= r.start && (in.cursor < r.end || (in.cursor == r.end && (last || rows[i+1].start > r.end))) {
			return i, widthOf(in.value[r.start:in.cursor])
		}
	}
	last := len(rows) - 1
	return last, widthOf(in.value[rows[last].start:rows[last].end])
}

// Update applies a key press or paste. It reports whether the text
// changed.
func (in *inputLine) Update(msg tea.Msg) bool {
	switch msg := msg.(type) {
	case tea.PasteMsg:
		return in.insert(cleanPaste(msg.Content))
	case tea.KeyPressMsg:
		return in.handleKey(msg)
	}
	return false
}

func (in *inputLine) handleKey(msg tea.KeyPressMsg) bool {
	switch msg.String() {
	case "shift+enter", "alt+enter", "ctrl+j":
		return in.insert("\n")
	case "backspace", "ctrl+h", "shift+backspace":
		return in.deleteRange(in.cursor-1, in.cursor)
	case "delete", "ctrl+d":
		return in.deleteRange(in.cursor, in.cursor+1)
	case "ctrl+w", "alt+backspace", "ctrl+backspace":
		return in.deleteRange(in.wordLeft(), in.cursor)
	case "alt+d", "ctrl+delete":
		return in.deleteRange(in.cursor, in.wordRight())
	case "ctrl+u":
		return in.deleteRange(in.lineStart(), in.cursor)
	case "ctrl+k":
		return in.deleteRange(in.cursor, in.lineEnd())
	case "left", "ctrl+b":
		in.cursor = max(in.cursor-1, 0)
	case "right", "ctrl+f":
		in.cursor = min(in.cursor+1, len(in.value))
	case "alt+left", "ctrl+left", "alt+b":
		in.cursor = in.wordLeft()
	case "alt+right", "ctrl+right", "alt+f":
		in.cursor = in.wordRight()
	case "home", "ctrl+a":
		in.cursor = in.lineStart()
	case "end", "ctrl+e":
		in.cursor = in.lineEnd()
	case "up":
		in.moveVertical(-1)
	case "down":
		in.moveVertical(1)
	default:
		k := msg.Key()
		if k.Text == "" || k.Mod&(tea.ModCtrl|tea.ModAlt|tea.ModMeta|tea.ModSuper|tea.ModHyper) != 0 {
			return false
		}
		return in.insert(k.Text)
	}
	return false
}

// insert adds text at the cursor, dropping control characters and anything
// beyond the length limit.
func (in *inputLine) insert(s string) bool {
	var add []rune
	for _, r := range s {
		if r == '\t' {
			r = ' '
		}
		if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r)) {
			continue
		}
		add = append(add, r)
	}
	add = add[:min(len(add), in.maxRunes-len(in.value))]
	if len(add) == 0 {
		return false
	}
	in.value = append(in.value[:in.cursor], append(add, in.value[in.cursor:]...)...)
	in.cursor += len(add)
	return true
}

// deleteRange removes value[from:to], clamped to the text.
func (in *inputLine) deleteRange(from, to int) bool {
	from, to = max(from, 0), min(to, len(in.value))
	if from >= to {
		return false
	}
	in.value = append(in.value[:from], in.value[to:]...)
	in.cursor = from
	return true
}

func (in *inputLine) wordLeft() int {
	i := in.cursor
	for i > 0 && unicode.IsSpace(in.value[i-1]) {
		i--
	}
	for i > 0 && !unicode.IsSpace(in.value[i-1]) {
		i--
	}
	return i
}

func (in *inputLine) wordRight() int {
	i := in.cursor
	for i < len(in.value) && unicode.IsSpace(in.value[i]) {
		i++
	}
	for i < len(in.value) && !unicode.IsSpace(in.value[i]) {
		i++
	}
	return i
}

func (in *inputLine) lineStart() int {
	i := in.cursor
	for i > 0 && in.value[i-1] != '\n' {
		i--
	}
	return i
}

func (in *inputLine) lineEnd() int {
	i := in.cursor
	for i < len(in.value) && in.value[i] != '\n' {
		i++
	}
	return i
}

// moveVertical moves the cursor to the same column of an adjacent row.
func (in *inputLine) moveVertical(delta int) {
	rows := in.rows()
	row, col := in.cursorRow(rows)
	target := row + delta
	if target < 0 || target >= len(rows) {
		return
	}
	r := rows[target]
	pos, used := r.start, 0
	for pos < r.end && used+runeWidth(in.value[pos]) <= col {
		used += runeWidth(in.value[pos])
		pos++
	}
	in.cursor = pos
}

// View renders exactly Height() rows, each at most width cells wide.
func (in *inputLine) View() string {
	st := in.st
	prompt := st.accent.Bold(true).Render("›") + " "
	if !in.focused {
		prompt = st.faint.Render("›") + " "
	}
	cursorStyle := lipgloss.NewStyle().Background(st.theme.Accent).Foreground(st.theme.OnAccent)
	textStyle := st.text
	if !in.focused {
		textStyle = st.muted
	}

	if len(in.value) == 0 {
		ph := truncate(in.placeholder, in.textWidth())
		if !in.focused {
			return prompt + st.faint.Render(ph)
		}
		first, rest := splitFirst(ph)
		return prompt + cursorStyle.Render(first) + st.faint.Render(rest)
	}

	rows := in.rows()
	row, _ := in.cursorRow(rows)
	height := min(len(rows), maxInputHeight)
	if row < in.offset {
		in.offset = row
	}
	if row >= in.offset+height {
		in.offset = row - height + 1
	}
	in.offset = min(in.offset, len(rows)-height)

	lines := make([]string, 0, height)
	for i := in.offset; i < in.offset+height; i++ {
		r := rows[i]
		p := "  "
		if i == 0 {
			p = prompt
		}
		text := in.value[r.start:r.end]
		if !in.focused || i != row {
			lines = append(lines, p+textStyle.Render(string(text)))
			continue
		}
		at := in.cursor - r.start
		under := " "
		after := ""
		if at < len(text) {
			under = string(text[at])
			after = string(text[at+1:])
		}
		lines = append(lines, p+textStyle.Render(string(text[:at]))+cursorStyle.Render(under)+textStyle.Render(after))
	}
	return strings.Join(lines, "\n")
}

// splitFirst splits off the first rune of s.
func splitFirst(s string) (string, string) {
	for i := range s {
		if i > 0 {
			return s[:i], s[i:]
		}
	}
	return s, ""
}

// cleanPaste normalises pasted text: CRLF and CR become LF.
func cleanPaste(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

func runeWidth(r rune) int { return lipgloss.Width(string(r)) }

func widthOf(rs []rune) int {
	n := 0
	for _, r := range rs {
		n += runeWidth(r)
	}
	return n
}
