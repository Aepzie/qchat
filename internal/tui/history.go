package tui

import (
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/transport"
)

// maxEntries bounds the history kept in memory; the oldest entries go first.
const maxEntries = 2000

// entryKind selects how a history entry is drawn.
type entryKind uint8

const (
	entrySystem entryKind = iota
	entryGood
	entryWarn
	entryError
	entryNote
	entryOutput
	entryAlert
	entryMessage
)

// row is one labelled line of command output. A value may span several
// lines separated by "\n".
type row struct {
	key   string
	value string
}

// entry is one item in the history pane. All text is sanitized when the
// entry is created.
type entry struct {
	at    time.Time
	kind  entryKind
	text  string
	title string
	rows  []row
	alert client.SecurityAlert
	addr  string

	// Message fields, used by entryMessage.
	from     string
	msgID    string
	outgoing bool
	status   MessageStatus
	errText  string
	skew     bool
	route    SendRoute
	// sender is the identity ID behind an entry under Message requests.
	sender string
}

// Layout of a history line: "15:04:05" + two spaces, then a one-cell marker
// and a space, then the body.
const (
	timestampWidth = 8
	noteIndent     = timestampWidth + 2
	bodyIndent     = noteIndent + 2
	maxAlertWidth  = 84
)

// standsAlone reports whether an entry is set off from its neighbours by a
// blank line.
func (e entry) standsAlone() bool {
	return e.kind == entryNote || e.kind == entryOutput || e.kind == entryAlert
}

// needsGap reports whether a blank line separates two adjacent entries.
// Consecutive messages from the same sender stay together.
func needsGap(prev, cur entry) bool {
	if prev.kind == entryMessage && cur.kind == entryMessage {
		return prev.outgoing != cur.outgoing || prev.from != cur.from
	}
	return cur.standsAlone() || prev.standsAlone() || cur.kind == entryMessage || prev.kind == entryMessage
}

// separator returns the lines drawn between two adjacent entries: a date
// divider when the day changes, a blank line, or nothing.
func separator(prev, cur entry, width int, st styles) []string {
	py, pm, pd := prev.at.Date()
	cy, cm, cd := cur.at.Date()
	if py != cy || pm != cm || pd != cd {
		label := "── " + cur.at.Format("Mon 2 Jan 2006") + " "
		rule := max(min(width, 48)-lipgloss.Width(label), 0)
		return []string{"", st.faint.Render(truncate(label+strings.Repeat("─", rule), width))}
	}
	if needsGap(prev, cur) {
		return []string{""}
	}
	return nil
}

// renderEntries draws the whole history at the given width.
func renderEntries(entries []entry, width int, st styles) []string {
	var lines []string
	for i, e := range entries {
		if i > 0 {
			lines = append(lines, separator(entries[i-1], e, width, st)...)
		}
		lines = append(lines, renderEntry(e, width, st)...)
	}
	return lines
}

func renderEntry(e entry, width int, st styles) []string {
	switch e.kind {
	case entryNote:
		return renderNote(e, width, st)
	case entryOutput:
		return renderOutput(e, width, st)
	case entryAlert:
		return renderAlert(e, width, st)
	case entryMessage:
		return renderMessage(e, width, st)
	default:
		return renderLine(e, width, st)
	}
}

func timestamp(e entry, st styles) string {
	return st.faint.Render(e.at.Format("15:04:05"))
}

// renderLine draws a one-paragraph system message with a colored marker.
func renderLine(e entry, width int, st styles) []string {
	marker, body := st.faint.Render("•"), st.muted
	switch e.kind {
	case entryGood:
		marker, body = st.ok.Render("●"), st.text
	case entryWarn:
		marker, body = st.warn.Render("◌"), st.text
	case entryError:
		marker, body = st.danger.Render("✕"), st.danger
	}
	indent := strings.Repeat(" ", bodyIndent)
	var out []string
	for i, line := range wrapLines(e.text, width-bodyIndent) {
		if i == 0 {
			out = append(out, timestamp(e, st)+"  "+marker+" "+body.Render(line))
			continue
		}
		out = append(out, indent+body.Render(line))
	}
	return out
}

// renderNote draws a note the user typed. Notes are never transmitted, and
// the label says so.
func renderNote(e entry, width int, st styles) []string {
	out := []string{timestamp(e, st) + "  " + st.accent.Bold(true).Render("you") + "  " + st.faint.Render("local · not sent")}
	indent := strings.Repeat(" ", noteIndent)
	for _, line := range wrapLines(e.text, width-noteIndent) {
		out = append(out, indent+st.text.Render(line))
	}
	return out
}

// renderMessage draws a message: a header with time, sender and delivery
// status, then the body.
func renderMessage(e entry, width int, st styles) []string {
	name := st.bold.Render(truncate(e.from, max(width/3, 8)))
	if e.outgoing {
		name = st.accent.Bold(true).Render("you")
	}
	head := timestamp(e, st) + "  " + name
	for _, meta := range messageMeta(e, st) {
		if lipgloss.Width(head)+2+lipgloss.Width(meta) <= width {
			head += "  " + meta
			break
		}
	}
	out := []string{head}
	indent := strings.Repeat(" ", noteIndent)
	for _, line := range renderBody(e.text, width-noteIndent, st) {
		out = append(out, indent+line)
	}
	if e.status == StatusFailed && e.errText != "" {
		for _, line := range wrapLines(e.errText, width-noteIndent) {
			out = append(out, indent+st.danger.Render(line))
		}
	}
	return out
}

// messageMeta returns the status and clock-skew markers of a message, from
// the most to the least descriptive form.
func messageMeta(e entry, st styles) []string {
	var long, short []string
	switch e.status {
	case StatusSending:
		long, short = append(long, st.faint.Render("… sending")), append(short, st.faint.Render("…"))
	case StatusSent:
		switch e.route {
		case RouteSealed:
			long, short = append(long, st.muted.Render("✓ sent sealed · relay does not know the sender")), append(short, st.muted.Render("✓ sealed"))
		case RouteIdentified:
			long, short = append(long, st.warn.Render("✓ sent identified · relay knows the sender")), append(short, st.warn.Render("✓ identified"))
		default:
			long, short = append(long, st.muted.Render("✓ sent · stored by relay until delivered")), append(short, st.muted.Render("✓ sent"))
		}
	case StatusRecipientOffline:
		long, short = append(long, st.warn.Render("⧗ recipient offline · not delivered")), append(short, st.warn.Render("⧗ offline"))
	case StatusFailed:
		long, short = append(long, st.danger.Render("✕ not sent")), append(short, st.danger.Render("✕"))
	}
	if e.skew {
		long, short = append(long, st.warn.Render("◷ sender clock off")), append(short, st.warn.Render("◷"))
	}
	if len(long) == 0 {
		return nil
	}
	return []string{strings.Join(long, "  "), strings.Join(short, " ")}
}

// renderOutput draws command output: a title and aligned key/value rows.
func renderOutput(e entry, width int, st styles) []string {
	out := []string{timestamp(e, st) + "  " + st.accent.Render("▸") + " " + st.bold.Render(e.title)}
	keyWidth := 0
	for _, r := range e.rows {
		keyWidth = max(keyWidth, lipgloss.Width(r.key))
	}
	valueIndent := bodyIndent + keyWidth + 2
	if width-valueIndent < 16 {
		valueIndent = bodyIndent + 2
	}
	pad := strings.Repeat(" ", valueIndent)
	for _, r := range e.rows {
		key := strings.Repeat(" ", bodyIndent) + st.muted.Render(r.key)
		values := wrapValue(r.value, width-valueIndent)
		if bodyIndent+lipgloss.Width(r.key)+2 > valueIndent {
			out = append(out, key)
		} else {
			first := values[0]
			values = values[1:]
			gap := valueIndent - bodyIndent - lipgloss.Width(r.key)
			out = append(out, key+strings.Repeat(" ", gap)+st.text.Render(first))
		}
		for _, v := range values {
			out = append(out, pad+st.text.Render(v))
		}
	}
	if e.text != "" {
		for _, line := range wrapLines(e.text, width-bodyIndent) {
			out = append(out, strings.Repeat(" ", bodyIndent)+st.faint.Render(line))
		}
	}
	return out
}

// wrapValue wraps each "\n"-separated line of a value.
func wrapValue(v string, width int) []string {
	var out []string
	for _, line := range strings.Split(v, "\n") {
		out = append(out, wrapLines(line, width)...)
	}
	return out
}

// renderAlert draws a security alert as a red bordered box spanning the
// pane, so it cannot be mistaken for routine output.
func renderAlert(e entry, width int, st styles) []string {
	boxWidth := min(width, maxAlertWidth)
	inner := max(boxWidth-4, 8)

	var body []string
	add := func(style lipgloss.Style, text string) {
		for _, line := range wrapLines(text, inner) {
			body = append(body, style.Render(line))
		}
	}
	add(st.alertTitle, "⚠ Server key mismatch · connection blocked")
	add(st.faint, e.at.Format("15:04:05")+" · "+e.addr)
	body = append(body, "")
	add(st.text, "The server presented a public key that does not match the pinned fingerprint. "+
		"This is what a machine-in-the-middle attack looks like; it can also mean the operator replaced the server key.")
	body = append(body, "")
	body = append(body, fingerprintBlock("expected", e.alert.Expected, inner, st)...)
	body = append(body, fingerprintBlock("presented", e.alert.Presented, inner, st)...)
	body = append(body, "")
	add(st.text, "qchat will not reconnect. Confirm the new fingerprint with the server operator over a channel you trust before changing your pin.")

	for i, line := range body {
		body[i] = padRight(line, inner, lipgloss.NewStyle())
	}
	box := st.alertBox.Render(strings.Join(body, "\n"))
	return strings.Split(box, "\n")
}

// fingerprintBlock renders a labelled fingerprint, with the label beside the
// hex groups when there is room and above them otherwise.
func fingerprintBlock(label string, fp transport.Fingerprint, width int, st styles) []string {
	const labelWidth = 11
	if fp.IsZero() {
		return []string{st.muted.Render(padPlain(label, labelWidth)) + st.faint.Render("unknown")}
	}
	if width-labelWidth >= groupsWidth(4) {
		groups := fingerprintLines(fp, width-labelWidth)
		out := make([]string, 0, len(groups))
		for i, g := range groups {
			prefix := strings.Repeat(" ", labelWidth)
			if i == 0 {
				prefix = st.muted.Render(padPlain(label, labelWidth))
			}
			out = append(out, prefix+st.text.Render(g))
		}
		return out
	}
	out := []string{st.muted.Render(label)}
	for _, g := range fingerprintLines(fp, width) {
		out = append(out, st.text.Render(g))
	}
	return out
}

// fingerprintLines splits a fingerprint's grouped form into lines of 8, 4,
// 2 or 1 groups, whichever is the widest that fits.
func fingerprintLines(fp transport.Fingerprint, width int) []string {
	groups := strings.Fields(fp.Grouped())
	per := 1
	for _, n := range []int{8, 4, 2} {
		if groupsWidth(n) <= width {
			per = n
			break
		}
	}
	var out []string
	for i := 0; i < len(groups); i += per {
		out = append(out, strings.Join(groups[i:min(i+per, len(groups))], " "))
	}
	return out
}

// groupsWidth is the width of n space-separated 4-digit groups.
func groupsWidth(n int) int { return n*5 - 1 }

// shortFingerprint returns the first four groups of a fingerprint.
func shortFingerprint(fp transport.Fingerprint) string {
	groups := strings.Fields(fp.Grouped())
	return strings.Join(groups[:min(4, len(groups))], " ")
}

func padPlain(s string, width int) string {
	if gap := width - lipgloss.Width(s); gap > 0 {
		return s + strings.Repeat(" ", gap)
	}
	return s
}
