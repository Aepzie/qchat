package tui

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

// Conversation layout.
const (
	// compactWidth is the narrowest pane that gets bubbles; narrower panes
	// draw messages as full-width compact lines.
	compactWidth = 32
	// minBubbleWidth is the smallest maximum bubble width, borders included.
	minBubbleWidth = 24
	// fadeFrames is how many animation frames a new incoming entry takes to
	// ramp from dim to full colour.
	fadeFrames = 5
	// groupWindow is how far apart two messages from the same sender may be
	// and still be drawn as one group.
	groupWindow = 5 * time.Minute
	// maxNoticeWidth bounds the width of centred system lines.
	maxNoticeWidth = 90
)

// renderOpts controls the frame-dependent parts of conversation rendering.
// The zero value draws a static conversation.
type renderOpts struct {
	// Frame is the animation frame counter. It drives the sending spinner,
	// the key change flash and the fade-in of new entries.
	Frame int
	// Animate enables frame-dependent output. Without it the output does
	// not depend on Frame: spinners are a static ◌ and nothing fades.
	Animate bool
	// Now is the reference time for the "Today" and "Yesterday" labels of
	// date separators; zero means time.Now.
	Now time.Time
	// Group shows the sender name above peer bubbles even for entries that
	// carry no sender ID.
	Group bool
}

func (o renderOpts) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

// renderConversation draws a whole conversation at width cells: bubbles,
// date separators, notices, file cards and alerts. Every line is at most
// width cells wide.
func renderConversation(st styles, entries []entry, width int, opts renderOpts) []string {
	return renderTail(st, entries, 0, width, opts)
}

// renderTail draws entries[from:] exactly as renderConversation draws them,
// including the separator before entries[from], so that a caller can keep
// the lines of entries[:from] and redraw only the tail, for example from
// firstAnimated on every animation frame.
func renderTail(st styles, entries []entry, from, width int, opts renderOpts) []string {
	if from >= len(entries) {
		return nil
	}
	from = max(from, 0)
	numbered := numberFiles(cloneEntries(entries))
	var lines []string
	lastDay := ""
	for i := from - 1; i >= 0; i-- {
		if numbered[i].kind == entryMessage {
			lastDay = dayKey(numbered[i].at)
			break
		}
	}
	for i := from; i < len(numbered); i++ {
		cur := numbered[i]
		var prev *entry
		if i > 0 {
			prev = &numbered[i-1]
		}
		if cur.kind == entryMessage && dayKey(cur.at) != lastDay {
			if i > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, dateRule(st, cur.at, width, opts))
			lastDay = dayKey(cur.at)
			prev = nil
		} else if prev != nil && needsGap(*prev, cur) {
			lines = append(lines, "")
		}
		lines = append(lines, renderEntryIn(st, cur, prev, width, opts)...)
	}
	return lines
}

// cloneEntries copies entries so that numbering files does not change the
// caller's slice.
func cloneEntries(entries []entry) []entry {
	return append([]entry(nil), entries...)
}

func dayKey(t time.Time) string { return t.Format("2006-01-02") }

// entryAnimating reports whether an entry's rendering still changes with
// the frame: a fading-in entry or a message that is being sent.
func entryAnimating(e entry, opts renderOpts) bool {
	if !opts.Animate {
		return false
	}
	if e.fresh && opts.Frame-e.arrival < fadeFrames {
		return true
	}
	return e.kind == entryMessage && e.status == StatusSending
}

// firstAnimated returns the index of the first entry whose rendering still
// changes with the frame, or len(entries) when none does.
func firstAnimated(entries []entry, opts renderOpts) int {
	for i, e := range entries {
		if entryAnimating(e, opts) {
			return i
		}
	}
	return len(entries)
}

// conversationAnimating reports whether any entry still animates, so the
// caller knows whether to keep its animation tick running.
func conversationAnimating(entries []entry, opts renderOpts) bool {
	return firstAnimated(entries, opts) < len(entries)
}

// continues reports whether cur continues a group of messages that prev
// started: same sender, same direction, same day, close in time.
func continues(prev, cur entry) bool {
	if prev.kind != entryMessage || cur.kind != entryMessage {
		return false
	}
	if prev.outgoing != cur.outgoing || prev.from != cur.from || prev.sender != cur.sender {
		return false
	}
	if dayKey(prev.at) != dayKey(cur.at) {
		return false
	}
	gap := cur.at.Sub(prev.at)
	return gap >= 0 && gap < groupWindow
}

// renderEntryIn draws one entry; prev is the entry drawn just above it, or
// nil when a separator or nothing is above it.
func renderEntryIn(st styles, e entry, prev *entry, width int, opts renderOpts) []string {
	var lines []string
	switch e.kind {
	case entryMessage:
		cont := prev != nil && continues(*prev, e)
		lines = renderBubble(st, e, cont, width, opts)
	case entryNote:
		lines = renderNote(e, width, st)
	case entryOutput:
		lines = renderOutput(e, width, st)
	case entryAlert:
		lines = renderAlert(e, width, st)
	default:
		lines = renderNotice(st, e, width)
	}
	return fadeIn(st, e, fitWidth(lines, width), opts)
}

// fitWidth guarantees that no line is wider than width.
func fitWidth(lines []string, width int) []string {
	limit := lipgloss.NewStyle().MaxWidth(max(width, 1))
	for i, l := range lines {
		if lipgloss.Width(l) > width {
			lines[i] = limit.Render(l)
		}
	}
	return lines
}

// fadeIn recolours a fresh entry from dim to full over fadeFrames frames.
// The layout does not change, only the colour.
func fadeIn(st styles, e entry, lines []string, opts renderOpts) []string {
	if !opts.Animate || !e.fresh {
		return lines
	}
	step := opts.Frame - e.arrival
	if step >= fadeFrames || step < 0 {
		return lines
	}
	style := lipgloss.NewStyle().Foreground(fadeColor(st.theme, step))
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = style.Render(stripSGR(l))
	}
	return out
}

// fadeColor is the colour of a fading entry at step 0..fadeFrames.
func fadeColor(th Theme, step int) color.Color {
	return fade(th.Faint, th.Text, step, fadeFrames)
}

// dateRule draws a centred date label between gradient rules, such as
// "──── Today ────".
func dateRule(st styles, at time.Time, width int, opts renderOpts) string {
	label := " " + dateLabel(at, opts.now()) + " "
	if lipgloss.Width(label)+2 > width {
		return st.muted.Render(truncate(strings.TrimSpace(label), width))
	}
	side := width - lipgloss.Width(label)
	left := side / 2
	return gradientRule(left, "─", st.theme.Gradient) + st.muted.Render(label) + gradientRule(side-left, "─", st.theme.Gradient)
}

// dateLabel names the day of at relative to now.
func dateLabel(at, now time.Time) string {
	at = at.In(now.Location())
	day := func(t time.Time) time.Time { return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()) }
	switch day(now).Sub(day(at)).Hours() / 24 {
	case 0:
		return "Today"
	case 1:
		return "Yesterday"
	}
	if at.Year() == now.Year() {
		return at.Format("Mon 2 Jan")
	}
	return at.Format("Mon 2 Jan 2006")
}

// renderNotice draws a system line centred and muted, with an icon that
// says what kind of line it is.
func renderNotice(st styles, e entry, width int) []string {
	icon, iconStyle, body := "•", st.faint, st.muted
	switch e.kind {
	case entryGood:
		icon, iconStyle, body = "●", st.ok, st.text
	case entryWarn:
		icon, iconStyle, body = "◌", st.warn, st.text
	case entryError:
		icon, iconStyle, body = "✕", st.danger, st.danger
	}
	box := min(width, maxNoticeWidth)
	wrapped := wrapLines(e.text, max(box-2, 1))
	indent := strings.Repeat(" ", max((width-widest(wrapped)-2)/2, 0))
	out := make([]string, len(wrapped))
	for i, l := range wrapped {
		lead := "  "
		if i == 0 {
			lead = iconStyle.Render(icon) + " "
		}
		out[i] = indent + lead + body.Render(l)
	}
	return out
}

// renderKeyChangeBanner draws the warning shown while a contact's safety
// number changed and the user has not decided again in /verify: a red
// bordered box that flashes with the frame when opts.Animate is set. name
// is the contact's sanitised label and may be empty.
func renderKeyChangeBanner(st styles, name string, width int, opts renderOpts) []string {
	th := st.theme
	name = cleanLine(name, 128)
	border := th.Danger
	if opts.Animate {
		border = pulse(th, th.Danger, opts.Frame)
	}
	title := "⚠ KEY CHANGED — verify with /verify"
	if width < 8 {
		return []string{st.danger.Bold(true).Render(truncate("⚠ /verify", width))}
	}
	inner := min(width, maxAlertWidth) - 4
	var body []string
	for _, l := range wrapLines(title, inner) {
		body = append(body, st.danger.Bold(true).Render(l))
	}
	if name != "" {
		for _, l := range wrapLines("The safety number of "+name+" changed. Compare it before trusting new messages.", inner) {
			body = append(body, st.text.Render(l))
		}
	}
	return boxLines(body, inner, lipgloss.NewStyle().Foreground(border))
}

// boxLines frames lines, each at most inner cells wide, in a rounded
// border with one cell of padding on each side.
func boxLines(lines []string, inner int, border lipgloss.Style) []string {
	edge := strings.Repeat("─", inner+2)
	out := make([]string, 0, len(lines)+2)
	out = append(out, border.Render("╭"+edge+"╮"))
	side := border.Render("│")
	for _, l := range lines {
		out = append(out, side+" "+padRight(l, inner, lipgloss.NewStyle())+" "+side)
	}
	return append(out, border.Render("╰"+edge+"╯"))
}

// widest returns the width of the widest line.
func widest(lines []string) int {
	w := 0
	for _, l := range lines {
		w = max(w, lipgloss.Width(l))
	}
	return w
}

// bubbleColors returns the fill and text colours of a message bubble.
func bubbleColors(th Theme, own bool) (fill, text color.Color) {
	if own {
		return colorOr(th.BubbleOwn, th.Highlight), colorOr(th.BubbleOwnText, th.Text)
	}
	return colorOr(th.BubblePeer, th.Surface), colorOr(th.BubblePeerText, th.Text)
}

// filledBox frames lines, each at most inner cells wide, as a rounded
// bubble filled with fill. The border is drawn in the fill colour, so the
// bubble reads as one shape. Styled lines keep the fill after every reset
// they contain. A nil fill gives a plain bordered box.
func filledBox(lines []string, inner int, fill color.Color) []string {
	if fill == nil {
		return boxLines(lines, inner, lipgloss.NewStyle())
	}
	edge := lipgloss.NewStyle().Foreground(fill)
	bg := backgroundSGR(fill)
	out := make([]string, 0, len(lines)+2)
	out = append(out, edge.Render("╭"+strings.Repeat("─", inner+2)+"╮"))
	side := edge.Render("│")
	for _, l := range lines {
		gap := strings.Repeat(" ", max(inner-lipgloss.Width(l), 0))
		out = append(out, side+bg+" "+keepBackground(l, bg)+bg+gap+" "+sgrReset+side)
	}
	return append(out, edge.Render("╰"+strings.Repeat("─", inner+2)+"╯"))
}

const sgrReset = "[m"

// backgroundSGR is the escape sequence that sets c as the background.
func backgroundSGR(c color.Color) string {
	r, g, b := rgb8(c)
	return fmt.Sprintf("[48;2;%d;%d;%dm", int(r), int(g), int(b))
}

// keepBackground re-applies the background sequence bg after every SGR
// reset in a styled line, so the bubble fill survives styled spans.
func keepBackground(line, bg string) string {
	var b strings.Builder
	for i := 0; i < len(line); {
		if line[i] != 0x1b {
			b.WriteByte(line[i])
			i++
			continue
		}
		n, sgr := escapeLength(line[i:])
		seq := line[i : i+n]
		b.WriteString(seq)
		if sgr && isReset(seq) {
			b.WriteString(bg)
		}
		i += n
	}
	return b.String()
}

// isReset reports whether an SGR sequence starts with a full reset.
func isReset(seq string) bool {
	params := strings.TrimSuffix(strings.TrimPrefix(seq, "["), "m")
	first, _, _ := strings.Cut(params, ";")
	return first == "" || first == "0" || first == "00"
}

func colorOr(c, fallback color.Color) color.Color {
	if c == nil {
		return fallback
	}
	return c
}

// senderKey is what a sender's avatar colour derives from: its identity ID
// when the entry has one, its label otherwise.
func senderKey(e entry) string {
	if e.sender != "" {
		return e.sender
	}
	return e.from
}

// renderBubble draws a message as a bubble: own messages right-aligned,
// peer messages left-aligned behind an avatar, with the time and delivery
// state below. cont marks a message that continues a group, which drops the
// sender name and avatar. Narrow panes get compact full-width lines.
func renderBubble(st styles, e entry, cont bool, width int, opts renderOpts) []string {
	if width < compactWidth {
		return renderMessage(e, width, st)
	}
	th := st.theme
	fillColor, textColor := bubbleColors(th, e.outgoing)
	gutter := 0
	avatarText := ""
	if !e.outgoing {
		avatarText = avatar(th, senderKey(e), e.from)
		gutter = lipgloss.Width(avatarText) + 1
	}
	maxBubble := min(max(width*7/10, minBubbleWidth), width-gutter)
	inner := maxBubble - 4

	var body []string
	if e.file != nil {
		body = renderFileCard(st, *e.file, e.fileNo, maxBubble)
	} else {
		content := bubbleBody(st, e.text, inner, textColor)
		body = filledBox(content, widest(content), fillColor)
	}

	var out []string
	if !e.outgoing && !cont && (opts.Group || e.sender != "") {
		name := lipgloss.NewStyle().Foreground(avatarColor(th, senderKey(e))).Bold(true)
		out = append(out, strings.Repeat(" ", gutter)+name.Render(truncate(e.from, width-gutter)))
	}
	bubbleWidth := widest(body)
	for i, l := range body {
		switch {
		case e.outgoing:
			out = append(out, strings.Repeat(" ", max(width-bubbleWidth, 0))+l)
		case i == 1 && !cont:
			out = append(out, avatarText+" "+l)
		default:
			out = append(out, strings.Repeat(" ", gutter)+l)
		}
	}

	meta := bubbleMeta(st, e, width-gutter, opts)
	if e.outgoing {
		out = append(out, strings.Repeat(" ", max(width-lipgloss.Width(meta)-1, 0))+meta)
	} else {
		out = append(out, strings.Repeat(" ", gutter+1)+meta)
	}
	if e.status == StatusFailed && e.errText != "" {
		for _, l := range wrapLines(e.errText, max(maxBubble-2, 1)) {
			line := st.danger.Render(l)
			if e.outgoing {
				out = append(out, strings.Repeat(" ", max(width-lipgloss.Width(l)-1, 0))+line)
				continue
			}
			out = append(out, strings.Repeat(" ", gutter+1)+line)
		}
	}
	return out
}

// bubbleBody renders a message body at most width cells wide: through the
// safe Markdown path when it is on and the body renders, as wrapped plain
// text in the bubble's text colour otherwise.
func bubbleBody(st styles, text string, width int, textColor color.Color) []string {
	width = max(width, 1)
	if st.markdown {
		if lines, ok := st.md.render(text, width); ok {
			return lines
		}
	}
	style := lipgloss.NewStyle().Foreground(textColor)
	lines := wrapLines(text, width)
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = style.Render(l)
	}
	return out
}

// statusMark is one marker under a bubble, in a long and a short form.
type statusMark struct {
	long, short string
}

// bubbleMeta is the line under a bubble: the time, the delivery state and
// the disappearing and clock skew markers, shortened to fit width.
func bubbleMeta(st styles, e entry, width int, opts renderOpts) string {
	marks := statusMarks(st, e, opts)
	line := st.faint.Render(e.at.Format("15:04"))
	if lipgloss.Width(line) > width {
		return ""
	}
	for _, m := range marks {
		switch {
		case lipgloss.Width(line)+1+lipgloss.Width(m.long) <= width:
			line += " " + m.long
		case lipgloss.Width(line)+1+lipgloss.Width(m.short) <= width:
			line += " " + m.short
		}
	}
	return line
}

// statusMarks lists the markers of a message: delivery state, disappearing
// timer and clock skew.
func statusMarks(st styles, e entry, opts renderOpts) []statusMark {
	var marks []statusMark
	add := func(style lipgloss.Style, long, short string) {
		marks = append(marks, statusMark{style.Render(long), style.Render(short)})
	}
	switch {
	case e.status == StatusSending:
		glyph := "◌"
		if opts.Animate {
			glyph = spinnerFrame(opts.Frame)
		}
		add(st.faint, glyph+" sending", glyph)
	case e.status == StatusSent && e.delivered:
		add(st.accent, "✓✓ delivered", "✓✓")
	case e.status == StatusSent && e.route == RouteSealed:
		add(st.accent, "✓ sealed", "✓")
	case e.status == StatusSent && e.route == RouteIdentified:
		add(st.muted, "✓ identified", "✓")
	case e.status == StatusSent:
		add(st.muted, "✓ sent", "✓")
	case e.status == StatusRecipientOffline:
		add(st.warn, "⧗ recipient offline · not delivered", "⧗ offline")
	case e.status == StatusFailed:
		add(st.danger, "✕ not sent", "✕")
	}
	if e.ttl > 0 {
		add(st.faint, "⏱ "+formatTimer(e.ttl), "⏱")
	}
	if e.skew {
		add(st.warn, "◷ sender clock off", "◷")
	}
	return marks
}
