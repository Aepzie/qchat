package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/craguS/qchat/internal/client"
)

// Layout constants.
const (
	sidebarWidth    = 24
	sidebarMinTotal = 70
	maxPaletteRows  = 5
	maxInputHeight  = 3
)

// dims is the computed layout for the current terminal size.
type dims struct {
	tooSmall bool
	sidebarW int
	mainW    int
	bodyH    int
	inputH   int
	paletteH int
	historyH int
}

// dims computes the layout. Every row of the body is accounted for:
// header + history + palette + separator + input == bodyH.
func (m *Model) dims() dims {
	d := dims{}
	if m.width < MinWidth || m.height < MinHeight {
		d.tooSmall = true
		return d
	}
	if m.width >= sidebarMinTotal {
		d.sidebarW = sidebarWidth
	}
	d.mainW = m.width - d.sidebarW
	d.bodyH = m.height - 2
	d.inputH = min(max(m.input.Height(), 1), maxInputHeight)
	if matches, open := m.paletteMatches(); open {
		d.paletteH = min(max(len(matches), 1), maxPaletteRows)
	}
	room := d.bodyH - 2 - d.inputH
	d.paletteH = min(d.paletteH, max(room-1, 0))
	d.historyH = room - d.paletteH
	return d
}

// historyWidth is the width available to history lines, or 0 before the
// terminal size is known.
func (m *Model) historyWidth() int {
	d := m.dims()
	if d.tooSmall {
		return 0
	}
	return d.mainW - 2
}

// layout applies the current terminal size to the child components.
func (m *Model) layout() {
	if m.mode != ModeInsert {
		m.completionBase = ""
	}
	d := m.dims()
	if d.tooSmall {
		return
	}
	m.input.SetWidth(d.mainW - 2)
	d = m.dims()
	m.history.SetWidth(d.mainW - 2)
	m.history.SetHeight(d.historyH)
	m.syncHistory()
}

// View implements tea.Model. The program runs in the alternate screen with
// mouse wheel reporting enabled.
func (m Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.WindowTitle = "qchat"
	return v
}

// render draws the whole screen as a string of exactly the terminal size.
func (m Model) render() string {
	if m.width <= 0 || m.height <= 0 {
		return ""
	}
	d := m.dims()
	if d.tooSmall {
		return m.renderTooSmall()
	}
	sidebar := m.renderSidebar(d)
	main := m.renderMain(d)
	lines := make([]string, 0, m.height)
	lines = append(lines, m.renderStatus(m.width))
	for i := 0; i < d.bodyH; i++ {
		line := main[i]
		if d.sidebarW > 0 {
			line = sidebar[i] + line
		}
		lines = append(lines, line)
	}
	lines = append(lines, m.renderFooter(m.width))
	return clamp(strings.Join(lines, "\n"), m.width, m.height)
}

func (m Model) renderTooSmall() string {
	var lines []string
	for _, l := range wrapLines(fmt.Sprintf("Terminal too small (need %d×%d)", MinWidth, MinHeight), m.width) {
		lines = append(lines, m.st.bold.Render(l))
	}
	for _, l := range wrapLines(fmt.Sprintf("current size %d×%d", m.width, m.height), m.width) {
		lines = append(lines, m.st.muted.Render(l))
	}
	box := lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, strings.Join(lines, "\n"))
	return clamp(box, m.width, m.height)
}

// statusSegment is one optional piece of the status bar. Segments with a
// lower priority are dropped first when space runs out.
type statusSegment struct {
	text     string
	priority int
}

func (m Model) renderStatus(width int) string {
	st := m.st
	t := st.theme
	segments := []statusSegment{
		{st.barBrand.Render("qchat"), 100},
		{m.stateSegment(), 99},
	}
	if m.conn.state == client.Connected {
		segments = append(segments, statusSegment{st.barMuted.Render("🔒 TLS 1.3 · PQ-hybrid"), 40})
	}
	segments = append(segments,
		statusSegment{st.barFaint.Render("pin ") + st.barMuted.Render(shortFingerprint(m.cfg.Pin)), 20},
		statusSegment{st.barFaint.Render("Tor: ") + st.barMuted.Render(onOff(m.cfg.Tor)), 10},
	)
	if m.conn.state == client.Connected && m.conn.hasRTT {
		segments = append(segments, statusSegment{st.bar.Foreground(t.Text).Render(formatRTT(m.conn.rtt)), 30})
	}
	right := st.barBadge.Render(" E2E: not yet ")
	sep := st.bar.Render("  ")
	lead := st.bar.Render(" ")

	join := func(segs []statusSegment) string {
		parts := make([]string, len(segs))
		for i, s := range segs {
			parts[i] = s.text
		}
		return lead + strings.Join(parts, sep)
	}
	left := join(segments)
	for lipgloss.Width(left)+1+lipgloss.Width(right) > width && len(segments) > 2 {
		drop := 0
		for i, s := range segments {
			if s.priority < segments[drop].priority {
				drop = i
			}
		}
		segments = append(segments[:drop], segments[drop+1:]...)
		left = join(segments)
	}
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return padRight(left, width, st.bar)
	}
	return left + st.bar.Render(strings.Repeat(" ", gap)) + right
}

func (m Model) stateSegment() string {
	st := m.st
	t := st.theme
	switch {
	case m.conn.blocked:
		return st.bar.Foreground(t.Danger).Bold(true).Render("✕ key mismatch")
	case m.conn.state == client.Connected:
		return st.bar.Foreground(t.Success).Render("●") + st.bar.Render(" connected")
	case m.conn.state == client.Connecting:
		return st.bar.Foreground(t.Warning).Render("◌ connecting")
	case m.conn.state == client.Disconnected:
		return st.bar.Foreground(t.Danger).Render("✕ disconnected")
	case m.conn.state == client.Failed:
		return st.bar.Foreground(t.Danger).Render("✕ stopped")
	default:
		return st.barFaint.Render("◌ starting")
	}
}

func (m Model) renderFooter(width int) string {
	st := m.st
	pill := st.pillInsert.Render(" INSERT ")
	hints := "enter send · esc normal · tab complete · /help"
	if m.mode == ModeNormal {
		pill = st.pillNormal.Render(" NORMAL ")
		hints = "i insert · j/k scroll · ctrl+d/u page · g/G ends · : command · q quit"
	}
	right := st.barFaint.Render("notes stay local ")
	room := width - lipgloss.Width(pill) - 2 - lipgloss.Width(right)
	if room < 24 {
		right = ""
		room = width - lipgloss.Width(pill) - 2
	}
	left := pill + st.bar.Render("  ") + st.barFaint.Render(truncate(hints, max(room-1, 0)))
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 0 {
		return padRight(left, width, st.bar)
	}
	return left + st.bar.Render(strings.Repeat(" ", gap)) + right
}

// renderSidebar draws the conversation list, exactly d.bodyH lines of
// d.sidebarW cells, the last column being the border.
func (m Model) renderSidebar(d dims) []string {
	if d.sidebarW == 0 {
		return nil
	}
	st := m.st
	inner := d.sidebarW - 1
	plain := lipgloss.NewStyle()
	lines := []string{"", "  " + st.sidebarTitle.Render("CONVERSATIONS"), ""}
	for i, c := range m.conversations {
		lines = append(lines, m.renderConversation(c, i == m.selected, inner))
	}
	lines = append(lines, "")
	for _, l := range wrapLines("Contacts arrive in v0.2", inner-4) {
		lines = append(lines, "  "+st.faint.Italic(true).Render(l))
	}
	out := make([]string, d.bodyH)
	edge := st.border.Render("│")
	for i := range out {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		out[i] = padRight(line, inner, plain) + edge
	}
	return out
}

func (m Model) renderConversation(c conversation, selected bool, width int) string {
	st := m.st
	badge, badgeW := "", 0
	if c.unread > 0 {
		label := fmt.Sprintf(" %d ", min(c.unread, 999))
		badgeW = lipgloss.Width(label)
		if selected {
			badge = st.unread.Render(label)
		} else {
			badge = st.accent.Bold(true).Render(label)
		}
	}
	nameW := max(width-3-badgeW, 1)
	name := truncate(sanitizeText(c.name), nameW)
	if selected {
		body := st.rowSelected.Render(padPlain(" "+name, width-1-badgeW))
		return st.rowMarker.Render("▌") + body + badge
	}
	return padRight("  "+st.muted.Render(name), width-badgeW, lipgloss.NewStyle()) + badge
}

// renderMain draws the right pane, exactly d.bodyH lines of d.mainW cells.
func (m Model) renderMain(d dims) []string {
	st := m.st
	plain := lipgloss.NewStyle()
	fit := func(s string) string { return padRight(" "+s, d.mainW, plain) }

	lines := make([]string, 0, d.bodyH)
	lines = append(lines, m.renderHeader(d.mainW))

	history := strings.Split(m.history.View(), "\n")
	for i := 0; i < d.historyH; i++ {
		line := ""
		if i < len(history) {
			line = history[i]
		}
		lines = append(lines, fit(line))
	}
	for _, p := range m.renderPalette(d) {
		lines = append(lines, fit(p))
	}
	lines = append(lines, st.border.Render(strings.Repeat("─", d.mainW)))

	input := strings.Split(m.input.View(), "\n")
	for i := 0; i < d.inputH; i++ {
		line := ""
		if i < len(input) {
			line = input[i]
		}
		lines = append(lines, fit(line))
	}
	return lines
}

func (m Model) renderHeader(width int) string {
	st := m.st
	title := " " + st.bold.Render("# System")
	sub := st.faint.Render("  connection log and local notes")
	hint := ""
	if !m.history.AtBottom() {
		hint = st.accent.Render("↓ newer below") + " "
	}
	room := width - lipgloss.Width(title) - lipgloss.Width(hint)
	if lipgloss.Width(sub) > room-1 {
		sub = ""
	}
	return padRight(title+sub, width-lipgloss.Width(hint), lipgloss.NewStyle()) + hint
}

// renderPalette draws the command palette rows, or nothing if it is closed.
func (m Model) renderPalette(d dims) []string {
	if d.paletteH == 0 {
		return nil
	}
	st := m.st
	matches, _ := m.paletteMatches()
	if len(matches) == 0 {
		return []string{st.faint.Render(truncate("  no matching command · /help lists them", d.mainW-2))}
	}
	sel := clampIndex(m.paletteSel, len(matches))
	start := 0
	if sel >= d.paletteH {
		start = sel - d.paletteH + 1
	}
	width := d.mainW - 2
	var out []string
	for i := start; i < len(matches) && len(out) < d.paletteH; i++ {
		c := matches[i]
		text := truncate(fmt.Sprintf("  %-13s %s", c.name, c.summary), width)
		if i == sel {
			out = append(out, st.paletteSel.Render(padPlain(text, width)))
			continue
		}
		out = append(out, st.palette.Render(text))
	}
	return out
}
