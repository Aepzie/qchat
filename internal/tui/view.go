package tui

import (
	"fmt"
	"slices"
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
	bannerH  int
	inputH   int
	paletteH int
	historyH int
}

// dims computes the layout. Every row of the body is accounted for:
// header + banner + history + palette + separator + input == bodyH.
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
	if m.confirm.active {
		d.inputH = 1
	}
	if matches, open := m.paletteMatches(); open {
		d.paletteH = min(max(len(matches), 1), maxPaletteRows)
	}
	room := d.bodyH - 2 - d.inputH
	d.bannerH = len(m.renderBanner(d.mainW, room))
	room -= d.bannerH
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
		return renderTooSmall(m.st, m.width, m.height, MinWidth, MinHeight)
	}
	lines := make([]string, 0, m.height)
	lines = append(lines, m.renderStatus(m.width))
	if m.overlay.kind != overlayNone {
		lines = append(lines, m.renderOverlay(m.width, d.bodyH)...)
	} else {
		sidebar := m.renderSidebar(d)
		main := m.renderMain(d)
		for i := 0; i < d.bodyH; i++ {
			line := main[i]
			if d.sidebarW > 0 {
				line = sidebar[i] + line
			}
			lines = append(lines, line)
		}
	}
	lines = append(lines, m.renderFooter(m.width))
	return clamp(strings.Join(lines, "\n"), m.width, m.height)
}

// renderTooSmall draws the notice shown when the terminal is smaller than
// minW×minH.
func renderTooSmall(st styles, width, height, minW, minH int) string {
	var lines []string
	for _, l := range wrapLines(fmt.Sprintf("Terminal too small (need %d×%d)", minW, minH), width) {
		lines = append(lines, st.bold.Render(l))
	}
	for _, l := range wrapLines(fmt.Sprintf("current size %d×%d", width, height), width) {
		lines = append(lines, st.muted.Render(l))
	}
	box := lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, strings.Join(lines, "\n"))
	return clamp(box, width, height)
}

// statusSegment is one optional piece of the status bar. Segments with a
// lower priority are dropped first when space runs out.
type statusSegment struct {
	text     string
	priority int
}

// e2eBadges returns the end-to-end encryption badge, longest form first.
// Messages are protected by sessions with forward secrecy (Phase 3).
func e2eBadges(enabled bool) []string {
	if !enabled {
		return []string{" E2E: off "}
	}
	return []string{" E2E · forward secrecy ", " E2E · FS ", " E2E "}
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
	if m.hasSelf && m.self.ShortID != "" {
		segments = append(segments, statusSegment{st.barFaint.Render("id ") + st.barMuted.Render(m.self.ShortID), 25})
	}
	sep := st.bar.Render("  ")
	lead := st.bar.Render(" ")
	join := func(segs []statusSegment) string {
		parts := make([]string, len(segs))
		for i, s := range segs {
			parts[i] = s.text
		}
		return lead + strings.Join(parts, sep)
	}
	fit := func(right string) (string, bool) {
		segs := slices.Clone(segments)
		left := join(segs)
		lost := false
		for lipgloss.Width(left)+1+lipgloss.Width(right) > width && len(segs) > 2 {
			drop := 0
			for i, s := range segs {
				if s.priority < segs[drop].priority {
					drop = i
				}
			}
			lost = lost || segs[drop].priority >= 30
			segs = slices.Delete(segs, drop, drop+1)
			left = join(segs)
		}
		return left, !lost
	}

	badges := e2eBadges(m.cfg.Backend != nil)
	var left, right string
	for i, b := range badges {
		right = st.barBadge.Render(b)
		var kept bool
		left, kept = fit(right)
		if kept && lipgloss.Width(left)+1+lipgloss.Width(right) <= width || i == len(badges)-1 {
			break
		}
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
	case m.conn.state == client.Authenticating:
		return st.bar.Foreground(t.Warning).Render("◌ authenticating")
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
	hints := "enter send · ctrl+n/p switch · esc normal · tab complete · /help"
	if m.mode == ModeNormal {
		pill = st.pillNormal.Render(" NORMAL ")
		hints = "J/K select · enter open · j/k scroll · g/G ends · : command · q quit"
	}
	switch {
	case m.overlay.kind == overlayVerify:
		hints = "v verified · u not verified · esc close"
	case m.overlay.kind == overlayWhoami || m.overlay.kind == overlayMembers:
		hints = "esc close"
	case m.confirm.active:
		hints = m.confirm.hints()
	}
	c := m.conv(m.open)
	note := "notes stay local "
	switch {
	case c != nil && c.kind == convContact:
		note = "end-to-end encrypted "
	case c != nil && c.kind == convGroup && !c.group.Left:
		note = "end-to-end encrypted · relay sees recipients "
	case c != nil && c.kind == convRequests:
		note = "read only "
	}
	right := st.barFaint.Render(note)
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
// d.sidebarW cells, the last column being the border. The list scrolls to
// keep the selected row visible.
func (m Model) renderSidebar(d dims) []string {
	if d.sidebarW == 0 {
		return nil
	}
	st := m.st
	inner := d.sidebarW - 1
	plain := lipgloss.NewStyle()
	lines := []string{"", "  " + st.sidebarTitle.Render("CONVERSATIONS"), ""}

	var hint []string
	if len(m.convs) == 1 {
		text := "No contacts yet. /add <qc1-id> [name]"
		if m.cfg.Backend == nil {
			text = "No identity loaded; messaging is off."
		}
		hint = append(hint, "")
		for _, l := range wrapLines(text, inner-4) {
			hint = append(hint, "  "+st.faint.Italic(true).Render(l))
		}
	}
	rows := max(d.bodyH-len(lines)-len(hint), 1)
	focus := m.open
	if m.mode == ModeNormal {
		focus = m.cursor
	}
	start := max(m.convIndex(focus)-rows+1, 0)
	for i := start; i < len(m.convs) && i < start+rows; i++ {
		c := &m.convs[i]
		lines = append(lines, m.renderConversation(c, c.key == m.open, m.mode == ModeNormal && c.key == m.cursor, inner))
	}
	lines = append(lines, hint...)

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

// renderConversation draws one sidebar row: name, verification marker and
// unread badge.
func (m Model) renderConversation(c *conversation, selected, cursor bool, width int) string {
	st := m.st
	t := st.theme
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
	mark, markColor := "", t.Text
	if c.kind == convContact {
		switch {
		case c.contact.KeyChanged:
			mark, markColor = " ⚠", t.Danger
		case c.contact.Verified:
			mark, markColor = " ✓", t.Success
		}
	}
	if c.kind == convGroup {
		switch {
		case c.group.Left:
			mark, markColor = " ✕", t.Muted
		case c.group.OutOfSync:
			mark, markColor = " ⚠", t.Warning
		case c.group.Invite:
			mark, markColor = " ?", t.Warning
		}
	}
	markW := lipgloss.Width(mark)
	nameW := max(width-3-badgeW-markW, 1)
	name := truncate(c.title(), nameW)
	if selected {
		body := st.rowSelected.Render(padPlain(" "+name, width-1-badgeW-markW))
		return st.rowMarker.Render("▌") + body + st.rowSelected.Foreground(markColor).Render(mark) + badge
	}
	lead := "  "
	if cursor {
		lead = st.accent.Render("›") + " "
	}
	nameStyle := st.muted
	if c.kind == convGroup && c.group.Left {
		nameStyle = st.faint
	}
	row := lead + nameStyle.Render(name) + lipgloss.NewStyle().Foreground(markColor).Render(mark)
	return padRight(row, width-badgeW, lipgloss.NewStyle()) + badge
}

// renderMain draws the right pane, exactly d.bodyH lines of d.mainW cells.
func (m Model) renderMain(d dims) []string {
	st := m.st
	plain := lipgloss.NewStyle()
	fit := func(s string) string { return padRight(" "+s, d.mainW, plain) }

	lines := make([]string, 0, d.bodyH)
	lines = append(lines, m.renderHeader(d.mainW))
	for _, b := range m.renderBanner(d.mainW, d.bodyH-2-d.inputH) {
		lines = append(lines, fit(b))
	}

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
	if m.confirm.active {
		input = []string{st.warn.Bold(true).Render(truncate(m.confirm.prompt(), d.mainW-2))}
	}
	for i := 0; i < d.inputH; i++ {
		line := ""
		if i < len(input) {
			line = input[i]
		}
		lines = append(lines, fit(line))
	}
	return lines
}

// renderHeader draws the conversation title with, for contacts, the short
// ID and the verification state.
func (m Model) renderHeader(width int) string {
	st := m.st
	c := m.conv(m.open)
	if c == nil {
		c = &m.convs[0]
	}
	hint := ""
	if !m.history.AtBottom() {
		hint = st.accent.Render("↓ newer below") + " "
	}
	room := width - lipgloss.Width(hint)
	var title string
	var extras []string
	switch c.kind {
	case convSystem:
		title = " " + st.bold.Render("# System")
		extras = []string{st.faint.Render("  connection log and local notes")}
	case convRequests:
		title = " " + st.bold.Render("# Message requests")
		extras = []string{st.faint.Render("  from people not in your contacts")}
	case convGroup:
		title = " " + st.bold.Render(truncate(c.title(), max(room/2, 8)))
		count := fmt.Sprintf("  %d members", len(c.group.Members))
		switch {
		case c.group.Left:
			extras = []string{st.warn.Render("  you left · read only"), st.warn.Render("  left")}
		case c.group.Invite:
			extras = []string{st.warn.Render("  invitation · /group accept"), st.warn.Render("  invitation")}
		case selfAdmin(c.group):
			extras = []string{st.faint.Render(count) + st.accent.Render(" · you are admin") + st.faint.Render(" · /group members"),
				st.faint.Render(count) + st.accent.Render(" · you are admin"), st.faint.Render(count)}
		default:
			extras = []string{st.faint.Render(count + " · /group members"), st.faint.Render(count)}
		}
	default:
		title = " " + st.bold.Render(truncate(c.contact.label(), max(room/2, 8)))
		state := []string{st.ok.Render("  ✓ verified"), st.ok.Render("  ✓")}
		switch {
		case c.contact.KeyChanged:
			state = []string{st.danger.Bold(true).Render("  ⚠ key changed — /verify"), st.danger.Bold(true).Render("  ⚠ /verify")}
		case !c.contact.Verified:
			state = []string{st.warn.Render("  unverified — /verify"), st.warn.Render("  unverified")}
		}
		extras = []string{st.faint.Render("  "+c.contact.ShortID) + state[0], state[0], state[1]}
	}
	line := title
	for _, extra := range extras {
		if lipgloss.Width(title)+lipgloss.Width(extra) <= room-1 {
			line = title + extra
			break
		}
	}
	return padRight(truncateStyled(line, room), room, lipgloss.NewStyle()) + hint
}

// renderBanner draws the warning of the open conversation (a changed
// safety number, or a group out of sync): a box when there is room, one
// line otherwise, nothing when there is no warning.
// room is the height left for banner and history together.
func (m Model) renderBanner(mainW, room int) []string {
	c := m.conv(m.open)
	if c == nil || room < 2 {
		return nil
	}
	var title, text, short string
	switch {
	case c.kind == convContact && c.contact.KeyChanged:
		title, short = "⚠ Safety number changed", "⚠ Safety number changed · compare it with /verify"
		text = c.contact.label() + "'s keys changed. This happens after a reinstall, or when someone intercepts. " +
			"Sending still works, but compare the new safety number with /verify before you trust this conversation."
	case c.kind == convGroup && c.group.OutOfSync && !c.group.Left:
		title, short = "⚠ Group out of sync", "⚠ group state differs — messages may be from a different membership view"
		text = "The group state differs from this member — messages may be from a different membership view. " +
			"It settles once every member has seen the latest change; /group members shows your view."
	default:
		return nil
	}
	st := m.st
	inner := min(mainW-2, maxAlertWidth) - 4
	body := []string{st.alertTitle.Render(truncate(title, inner))}
	for _, l := range wrapLines(text, inner) {
		body = append(body, st.text.Render(l))
	}
	if room-len(body)-2 >= 4 {
		for i, l := range body {
			body[i] = padRight(l, inner, lipgloss.NewStyle())
		}
		return strings.Split(st.alertBox.Render(strings.Join(body, "\n")), "\n")
	}
	return []string{st.alertTitle.Render(truncate(short, mainW-2))}
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
	nameW := 13
	for _, c := range matches {
		nameW = max(nameW, len(c.name))
	}
	var out []string
	for i := start; i < len(matches) && len(out) < d.paletteH; i++ {
		c := matches[i]
		text := truncate(fmt.Sprintf("  %-*s %s", nameW, c.name, c.summary), width)
		if i == sel {
			out = append(out, st.paletteSel.Render(padPlain(text, width)))
			continue
		}
		out = append(out, st.palette.Render(text))
	}
	return out
}
