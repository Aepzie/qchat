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
	// leftPanelWidth is the outer width of the list panel, borders included.
	leftPanelWidth = 28
	// sidebarMinTotal is the narrowest terminal that shows the list panel.
	sidebarMinTotal = 70
	// ruleMinHeight is the shortest terminal that gets the tab underline.
	ruleMinHeight  = 16
	maxPaletteRows = 5
	maxInputHeight = 3
)

// dims is the computed layout for the current terminal size. The body sits
// between the tab bar (plus its underline) and the footer and holds the
// list panel on the left and the conversation panel on the right, both
// framed. Inside the right panel: header + banner + history + palette +
// input box == innerH.
type dims struct {
	tooSmall bool
	ruleH    int
	leftW    int
	mainW    int
	innerW   int
	bodyH    int
	innerH   int
	bannerH  int
	inputH   int
	paletteH int
	historyH int
}

// dims computes the layout.
func (m *Model) dims() dims {
	d := dims{}
	if m.width < MinWidth || m.height < MinHeight {
		d.tooSmall = true
		return d
	}
	if m.height >= ruleMinHeight {
		d.ruleH = 1
	}
	if m.width >= sidebarMinTotal {
		d.leftW = leftPanelWidth
	}
	d.mainW = m.width - d.leftW
	d.innerW = d.mainW - 2
	d.bodyH = m.height - 2 - d.ruleH
	d.innerH = d.bodyH - 2
	d.inputH = min(max(m.input.Height(), 1), maxInputHeight)
	if m.confirm.active {
		d.inputH = min(len(wrapLines(m.confirm.prompt(), max(d.innerW-4, 1))), maxInputHeight)
	}
	if matches, open := m.paletteMatches(); open {
		d.paletteH = min(max(len(matches), 1), maxPaletteRows)
	}
	room := d.innerH - 1 - (d.inputH + 2)
	d.bannerH = len(m.renderBanner(d.innerW, room))
	room -= d.bannerH
	d.paletteH = min(d.paletteH, max(room-1, 0))
	d.historyH = max(room-d.paletteH, 0)
	return d
}

// historyWidth is the width available to history lines, or 0 before the
// terminal size is known.
func (m *Model) historyWidth() int {
	d := m.dims()
	if d.tooSmall {
		return 0
	}
	return d.innerW - 2
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
	m.input.SetWidth(d.innerW - 4)
	d = m.dims()
	atBottom := m.history.AtBottom()
	m.history.SetWidth(d.innerW - 2)
	m.history.SetHeight(d.historyH)
	m.syncHistory()
	if atBottom {
		m.history.GotoBottom()
	}
}

// View implements tea.Model. The program runs in the alternate screen with
// mouse reporting enabled, for the wheel and clicks on tabs.
func (m Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.WindowTitle = "qchat"
	v.BackgroundColor = m.st.theme.Background
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
	if m.splash && m.animAllowed() {
		return clamp(splashView(m.width, m.height, m.frame, m.st.theme), m.width, m.height)
	}
	lines := make([]string, 0, m.height)
	bar, _ := m.renderTabBar(m.width)
	lines = append(lines, bar)
	if d.ruleH > 0 {
		lines = append(lines, m.renderTabRule(m.width))
	}
	if m.overlay.kind != overlayNone {
		lines = append(lines, m.renderOverlay(m.width, d.bodyH)...)
	} else {
		left := m.renderLeftPanel(d)
		main := m.renderMain(d)
		for i := 0; i < d.bodyH; i++ {
			line := main[i]
			if d.leftW > 0 {
				line = left[i] + line
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

// stateSegment is the connection state in the status bar, with a spinner
// while connecting.
func (m Model) stateSegment() string {
	st := m.st
	t := st.theme
	switch {
	case m.conn.blocked:
		return st.bar.Foreground(t.Danger).Bold(true).Render("✕ key mismatch")
	case m.conn.state == client.Connected:
		return st.bar.Foreground(t.Success).Render("●") + st.bar.Render(" connected")
	case m.conn.state == client.Connecting:
		return st.bar.Foreground(t.Warning).Render(m.spinner() + " connecting")
	case m.conn.state == client.Authenticating:
		return st.bar.Foreground(t.Warning).Render(m.spinner() + " authenticating")
	case m.conn.state == client.Disconnected:
		return st.bar.Foreground(t.Danger).Render("✕ disconnected")
	case m.conn.state == client.Failed:
		return st.bar.Foreground(t.Danger).Render("✕ stopped")
	default:
		return st.barFaint.Render("◌ starting")
	}
}

// footerHints returns the key hints for the current focus.
func (m Model) footerHints() string {
	switch {
	case m.overlay.kind == overlayVerify:
		return "v verified · u not verified · esc close"
	case m.overlay.kind == overlayWhoami || m.overlay.kind == overlayMembers:
		return "esc close"
	case m.overlay.kind == overlaySearch:
		return "↑/↓ select · enter open conversation · esc close"
	case m.overlay.kind == overlayHelp:
		return "j/k scroll · g/G ends · esc close"
	case m.confirm.active:
		return m.confirm.hints()
	case m.prompt.kind != promptNone:
		return "enter confirm · esc cancel"
	case m.mode == ModeInsert:
		return "enter send · esc normal · alt+1-6 tabs · ctrl+n/p switch · tab complete · /help"
	}
	switch m.tab {
	case tabRequests:
		return "J/K select · a accept · d dismiss · l decline · enter view · 1-6 tabs"
	case tabContacts:
		return "J/K select · enter open · v verify · r rename · x remove · 1-6 tabs"
	case tabFiles:
		return "J/K select · enter/s save · 1-6 tabs · [ ] cycle"
	}
	return "J/K select · enter open · 1-6 tabs · [ ] cycle · j/k scroll · : command · q quit"
}

func (m Model) renderFooter(width int) string {
	st := m.st
	pill := st.pillInsert.Render(" INSERT ")
	if m.mode == ModeNormal {
		pill = st.pillNormal.Render(" NORMAL ")
	}
	hints := m.footerHints()
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

// panel frames content in a rounded border of exactly width×height cells.
// The title sits in the top border; focused panels glow.
func (m Model) panel(content []string, width, height int, title string, focused bool) []string {
	th := m.st.theme
	border := lipgloss.NewStyle().Foreground(colorOr(th.PanelBorder, th.Border))
	if focused {
		border = lipgloss.NewStyle().Foreground(colorOr(th.PanelBorderFocus, th.Accent))
	}
	inner := max(width-2, 0)
	innerH := max(height-2, 0)
	top := border.Render("╭")
	if title != "" && inner >= 6 {
		t := truncateStyled(title, inner-4)
		top += border.Render("─ ") + t + border.Render(" ")
		if rest := inner - 3 - lipgloss.Width(t); rest > 0 {
			top += border.Render(strings.Repeat("─", rest))
		}
	} else {
		top += border.Render(strings.Repeat("─", inner))
	}
	top += border.Render("╮")
	out := make([]string, 0, height)
	out = append(out, top)
	edge := border.Render("│")
	plain := lipgloss.NewStyle()
	for i := 0; i < innerH; i++ {
		line := ""
		if i < len(content) {
			line = content[i]
		}
		out = append(out, edge+padRight(truncateStyled(line, inner), inner, plain)+edge)
	}
	out = append(out, border.Render("╰"+strings.Repeat("─", inner)+"╯"))
	return out
}

// renderLeftPanel draws the list panel of the active tab, exactly d.bodyH
// lines of d.leftW cells.
func (m Model) renderLeftPanel(d dims) []string {
	if d.leftW == 0 {
		return nil
	}
	inner := d.leftW - 2
	content := m.listContent(inner, d.bodyH-2)
	title := m.st.accent.Bold(true).Render(strings.ToUpper(m.tab.String()))
	return m.panel(content, d.leftW, d.bodyH, title, m.mode == ModeNormal && m.overlay.kind == overlayNone)
}

// listContent returns the lines of the list of the active tab.
func (m Model) listContent(width, height int) []string {
	switch m.tab {
	case tabRequests:
		return m.renderRequestCards(width, height)
	case tabFiles:
		return m.renderTransfers(width, height)
	case tabSystem:
		return m.renderSystemSummary(width)
	}
	st := m.st
	keys := m.listKeys()
	var hint []string
	if len(keys) == 0 {
		text := "No contacts yet. /add <qc1-id> [name]"
		switch {
		case m.cfg.Backend == nil:
			text = "No identity loaded; messaging is off."
		case m.tab == tabGroups:
			text = "No groups yet. /group create <name> [qc1-ids]"
		}
		hint = append(hint, "")
		for _, l := range wrapLines(text, width-2) {
			hint = append(hint, " "+st.faint.Italic(true).Render(l))
		}
	}
	var footer []string
	if m.tab == tabContacts && len(keys) > 0 {
		footer = []string{st.faint.Render(truncate(" v verify · r rename · x remove", width))}
	}
	rows := max(height-len(hint)-len(footer), 1)
	focus := m.open
	if m.mode == ModeNormal {
		focus = m.cursor
	}
	sel := 0
	for i, k := range keys {
		if k == focus {
			sel = i
		}
	}
	start := max(sel-rows+1, 0)
	var lines []string
	for i := start; i < len(keys) && i < start+rows; i++ {
		c := m.convByKey(keys[i])
		lines = append(lines, m.renderListRow(c, c.key == m.open, m.mode == ModeNormal && c.key == m.cursor, width))
	}
	lines = append(lines, hint...)
	if len(footer) > 0 {
		for len(lines) < height-len(footer) {
			lines = append(lines, "")
		}
		lines = append(lines, footer...)
	}
	return lines
}

// convByKey returns a copy of the conversation with key, or an empty one.
func (m Model) convByKey(key string) *conversation {
	for i := range m.convs {
		if m.convs[i].key == key {
			c := m.convs[i]
			return &c
		}
	}
	return &conversation{}
}

// renderListRow draws one list row: avatar, name, verification marker and
// unread badge.
func (m Model) renderListRow(c *conversation, selected, cursor bool, width int) string {
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
	icon := st.accent.Render("#")
	if c.kind == convContact {
		icon = avatar(t, c.key, c.contact.label())
	}
	iconW := lipgloss.Width(icon) + 1
	markW := lipgloss.Width(mark)
	name := c.title()
	if c.kind == convGroup {
		name = c.group.Name
	}
	name = truncate(name, max(width-3-iconW-badgeW-markW, 1))
	if selected {
		body := st.rowSelected.Render(padPlain(" "+name, width-1-iconW-badgeW-markW))
		return st.rowMarker.Render("▌") + icon + " " + body + st.rowSelected.Foreground(markColor).Render(mark) + badge
	}
	lead := "  "
	if cursor {
		lead = st.accent.Render("›") + " "
	}
	nameStyle := st.muted
	if c.kind == convGroup && c.group.Left {
		nameStyle = st.faint
	}
	row := lead + icon + " " + nameStyle.Render(name) + lipgloss.NewStyle().Foreground(markColor).Render(mark)
	return padRight(row, width-badgeW, lipgloss.NewStyle()) + badge
}

// renderMain draws the right panel, exactly d.bodyH lines of d.mainW cells:
// header, banner, history, palette and the input box.
func (m Model) renderMain(d dims) []string {
	st := m.st
	th := st.theme
	fit := func(s string) string { return " " + s }

	lines := make([]string, 0, d.innerH)
	lines = append(lines, m.renderHeader(d.innerW))
	lines = append(lines, m.renderBanner(d.innerW, d.innerH-1-d.inputH-2)...)

	var body []string
	if d.leftW == 0 && m.mode == ModeNormal && m.tab != tabChats {
		body = m.listContent(d.innerW-2, d.historyH)
	} else {
		body = strings.Split(m.history.View(), "\n")
	}
	for i := 0; i < d.historyH; i++ {
		line := ""
		if i < len(body) {
			line = body[i]
		}
		lines = append(lines, fit(line))
	}
	for _, p := range m.renderPalette(d) {
		lines = append(lines, fit(p))
	}

	input := strings.Split(m.input.View(), "\n")
	if m.confirm.active {
		input = nil
		for _, l := range wrapLines(m.confirm.prompt(), max(d.innerW-4, 1)) {
			input = append(input, st.warn.Bold(true).Render(l))
		}
	}
	for len(input) < d.inputH {
		input = append(input, "")
	}
	input = input[:d.inputH]
	for i, l := range input {
		input[i] = " " + l
	}
	focused := m.mode == ModeInsert && m.overlay.kind == overlayNone
	boxTitle := st.accent.Render("✎ ") + st.text.Render(m.inputTitle())
	if m.prompt.kind != promptNone {
		boxTitle = st.accent.Bold(true).Render(m.prompt.title())
	}
	lines = append(lines, m.panel(input, d.innerW, d.inputH+2, boxTitle, focused)...)
	title := st.accent.Bold(true).Render(gradientText(m.panelTitle(), th.Gradient))
	return m.panel(lines, d.mainW, d.bodyH, title, focused)
}

// panelTitle names the right panel.
func (m Model) panelTitle() string {
	c := m.conv(m.open)
	if c == nil {
		return "SYSTEM"
	}
	switch c.kind {
	case convSystem:
		return "◉ SYSTEM"
	case convRequests:
		return "✦ REQUESTS"
	case convGroup:
		return "◆ GROUP"
	}
	return "◆ CHAT"
}

// inputTitle is the title of the input box: who a message goes to.
func (m Model) inputTitle() string {
	c := m.conv(m.open)
	if c == nil {
		return "note"
	}
	switch c.kind {
	case convContact:
		return "message " + c.contact.label()
	case convGroup:
		return "message " + c.title()
	case convRequests:
		return "read only · a accept in the list"
	}
	return "note · stays on this device"
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
		title = " " + avatar(st.theme, c.key, c.contact.label()) + " " + st.bold.Render(truncate(c.contact.label(), max(room/2, 8)))
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
// safety number, or a group out of sync) or, in the Chats tab, the pointer
// to unseen message requests: a box when there is room, one line
// otherwise, nothing when there is nothing to say.
// room is the height left for banner and history together.
func (m Model) renderBanner(mainW, room int) []string {
	c := m.conv(m.open)
	if c == nil || room < 2 {
		return nil
	}
	st := m.st
	var title, text, short string
	switch {
	case c.kind == convContact && c.contact.KeyChanged:
		opts := renderOpts{Frame: m.frame, Animate: m.animating() && m.frame < m.flashUntil, Now: m.cfg.Now()}
		if box := renderKeyChangeBanner(st, c.contact.label(), mainW-2, opts); room-len(box) >= 4 {
			return box
		}
		return []string{st.alertTitle.Render(truncate("⚠ Safety number changed · compare it with /verify", mainW-2))}
	case c.kind == convGroup && c.group.OutOfSync && !c.group.Left:
		title, short = "⚠ Group out of sync", "⚠ group state differs — messages may be from a different membership view"
		text = "The group state differs from this member — messages may be from a different membership view. " +
			"It settles once every member has seen the latest change; /group members shows your view."
	default:
		if banner := m.requestsBanner(); banner != "" {
			return []string{" " + st.accent.Bold(true).Render(truncate(banner, mainW-2))}
		}
		return nil
	}
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
	width := d.innerW - 2
	if len(matches) == 0 {
		return []string{st.faint.Render(truncate("  no matching command · /help lists them", width))}
	}
	sel := clampIndex(m.paletteSel, len(matches))
	start := 0
	if sel >= d.paletteH {
		start = sel - d.paletteH + 1
	}
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
