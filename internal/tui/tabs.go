package tui

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/Aepzie/qchat/internal/client"
)

// tab is one of the top-level views selected in the tab bar.
type tab uint8

const (
	tabChats tab = iota
	tabRequests
	tabGroups
	tabContacts
	tabFiles
	tabSystem
	tabCount
)

var (
	tabNames = [tabCount]string{"Chats", "Requests", "Groups", "Contacts", "Files", "System"}
	tabIcons = [tabCount]string{"◆", "✦", "#", "◉", "⇄", "⚡"}
)

// String returns the tab name as shown in the tab bar.
func (t tab) String() string {
	if t >= tabCount {
		return "?"
	}
	return tabNames[t]
}

// altTabKey maps alt+1 … alt+6 to a tab.
func altTabKey(key string) (tab, bool) {
	digit, ok := strings.CutPrefix(key, "alt+")
	if !ok {
		return 0, false
	}
	return digitTab(digit)
}

// digitTab maps "1" … "6" to a tab.
func digitTab(s string) (tab, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || len(s) != 1 || n < 1 || n > int(tabCount) {
		return 0, false
	}
	return tab(n - 1), true
}

// cycleTab moves to the next or previous tab, wrapping around.
func (m *Model) cycleTab(delta int) tea.Cmd {
	n := int(tabCount)
	return m.setTab(tab((int(m.tab) + delta + n) % n))
}

// setTab switches tabs. The conversation on the right follows when the tab
// has an obvious one: System shows the connection log, Requests the
// message requests, the list tabs their first entry when the open
// conversation is not part of them.
func (m *Model) setTab(t tab) tea.Cmd {
	if t >= tabCount {
		return nil
	}
	m.tab = t
	m.overlay = overlay{}
	var cmd tea.Cmd
	switch t {
	case tabSystem:
		cmd = m.openConversation(systemKey)
	case tabRequests:
		clear(m.unseen)
		m.reqSel = clampIndex(m.reqSel, len(m.requestCards()))
		if m.conv(requestsKey) != nil {
			cmd = m.openConversation(requestsKey)
		}
	case tabFiles:
		m.fileSel = clampIndex(m.fileSel, len(m.transfers()))
	default:
		keys := m.listKeys()
		if !slices.Contains(keys, m.open) && len(keys) > 0 {
			cmd = m.openConversation(keys[0])
		}
	}
	m.tab = t
	if keys := m.listKeys(); !slices.Contains(keys, m.cursor) {
		m.cursor = m.open
		if len(keys) > 0 && !slices.Contains(keys, m.open) {
			m.cursor = keys[0]
		}
	}
	return cmd
}

// tabShows reports whether the conversation with key belongs to tab t, so
// that opening it keeps the tab.
func (m *Model) tabShows(t tab, key string) bool {
	c := m.conv(key)
	if c == nil {
		return false
	}
	switch t {
	case tabChats:
		return c.kind == convContact || c.kind == convGroup
	case tabGroups:
		return c.kind == convGroup
	case tabContacts:
		return c.kind == convContact
	case tabRequests:
		return c.kind == convRequests || c.kind == convGroup && c.group.Invite && !c.group.Left
	case tabFiles:
		return true
	case tabSystem:
		return c.kind == convSystem
	}
	return false
}

// followTab switches to the natural tab of the conversation with key when
// the active tab does not show it.
func (m *Model) followTab(key string) {
	if m.tabShows(m.tab, key) {
		return
	}
	c := m.conv(key)
	if c == nil {
		return
	}
	switch c.kind {
	case convSystem:
		m.tab = tabSystem
	case convRequests:
		m.tab = tabRequests
		clear(m.unseen)
	default:
		m.tab = tabChats
	}
}

// listKeys returns the conversation keys listed by the active tab, in
// order, or nil for the tabs that list something else.
func (m *Model) listKeys() []string {
	var keys []string
	for _, c := range m.convs {
		switch {
		case m.tab == tabChats && (c.kind == convContact || c.kind == convGroup),
			m.tab == tabGroups && c.kind == convGroup,
			m.tab == tabContacts && c.kind == convContact:
			keys = append(keys, c.key)
		}
	}
	return keys
}

// moveListCursor moves the selection of the active tab's list.
func (m *Model) moveListCursor(delta int) {
	switch m.tab {
	case tabRequests:
		if n := len(m.requestCards()); n > 0 {
			m.reqSel = (clampIndex(m.reqSel, n) + delta + n) % n
		}
		return
	case tabFiles:
		if n := len(m.transfers()); n > 0 {
			m.fileSel = (clampIndex(m.fileSel, n) + delta + n) % n
		}
		return
	case tabSystem:
		return
	}
	keys := m.listKeys()
	if len(keys) == 0 {
		return
	}
	i := max(slices.Index(keys, m.cursor), 0)
	if !slices.Contains(keys, m.cursor) && delta > 0 {
		i = -1
	}
	m.cursor = keys[(i+delta+len(keys))%len(keys)]
}

// handleTabKey handles the normal-mode keys that depend on tabs: digits,
// brackets, list selection and the quick actions of the active tab. It
// reports false for keys it leaves to the generic handler.
func (m *Model) handleTabKey(key string) (tea.Cmd, bool) {
	if t, ok := digitTab(key); ok {
		return m.setTab(t), true
	}
	switch key {
	case "[":
		return m.cycleTab(-1), true
	case "]":
		return m.cycleTab(1), true
	case "J", "shift+j":
		m.moveListCursor(1)
		return nil, true
	case "K", "shift+k":
		m.moveListCursor(-1)
		return nil, true
	}
	switch m.tab {
	case tabRequests:
		return m.handleRequestKey(key)
	case tabContacts:
		return m.handleContactKey(key)
	case tabFiles:
		return m.handleFileKey(key)
	}
	return nil, false
}

// handleContactKey runs the quick actions of the Contacts tab on the
// selected contact: v verify, r rename, x remove.
func (m *Model) handleContactKey(key string) (tea.Cmd, bool) {
	if key != "v" && key != "r" && key != "x" {
		return nil, false
	}
	c := m.conv(m.cursor)
	if c == nil || c.kind != convContact {
		return nil, true
	}
	cmd := m.openConversation(c.key)
	switch key {
	case "v":
		return tea.Batch(cmd, m.runCommand("/verify")), true
	case "r":
		m.setMode(ModeInsert)
		m.input.SetValue("/rename ")
	case "x":
		return tea.Batch(cmd, m.runCommand("/remove")), true
	}
	return cmd, true
}

// handleClick switches tabs when a tab of the tab bar is clicked.
func (m *Model) handleClick(msg tea.MouseClickMsg) tea.Cmd {
	mouse := msg.Mouse()
	if mouse.Button != tea.MouseLeft || mouse.Y != 0 || m.overlay.kind != overlayNone {
		return nil
	}
	_, spans := m.renderTabBar(m.width)
	for t, s := range spans {
		if mouse.X >= s[0] && mouse.X < s[1] {
			return m.setTab(tab(t))
		}
	}
	return nil
}

// tabBadge returns the counter of a tab, without styling, or "".
func (m Model) tabBadge(t tab) string {
	count := 0
	mark := "●"
	switch t {
	case tabChats, tabGroups:
		for _, c := range m.convs {
			if c.kind == convGroup || t == tabChats && c.kind == convContact {
				count += c.unread
			}
		}
	case tabRequests:
		count, mark = len(m.requestCards()), "✦"
	case tabContacts:
		for _, c := range m.convs {
			if c.kind == convContact && c.contact.KeyChanged {
				count++
			}
		}
		mark = "⚠"
	case tabFiles:
		for _, tr := range m.transfers() {
			if s := tr.entry.file.State; s == FileReceiving || s == FileSending {
				count++
			}
		}
		mark = "⇄"
	case tabSystem:
		if c := m.conv(systemKey); c != nil {
			count = c.unread
		}
	}
	if count <= 0 {
		return ""
	}
	return mark + strconv.Itoa(min(count, 999))
}

// tabLabel returns the plain label of a tab at a detail level: 0 number and
// name, 1 number and icon, 2 number only.
func tabLabel(t tab, level int) string {
	switch level {
	case 0:
		return fmt.Sprintf("%d %s", t+1, tabNames[t])
	case 1:
		return fmt.Sprintf("%d%s", t+1, tabIcons[t])
	}
	return strconv.Itoa(int(t) + 1)
}

// renderTabBar draws the top line: brand, tabs with badges and the
// connection status, exactly width cells. It also returns the cell range of
// every tab, for mouse clicks.
func (m Model) renderTabBar(width int) (string, [tabCount][2]int) {
	st := m.st
	th := st.theme
	var spans [tabCount][2]int
	brand := st.bar.Render(" ") + st.bar.Bold(true).Render(gradientText("⚡ qchat", th.Gradient)) + st.bar.Render(" ")
	if lipgloss.Width(brand)+20 > width {
		brand = st.bar.Render(" ") + st.bar.Bold(true).Render(gradientText("qchat", th.Gradient)) + st.bar.Render(" ")
	}
	minStatus := lipgloss.Width(m.stateSegment())
	var tabs string
	for level := 0; level < 3; level++ {
		tabs, spans = m.renderTabs(level, lipgloss.Width(brand))
		if lipgloss.Width(brand)+lipgloss.Width(tabs)+1+minStatus <= width || level == 2 {
			break
		}
	}
	left := brand + tabs
	if lipgloss.Width(left) > width {
		return truncateStyled(left, width), spans
	}
	status := m.renderStatusSegments(width - lipgloss.Width(left) - 1)
	gap := width - lipgloss.Width(left) - lipgloss.Width(status)
	if gap < 0 {
		return padRight(left, width, st.bar), spans
	}
	return left + st.bar.Render(strings.Repeat(" ", gap)) + status, spans
}

// renderTabs draws the tabs at a detail level, starting at cell offset.
func (m Model) renderTabs(level, offset int) (string, [tabCount][2]int) {
	st := m.st
	th := st.theme
	var spans [tabCount][2]int
	var b strings.Builder
	x := offset
	for t := tab(0); t < tabCount; t++ {
		label := tabLabel(t, level)
		style := st.bar.Foreground(th.Muted)
		if t == m.tab {
			style = st.bar.Foreground(colorOr(th.Glow, th.Accent)).Bold(true)
		}
		cell := style.Render(" " + label)
		if badge := m.tabBadge(t); badge != "" {
			sep := " "
			if level > 0 {
				sep = ""
			}
			badgeColor := th.Accent
			switch {
			case t == tabRequests && len(m.unseen) > 0 && m.animating():
				badgeColor = pulse(th, th.Accent, m.frame)
			case t == tabContacts:
				badgeColor = th.Danger
			case t == tabRequests:
				badgeColor = colorOr(th.Glow, th.Accent)
			}
			cell += st.bar.Foreground(badgeColor).Bold(true).Render(sep + badge)
		}
		if level == 0 {
			cell += st.bar.Render(" ")
		}
		w := lipgloss.Width(cell)
		spans[t] = [2]int{x, x + w}
		x += w
		b.WriteString(cell)
	}
	return b.String(), spans
}

// renderTabRule draws the line under the tab bar: a dim rule with a
// gradient underline below the active tab.
func (m Model) renderTabRule(width int) string {
	st := m.st
	th := st.theme
	_, spans := m.renderTabBar(width)
	s := spans[m.tab]
	start, end := min(s[0], width), min(s[1], width)
	dim := lipgloss.NewStyle().Foreground(colorOr(th.PanelBorder, th.Border))
	line := dim.Render(strings.Repeat("─", start))
	if end > start {
		line += gradientRule(end-start, "━", th.Gradient)
	}
	if rest := width - end; rest > 0 {
		line += dim.Render(strings.Repeat("─", rest))
	}
	return truncateStyled(line, width)
}

// statusSegments returns the optional pieces of the connection status with
// their priorities; lower priorities are dropped first.
func (m Model) statusSegments() []statusSegment {
	st := m.st
	t := st.theme
	segments := []statusSegment{{m.stateSegment(), 100}}
	if m.conn.state == client.Connected {
		segments = append(segments, statusSegment{st.barMuted.Render("🔒 TLS 1.3 · PQ-hybrid"), 40})
	}
	if m.sealed {
		segments = append(segments, statusSegment{st.barMuted.Render("sealed"), 35})
	}
	segments = append(segments, statusSegment{st.barFaint.Render("Tor: ") + st.barMuted.Render(onOff(m.cfg.Tor)), 15})
	if m.conn.state == client.Connected && m.conn.hasRTT {
		segments = append(segments, statusSegment{st.bar.Foreground(t.Text).Render(formatRTT(m.conn.rtt)), 30})
	}
	if m.hasSelf && m.self.ShortID != "" {
		segments = append(segments, statusSegment{st.barFaint.Render("id ") + st.barMuted.Render(m.self.ShortID), 12})
	}
	segments = append(segments,
		statusSegment{st.barFaint.Render("pin ") + st.barMuted.Render(shortFingerprint(m.cfg.Pin)), 10},
		statusSegment{st.barBadge.Render(e2eBadges(m.cfg.Backend != nil)[0]), 20},
	)
	return segments
}

// renderStatusSegments joins as many status segments as fit in width
// cells, dropping the least important first. The state always stays unless
// even it does not fit.
func (m Model) renderStatusSegments(width int) string {
	st := m.st
	segs := m.statusSegments()
	sep := st.barFaint.Render(" · ")
	join := func() string {
		parts := make([]string, len(segs))
		for i, s := range segs {
			parts[i] = s.text
		}
		return strings.Join(parts, sep) + st.bar.Render(" ")
	}
	out := join()
	for lipgloss.Width(out) > width && len(segs) > 1 {
		drop := 0
		for i, s := range segs {
			if s.priority < segs[drop].priority {
				drop = i
			}
		}
		segs = slices.Delete(segs, drop, drop+1)
		out = join()
	}
	if lipgloss.Width(out) > width {
		return ""
	}
	return out
}
