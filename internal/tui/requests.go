package tui

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/craguS/qchat/internal/client"
)

// requestCard is one entry of the Requests tab: a message request from an
// unknown sender, or a group invitation.
type requestCard struct {
	// key is the sender's identity ID, or the group ID of an invitation.
	key     string
	invite  bool
	title   string
	preview string
	at      time.Time
	count   int
}

// requestCards returns the pending message requests, oldest sender first,
// followed by the group invitations.
func (m *Model) requestCards() []requestCard {
	var cards []requestCard
	if req := m.conv(requestsKey); req != nil {
		for _, id := range req.senders {
			card := requestCard{key: id, title: shortID(id)}
			for _, e := range req.entries {
				if e.sender != id || e.kind != entryMessage {
					continue
				}
				if card.count == 0 {
					card.preview = cleanLine(e.text, 200)
					if e.file != nil {
						card.preview = "⇄ " + cleanLine(e.file.Name, 120)
					}
				}
				card.count++
				card.at = e.at
			}
			cards = append(cards, card)
		}
	}
	for _, c := range m.convs {
		if c.kind != convGroup || !c.group.Invite || c.group.Left {
			continue
		}
		cards = append(cards, requestCard{
			key: c.key, invite: true, title: c.title(),
			preview: fmt.Sprintf("group invitation · %d members", len(c.group.Members)),
			count:   len(c.entries),
		})
	}
	return cards
}

// promptKind is the question answered in the input box.
type promptKind uint8

const (
	promptNone promptKind = iota
	// promptAcceptName asks for the display name of an accepted request.
	promptAcceptName
	// promptSaveDir asks for the directory a file is saved to.
	promptSaveDir
)

// prompt is an inline question. target is the sender ID or the
// conversation key; fileNo the /save number of the file to save.
type prompt struct {
	kind   promptKind
	target string
	fileNo int
}

// title is the input box title while the prompt is open.
func (p prompt) title() string {
	switch p.kind {
	case promptAcceptName:
		return "✦ name for " + shortID(p.target) + " · enter accept · esc cancel"
	case promptSaveDir:
		return "⇄ save to directory · empty = Downloads · esc cancel"
	}
	return ""
}

// ask opens an inline prompt in the input box.
func (m *Model) ask(p prompt) {
	m.prompt = p
	m.setMode(ModeInsert)
	m.input.Reset()
}

// cancelPrompt closes the prompt without acting.
func (m *Model) cancelPrompt() {
	m.prompt = prompt{}
	m.input.Reset()
}

// answerPrompt acts on the text typed into an open prompt.
func (m *Model) answerPrompt(raw string) tea.Cmd {
	p := m.prompt
	m.prompt = prompt{}
	switch p.kind {
	case promptAcceptName:
		if !m.requireBackend() {
			return nil
		}
		name := cleanLine(raw, maxNameRunes)
		m.log(entrySystem, "Looking up "+shortID(p.target)+" on the relay…")
		return addCmd(m.cfg.Backend, p.target, name)
	case promptSaveDir:
		if m.conv(p.target) == nil {
			return nil
		}
		cmd := m.openConversation(p.target)
		n := strconv.Itoa(p.fileNo)
		return tea.Batch(cmd, m.cmdSave([]string{n}, n+" "+raw))
	}
	return nil
}

// handleRequestKey runs the actions of the Requests tab on the selected
// card: a accept, d dismiss, l decline an invitation, enter view.
func (m *Model) handleRequestKey(key string) (tea.Cmd, bool) {
	cards := m.requestCards()
	switch key {
	case "a", "d", "l", "enter", "v":
	default:
		return nil, false
	}
	if len(cards) == 0 {
		return nil, true
	}
	m.reqSel = clampIndex(m.reqSel, len(cards))
	card := cards[m.reqSel]
	switch key {
	case "a":
		if card.invite {
			if !m.requireBackend() {
				return nil, true
			}
			c := m.conv(card.key)
			return changeGroupCmd(m.cfg.Backend, card.key, GroupChange{Op: GroupAccept},
				"You joined "+c.title()+"."), true
		}
		m.ask(prompt{kind: promptAcceptName, target: card.key})
	case "d":
		if card.invite {
			m.log(entryWarn, "Decline an invitation with l; it tells the group you left.")
			return nil, true
		}
		m.dismissRequest(card.key)
	case "l":
		if !card.invite {
			return nil, true
		}
		if !m.requireBackend() {
			return nil, true
		}
		return leaveGroupCmd(m.cfg.Backend, card.key), true
	case "enter", "v":
		if card.invite {
			cmd := m.openConversation(card.key)
			return cmd, true
		}
		cmd := m.openConversation(requestsKey)
		m.history.GotoBottom()
		return cmd, true
	}
	return nil, true
}

// dismissRequest forgets the messages of an unknown sender on this device.
// New messages from them arrive as a new request.
func (m *Model) dismissRequest(id string) {
	req := m.conv(requestsKey)
	if req == nil {
		return
	}
	req.entries = slices.DeleteFunc(req.entries, func(e entry) bool { return e.sender == id })
	req.senders = slices.DeleteFunc(req.senders, func(s string) bool { return s == id })
	delete(m.unseen, id)
	if len(req.senders) == 0 {
		m.convs = slices.DeleteFunc(m.convs, func(c conversation) bool { return c.key == requestsKey })
		if m.open == requestsKey {
			m.open = systemKey
			m.input.placeholder = placeholderFor(&m.convs[0])
		}
		if m.cursor == requestsKey {
			m.cursor = m.open
		}
	}
	m.reqSel = clampIndex(m.reqSel, len(m.requestCards()))
	m.refreshHistory()
	m.sysLog(entrySystem, "Dismissed the request from "+shortID(id)+".")
}

// unseenRequests counts the requests and invitations not yet seen in the
// Requests tab.
func (m *Model) unseenRequests() int { return len(m.unseen) }

// requestsBanner is the line shown in the Chats tab while unseen requests
// exist, or "".
func (m *Model) requestsBanner() string {
	n := m.unseenRequests()
	if n == 0 || m.tab != tabChats {
		return ""
	}
	noun := "message request"
	if n != 1 {
		noun += "s"
	}
	return fmt.Sprintf("✦ %d new %s — press 2", n, noun)
}

// transfer is one file of the Files tab.
type transfer struct {
	convKey   string
	convTitle string
	no        int
	entry     entry
}

// transfers returns every file message of every conversation, in sidebar
// order.
func (m *Model) transfers() []transfer {
	var out []transfer
	for i := range m.convs {
		c := &m.convs[i]
		if c.kind != convContact && c.kind != convGroup {
			continue
		}
		for _, e := range numberFiles(fileEntries(c)) {
			out = append(out, transfer{convKey: c.key, convTitle: c.title(), no: e.fileNo, entry: e})
		}
	}
	return out
}

// handleFileKey runs the actions of the Files tab: enter or s saves the
// selected file after asking for a directory.
func (m *Model) handleFileKey(key string) (tea.Cmd, bool) {
	if key != "enter" && key != "s" {
		return nil, false
	}
	list := m.transfers()
	if len(list) == 0 {
		return nil, true
	}
	m.fileSel = clampIndex(m.fileSel, len(list))
	tr := list[m.fileSel]
	cmd := m.openConversation(tr.convKey)
	m.ask(prompt{kind: promptSaveDir, target: tr.convKey, fileNo: tr.no})
	return cmd, true
}

// renderRequestCards draws the cards of the Requests tab, each a few lines
// tall, at width cells.
func (m Model) renderRequestCards(width, height int) []string {
	st := m.st
	th := st.theme
	cards := m.requestCards()
	if len(cards) == 0 {
		var out []string
		for _, l := range wrapLines("No message requests or invitations.", width-2) {
			out = append(out, " "+st.faint.Italic(true).Render(l))
		}
		return out
	}
	sel := clampIndex(m.reqSel, len(cards))
	const cardH = 4
	start := 0
	if per := max(height/cardH, 1); sel >= per {
		start = sel - per + 1
	}
	var out []string
	for i := start; i < len(cards); i++ {
		card := cards[i]
		edge := lipgloss.NewStyle().Foreground(colorOr(th.PanelBorder, th.Border))
		if i == sel {
			edge = lipgloss.NewStyle().Foreground(colorOr(th.Glow, th.Accent))
		}
		mark := edge.Render("┃") + " "
		head := avatar(th, card.key, "") + " " + st.bold.Render(truncate(card.title, max(width-12, 4)))
		if card.invite {
			head = st.accent.Render("#") + " " + st.bold.Render(truncate(card.title, max(width-6, 4)))
		}
		if m.unseen[card.key] {
			head += " " + st.accent.Render("✦")
		}
		meta := ""
		if !card.at.IsZero() {
			meta = card.at.Format("15:04") + " · "
		}
		if card.invite {
			meta += "a accept · l decline"
		} else {
			meta += fmt.Sprintf("%d msg · a accept · d dismiss", card.count)
		}
		inner := max(width-2, 1)
		out = append(out,
			mark+truncateStyled(head, inner),
			mark+st.muted.Render(truncate(card.preview, inner)),
			mark+st.faint.Render(truncate(meta, inner)),
			"",
		)
	}
	return out
}

// renderTransfers draws the Files tab list at width cells.
func (m Model) renderTransfers(width, height int) []string {
	st := m.st
	th := st.theme
	list := m.transfers()
	if len(list) == 0 {
		var out []string
		for _, l := range wrapLines("No files yet. /send <path> in a conversation.", width-2) {
			out = append(out, " "+st.faint.Italic(true).Render(l))
		}
		return out
	}
	sel := clampIndex(m.fileSel, len(list))
	const rowH = 3
	start := 0
	if per := max(height/rowH, 1); sel >= per {
		start = sel - per + 1
	}
	var out []string
	for i := start; i < len(list); i++ {
		tr := list[i]
		f := tr.entry.file
		lead := "  "
		if i == sel {
			lead = st.accent.Render("▸") + " "
		}
		inner := max(width-2, 1)
		dir := "↓"
		if tr.entry.outgoing {
			dir = "↑"
		}
		out = append(out, lead+st.bold.Render(truncate(dir+" "+f.Name, inner)))
		barW := max(min(inner-12, 16), 4)
		frac := 0.0
		switch {
		case f.State == FileComplete:
			frac = 1
		case f.Total > 0:
			frac = float64(f.Done) / float64(f.Total)
		}
		filled := min(int(frac*float64(barW)+0.5), barW)
		bar := gradientText(strings.Repeat("━", filled), th.Gradient) +
			lipgloss.NewStyle().Foreground(colorOr(th.PanelBorder, th.Border)).Render(strings.Repeat("─", barW-filled))
		info := fmt.Sprintf(" %3d%% %s", int(frac*100), f.State)
		out = append(out, "  "+truncateStyled(bar+st.faint.Render(info), inner))
		out = append(out, "  "+st.faint.Render(truncate(tr.convTitle+" · "+formatSize(f.Size), inner)))
	}
	return out
}

// renderSystemSummary draws the security summary of the System tab.
func (m Model) renderSystemSummary(width int) []string {
	st := m.st
	inner := max(width-2, 1)
	row := func(label, value string) string {
		return " " + truncateStyled(st.faint.Render(label+" ")+st.text.Render(value), inner)
	}
	out := []string{" " + m.stateSegmentPlain(inner)}
	out = append(out,
		row("server", truncate(sanitizeText(m.cfg.Addr), inner)),
		row("tls", "1.3 · X25519MLKEM768"),
		row("sealed", onOff(m.sealed)),
		row("tor", onOff(m.cfg.Tor)),
	)
	if m.hasSelf {
		out = append(out, row("id", m.self.ShortID))
	}
	e2e := "on · forward secrecy"
	if m.cfg.Backend == nil {
		e2e = "off · no identity"
	}
	out = append(out, row("e2e", e2e), "", " "+st.faint.Render("server pin"))
	for _, l := range fingerprintLines(m.cfg.Pin, inner-1) {
		out = append(out, "  "+st.muted.Render(l))
	}
	return out
}

// stateSegmentPlain is the connection state for panels, without the status
// bar background.
func (m Model) stateSegmentPlain(width int) string {
	st := m.st
	th := st.theme
	text, color := "◌ starting", th.Faint
	switch {
	case m.conn.blocked:
		text, color = "✕ key mismatch", th.Danger
	case m.conn.state == client.Connected:
		text, color = "● connected", th.Success
	case m.connecting():
		text, color = m.spinner()+" "+m.conn.state.String(), th.Warning
	case m.conn.state != 0:
		text, color = "✕ "+m.conn.state.String(), th.Danger
	}
	return lipgloss.NewStyle().Foreground(color).Render(truncate(text, width))
}
