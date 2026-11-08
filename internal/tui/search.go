package tui

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const (
	// searchLimit is how many hits one search returns at most.
	searchLimit = 200
	// maxQueryRunes bounds a search query.
	maxQueryRunes = 200
	// searchUsage explains /search.
	searchUsage = "usage: /search <text> searches this conversation · /search all <text> searches every conversation"
)

// searchResult is a sanitised SearchHit, ready to draw.
type searchResult struct {
	convID   string
	title    string
	from     string
	text     string
	at       string
	outgoing bool
}

// searchResultMsg carries the answer to a search.
type searchResultMsg struct {
	seq  int
	hits []SearchHit
	err  error
}

// searchBackend returns the Backend's SearchBackend, or nil.
func (m *Model) searchBackend() SearchBackend {
	sb, _ := m.cfg.Backend.(SearchBackend)
	return sb
}

func searchCmd(sb SearchBackend, seq int, query, convID string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
		defer cancel()
		hits, err := sb.Search(ctx, query, convID, searchLimit)
		return searchResultMsg{seq: seq, hits: hits, err: err}
	}
}

// cmdSearch runs /search [all] <text>.
func (m *Model) cmdSearch(rest string) tea.Cmd {
	if !m.requireBackend() {
		return nil
	}
	sb := m.searchBackend()
	if sb == nil {
		m.log(entryError, "Search is not available.")
		return nil
	}
	all := false
	if first, after, _ := strings.Cut(rest, " "); strings.EqualFold(first, "all") {
		all, rest = true, after
	}
	query := cleanLine(rest, maxQueryRunes)
	if query == "" {
		m.log(entryError, searchUsage)
		return nil
	}
	convID, scope := "", "all conversations"
	if !all {
		c := m.openConv()
		if c.kind != convContact && c.kind != convGroup {
			m.log(entryError, "Open a contact or group to search it, or search everything with /search all <text>.")
			return nil
		}
		convID, scope = c.key, c.title()
	}
	m.searchSeq++
	m.overlay = overlay{kind: overlaySearch, query: query, name: scope, busy: true}
	return searchCmd(sb, m.searchSeq, query, convID)
}

// applySearch shows the answer to the latest search.
func (m *Model) applySearch(msg searchResultMsg) {
	if m.overlay.kind != overlaySearch || msg.seq != m.searchSeq {
		return
	}
	m.overlay.busy = false
	if msg.err != nil {
		m.overlay.errText = "Search failed: " + describeBackendError(msg.err) + "."
		return
	}
	hits := msg.hits[:min(len(msg.hits), searchLimit)]
	m.overlay.hits = make([]searchResult, 0, len(hits))
	for _, h := range hits {
		m.overlay.hits = append(m.overlay.hits, m.searchResult(h))
	}
}

// searchResult sanitises a hit and resolves its conversation and sender
// names.
func (m *Model) searchResult(h SearchHit) searchResult {
	r := searchResult{
		convID:   cleanLine(h.ConversationID, 128),
		text:     cleanLine(h.Text, maxEntryText),
		outgoing: h.Outgoing,
	}
	if !h.At.IsZero() {
		r.at = h.At.Format("2 Jan 2006 15:04")
	}
	c := m.conv(r.convID)
	switch {
	case c != nil:
		r.title = c.title()
	case strings.HasPrefix(r.convID, groupPrefix):
		r.title = "# unknown group"
	default:
		r.title = shortID(r.convID)
	}
	switch {
	case h.Outgoing:
		r.from = "you"
	case c != nil && c.kind == convGroup:
		r.from = m.memberLabel(c, cleanLine(h.From, 128))
	}
	return r
}

// handleSearchKey moves the selection or opens the selected conversation.
func (m *Model) handleSearchKey(msg tea.KeyPressMsg) tea.Cmd {
	o := &m.overlay
	n := len(o.hits)
	switch msg.String() {
	case "up", "k", "ctrl+p":
		o.sel = max(o.sel-1, 0)
	case "down", "j", "ctrl+n":
		o.sel = min(o.sel+1, max(n-1, 0))
	case "pgup":
		o.sel = max(o.sel-10, 0)
	case "pgdown":
		o.sel = min(o.sel+10, max(n-1, 0))
	case "home", "g":
		o.sel = 0
	case "end", "G", "shift+g":
		o.sel = max(n-1, 0)
	case "enter":
		if n == 0 {
			return nil
		}
		hit := o.hits[clampIndex(o.sel, n)]
		m.overlay = overlay{}
		if m.conv(hit.convID) == nil {
			m.log(entryError, "That conversation is no longer in your list.")
			return nil
		}
		return m.openConversation(hit.convID)
	}
	return nil
}

// searchTitle is the header of the search overlay.
func (m Model) searchTitle() string {
	o := m.overlay
	st := m.st
	count := ""
	switch {
	case o.busy:
		count = "  searching…"
	case len(o.hits) == 1:
		count = "  1 message"
	default:
		count = fmt.Sprintf("  %d messages", len(o.hits))
	}
	return st.bold.Render("Search “"+truncate(o.query, 40)+"”") + st.faint.Render(" in "+truncate(o.name, 32)+count)
}

// searchLines draws the results of the search overlay in exactly height
// lines of width cells, scrolled so that the selection is visible.
func (m Model) searchLines(width, height int) []string {
	o := m.overlay
	st := m.st
	var lines []string
	add := func(style lipgloss.Style, text string) {
		for _, l := range wrapLines(text, width) {
			lines = append(lines, style.Render(l))
		}
	}
	switch {
	case o.errText != "":
		add(st.danger, o.errText)
		return lines
	case o.busy:
		add(st.faint, "Decrypting and scanning stored messages…")
		return lines
	case len(o.hits) == 0:
		add(st.muted, "No stored message contains “"+o.query+"”.")
		lines = append(lines, "")
		add(st.faint, "Search covers the most recent stored messages of each conversation on this device. Message requests are not stored and are not searched.")
		return lines
	}
	per := 2
	if height >= 3*len(o.hits) || height >= 9 {
		per = 3
	}
	visible := max(height/per, 1)
	sel := clampIndex(o.sel, len(o.hits))
	start := max(sel-visible+1, 0)
	for i := start; i < len(o.hits) && len(lines)+per <= max(height, per); i++ {
		lines = append(lines, m.searchRow(o.hits[i], i == sel, width)...)
		if per == 3 {
			lines = append(lines, "")
		}
	}
	return lines
}

// searchRow draws one result: where and when, then the text around the
// match with the match highlighted.
func (m Model) searchRow(r searchResult, selected bool, width int) []string {
	st := m.st
	lead := "  "
	if selected {
		lead = st.accent.Bold(true).Render("▌") + " "
	}
	inner := max(width-2, 1)
	title := st.bold.Render(truncate(r.title, max(inner/2, 8)))
	if selected {
		title = st.accent.Bold(true).Render(truncate(r.title, max(inner/2, 8)))
	}
	head := title
	if r.at != "" {
		head += st.faint.Render("  " + r.at)
	}
	if r.from != "" {
		head += st.muted.Render("  " + r.from)
	}
	return []string{
		lead + truncateStyled(head, inner),
		lead + m.snippet(r.text, m.overlay.query, inner),
	}
}

// snippet returns text cut to width cells around the first match of query,
// ignoring case, with the match highlighted.
func (m Model) snippet(text, query string, width int) string {
	st := m.st
	runes := []rune(text)
	at, n := indexFold(runes, []rune(query))
	if at < 0 {
		return st.muted.Render(truncate(text, width))
	}
	before := string(runes[:at])
	match := string(runes[at : at+n])
	after := string(runes[at+n:])
	room := max(width/3, 4)
	if lipgloss.Width(before) > room {
		r := []rune(before)
		for len(r) > 0 && lipgloss.Width(string(r))+1 > room {
			r = r[1:]
		}
		before = "…" + string(r)
	}
	if lipgloss.Width(before)+lipgloss.Width(match) > width {
		match = truncate(match, max(width-lipgloss.Width(before), 1))
		return st.muted.Render(before) + st.match.Render(match)
	}
	rest := width - lipgloss.Width(before) - lipgloss.Width(match)
	return st.muted.Render(before) + st.match.Render(match) + st.muted.Render(truncate(after, rest))
}

// indexFold returns the rune index and length of the first match of query
// in text, ignoring case, or -1.
func indexFold(text, query []rune) (int, int) {
	if len(query) == 0 {
		return -1, 0
	}
	for i := 0; i+len(query) <= len(text); i++ {
		match := true
		for j, q := range query {
			if unicode.ToLower(text[i+j]) != unicode.ToLower(q) {
				match = false
				break
			}
		}
		if match {
			return i, len(query)
		}
	}
	return -1, 0
}
