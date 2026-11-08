package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// helpSection is one titled group of the help overlay.
type helpSection struct {
	title string
	rows  []row
}

// helpCommandGroups assigns every command of the palette to a help
// section, in display order.
var helpCommandGroups = []struct {
	title string
	names []string
}{
	{"Conversations", []string{"/search", "/send", "/file", "/save", "/timer", "/clear"}},
	{"Contacts", []string{"/add", "/verify", "/rename", "/remove", "/whoami"}},
	{"Appearance", []string{"/theme", "/markdown", "/animations"}},
	{"Connection", []string{"/status", "/fingerprint"}},
	{"General", []string{"/help", "/quit"}},
}

// helpSections returns the content of the help overlay: every command,
// grouped, then keys, status marks and what is private.
func helpSections() []helpSection {
	summary := map[string]string{}
	for _, c := range commands {
		summary[c.name] = c.summary
	}
	var out []helpSection
	for _, g := range helpCommandGroups {
		s := helpSection{title: g.title}
		for _, name := range g.names {
			s.rows = append(s.rows, row{name, summary[name]})
		}
		out = append(out, s)
		if g.title == "Contacts" {
			groups := helpSection{title: "Groups"}
			for _, c := range groupCommands {
				groups.rows = append(groups.rows, row{c.name, c.summary})
			}
			out = append(out, groups)
		}
	}
	return append(out,
		helpSection{"Keys", []row{
			{"tabs", "1-6 in normal mode, alt+1-6 anywhere · ctrl+←/→ or [ ] cycle · click a tab · 1 Chats 2 Requests 3 Groups 4 Contacts 5 Files 6 System"},
			{"requests", "J/K select · a accept (asks for a name) · d dismiss · l decline an invitation · enter view"},
			{"contacts", "J/K select · enter open · v verify · r rename · x remove"},
			{"files", "J/K select · enter or s save (asks for a directory, empty = Downloads)"},
			{"any mode", "ctrl+n / ctrl+p next or previous conversation"},
			{"insert", "enter send · esc normal mode · tab complete · ↑/↓ palette · pgup/pgdn scroll · shift+enter new line"},
			{"normal", "J/K select · enter open · i insert · j/k line · ctrl+d/u half page · g/G top/bottom · : command · q quit"},
			{"overlays", "esc close · ↑/↓ or j/k move · enter open a search result"},
		}},
		helpSection{"Marks", []row{
			{"messages", "… sending · ✓ sent, stored by the relay until delivered · ⧗ recipient offline, not delivered (old relays) · ✕ not sent · ◷ sender clock off"},
			{"contacts", "✓ verified · ⚠ safety number changed, run /verify"},
			{"groups", "✕ left · ? invitation · ⚠ out of sync"},
		}},
		helpSection{"Privacy", []row{
			{"encryption", "Messages to contacts and # groups are end-to-end encrypted. The relay sees who talks to whom (for groups, every recipient), when, and sizes."},
			{"local", "Notes in System, settings and search stay on this device. History is stored encrypted."},
			{"files", "Files are encrypted end to end and stored encrypted here; /save writes a plain copy where you choose. The relay sees their size."},
			{"timers", "Disappearing messages are deleted on both devices after the timer. The other side can still copy or photograph them."},
			{"typing", "qchat sends no typing indicators or read receipts."},
		}},
	)
}

// openHelp shows the help overlay.
func (m *Model) openHelp() {
	m.overlay = overlay{kind: overlayHelp}
}

// helpLines draws the help content at width cells.
func (m Model) helpLines(width int) []string {
	st := m.st
	nameW := 0
	for _, s := range helpSections() {
		for _, r := range s.rows {
			nameW = max(nameW, lipgloss.Width(r.key))
		}
	}
	nameW = min(nameW, 16)
	stacked := width-nameW-4 < 24
	var lines []string
	for i, s := range helpSections() {
		if i > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, st.accent.Bold(true).Render(truncate(s.title, width)))
		for _, r := range s.rows {
			if stacked {
				lines = append(lines, "  "+st.bold.Render(truncate(r.key, width-2)))
				for _, l := range wrapLines(r.value, width-4) {
					lines = append(lines, "    "+st.muted.Render(l))
				}
				continue
			}
			pad := strings.Repeat(" ", nameW+4)
			for j, l := range wrapLines(r.value, width-nameW-4) {
				if j == 0 {
					lines = append(lines, "  "+st.bold.Render(padPlain(truncate(r.key, nameW), nameW))+"  "+st.muted.Render(l))
					continue
				}
				lines = append(lines, pad+st.muted.Render(l))
			}
		}
	}
	return lines
}

// handleHelpKey scrolls the help overlay. The offset is clamped when it is
// drawn.
func (m *Model) handleHelpKey(msg tea.KeyPressMsg) tea.Cmd {
	o := &m.overlay
	switch msg.String() {
	case "up", "k":
		o.scroll = max(o.scroll-1, 0)
	case "down", "j":
		o.scroll++
	case "pgup", "ctrl+u", "ctrl+b":
		o.scroll = max(o.scroll-10, 0)
	case "pgdown", "ctrl+d", "ctrl+f", "space":
		o.scroll += 10
	case "home", "g":
		o.scroll = 0
	case "end", "G", "shift+g":
		o.scroll = 1 << 20
	}
	return nil
}

// scrolled returns height lines of lines starting at offset, clamped so
// that the last page is full, with a marker when more lines follow.
func (m Model) scrolled(lines []string, offset, height, width int) []string {
	if height <= 0 {
		return nil
	}
	if len(lines) <= height {
		return lines
	}
	offset = min(max(offset, 0), len(lines)-height)
	out := append([]string(nil), lines[offset:offset+height]...)
	if offset+height < len(lines) {
		out[height-1] = m.st.faint.Render(truncate("↓ more · j/k scroll", width))
	}
	return out
}
