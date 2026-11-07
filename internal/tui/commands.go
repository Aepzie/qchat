package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/craguS/qchat/internal/client"
)

// command is one entry of the command palette.
type command struct {
	name    string
	summary string
}

// commands lists every command, in palette order.
var commands = []command{
	{"/help", "commands and keys"},
	{"/status", "connection details"},
	{"/fingerprint", "pinned server key"},
	{"/clear", "clear this history"},
	{"/quit", "exit qchat"},
}

// paletteQuery returns the command prefix being typed, or false if the input
// is not a command in progress.
func paletteQuery(input string) (string, bool) {
	if !strings.HasPrefix(input, "/") || strings.ContainsAny(input, " \t\n") {
		return "", false
	}
	return input, true
}

// matchCommands returns the commands whose name starts with prefix.
func matchCommands(prefix string) []command {
	var out []command
	for _, c := range commands {
		if strings.HasPrefix(c.name, strings.ToLower(prefix)) {
			out = append(out, c)
		}
	}
	return out
}

// resolveCommand maps typed input to a command name. An exact name wins;
// otherwise the palette selection is used if the input is a prefix of it.
func resolveCommand(input string, selected int) (string, bool) {
	name := strings.ToLower(strings.Fields(input)[0])
	for _, c := range commands {
		if c.name == name {
			return name, true
		}
	}
	matches := matchCommands(name)
	if len(matches) == 0 {
		return "", false
	}
	return matches[clampIndex(selected, len(matches))].name, true
}

func clampIndex(i, n int) int {
	if n == 0 {
		return 0
	}
	if i < 0 {
		return 0
	}
	if i >= n {
		return n - 1
	}
	return i
}

// runCommand executes a command line that starts with "/".
func (m *Model) runCommand(input string) tea.Cmd {
	name, ok := resolveCommand(input, m.paletteSel)
	if !ok {
		shown := truncate(sanitizeText(strings.Fields(input)[0]), 32)
		m.log(entryError, fmt.Sprintf("Unknown command %s. Type /help to see what is available.", shown))
		return nil
	}
	switch name {
	case "/help":
		m.addOutput("help", helpRows(), "")
	case "/status":
		m.addOutput("status", m.statusRows(), "")
	case "/fingerprint":
		m.addOutput("fingerprint", m.fingerprintRows(),
			"Compare this with the fingerprint published by the server operator, over a channel you trust.")
	case "/clear":
		m.entries = nil
		m.refreshHistory()
	case "/quit":
		m.quitting = true
		return tea.Quit
	}
	return nil
}

func helpRows() []row {
	var rows []row
	for _, c := range commands {
		rows = append(rows, row{c.name, c.summary})
	}
	return append(rows,
		row{"insert", "enter send · esc normal mode · tab complete · pgup/pgdn scroll"},
		row{"normal", "i insert · j/k line · ctrl+d/u half page · g/G top/bottom · : command · q quit"},
		row{"notes", "Text you type stays on this device and is never sent. Encrypted messaging arrives in a later version."},
	)
}

func (m *Model) statusRows() []row {
	c := m.conn
	state := c.state.String()
	switch {
	case c.blocked:
		state = "blocked: server key mismatch"
	case c.state == client.Connected && !c.info.ConnectedAt.IsZero():
		state = "connected since " + c.info.ConnectedAt.Format("15:04:05")
	case c.state == 0:
		state = "starting"
	}
	rows := []row{
		{"state", state},
		{"server", sanitizeText(m.cfg.Addr)},
		{"transport", client.TransportDescription + " (required)"},
	}
	if c.state == client.Connected {
		rows = append(rows, row{"protocol", fmt.Sprintf("v%d · keepalive %s", c.info.ProtocolVersion, c.info.PingInterval)})
		if c.hasRTT {
			rows = append(rows, row{"latency", formatRTT(c.rtt)})
		}
	}
	rows = append(rows,
		row{"pin", m.pinGrouped()},
		row{"tor", onOff(m.cfg.Tor)},
		row{"e2e", "not yet · this version sends no messages"},
	)
	return rows
}

func (m *Model) fingerprintRows() []row {
	return []row{
		{"grouped", m.pinGrouped()},
		{"canonical", m.cfg.Pin.String()},
	}
}

// pinGrouped returns the full grouped pin, split into lines that fit the
// history pane.
func (m *Model) pinGrouped() string {
	width := m.historyWidth() - bodyIndent - len("canonical") - 2
	return strings.Join(fingerprintLines(m.cfg.Pin, width), "\n")
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// formatRTT renders a round-trip time for the status bar.
func formatRTT(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return "<1 ms"
	case d < 10*time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.1f s", d.Seconds())
	}
}
