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
	{"/add", "add a contact: /add <qc1-id> [name]"},
	{"/verify", "compare safety numbers"},
	{"/rename", "rename this contact"},
	{"/remove", "remove this contact"},
	{"/whoami", "your ID and QR code"},
	{"/status", "connection details"},
	{"/fingerprint", "pinned server key"},
	{"/clear", "clear this view"},
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
	fields := strings.Fields(input)
	rest := strings.TrimSpace(strings.TrimPrefix(input, fields[0]))
	switch name {
	case "/add":
		return m.cmdAdd(fields[1:])
	case "/rename":
		return m.cmdRename(rest)
	case "/remove":
		if c := m.requireContact(name); c != nil {
			m.confirm = confirmation{active: true, contactID: c.contact.ID, name: c.contact.label()}
		}
	case "/verify":
		if c := m.requireContact(name); c != nil {
			return verificationCmd(m.cfg.Backend, c.contact.ID)
		}
	case "/whoami":
		if m.requireBackend() {
			m.openWhoami()
		}
	case "/help":
		m.addOutput("help", helpRows(), "")
	case "/status":
		m.addOutput("status", m.statusRows(), "")
	case "/fingerprint":
		m.addOutput("fingerprint", m.fingerprintRows(),
			"Compare this with the fingerprint published by the server operator, over a channel you trust.")
	case "/clear":
		m.openConv().entries = nil
		m.refreshHistory()
	case "/quit":
		m.quitting = true
		return tea.Quit
	}
	return nil
}

// requireBackend reports whether messaging is available, explaining why
// not otherwise.
func (m *Model) requireBackend() bool {
	if m.cfg.Backend == nil || !m.hasSelf {
		m.log(entryError, "Messaging is off: no identity is loaded.")
		return false
	}
	return true
}

// requireContact returns the open contact conversation, or nil after
// explaining that the command needs one.
func (m *Model) requireContact(name string) *conversation {
	if !m.requireBackend() {
		return nil
	}
	c := m.openConv()
	if c.kind != convContact {
		m.log(entryError, "Open a contact first (ctrl+n / ctrl+p), then run "+name+".")
		return nil
	}
	return c
}

func (m *Model) cmdAdd(args []string) tea.Cmd {
	if !m.requireBackend() {
		return nil
	}
	id, name, err := parseAddArgs(args)
	if err != nil {
		m.log(entryError, sanitizeText(err.Error())+".")
		return nil
	}
	if id == m.self.ID {
		m.log(entryError, "That is your own ID.")
		return nil
	}
	if c := m.conv(id); c != nil {
		m.log(entryError, "Already in your contacts as "+c.contact.label()+".")
		return nil
	}
	m.log(entrySystem, "Looking up "+shortID(id)+" on the relay…")
	return addCmd(m.cfg.Backend, id, name)
}

func (m *Model) cmdRename(rest string) tea.Cmd {
	c := m.requireContact("/rename")
	if c == nil {
		return nil
	}
	name := cleanLine(rest, maxNameRunes)
	if name == "" {
		m.log(entryError, "usage: /rename <name>")
		return nil
	}
	return renameCmd(m.cfg.Backend, c.contact.ID, name)
}

func helpRows() []row {
	var rows []row
	for _, c := range commands {
		rows = append(rows, row{c.name, c.summary})
	}
	return append(rows,
		row{"any mode", "ctrl+n / ctrl+p next or previous conversation"},
		row{"insert", "enter send · esc normal mode · tab complete · pgup/pgdn scroll"},
		row{"normal", "J/K select · enter open · i insert · j/k line · ctrl+d/u half page · g/G top/bottom · : command · q quit"},
		row{"status", "… sending · ✓ sent, stored by the relay until delivered · ⧗ recipient offline, not delivered (old relays) · ✕ not sent · ◷ sender clock off"},
		row{"contacts", "✓ verified · ⚠ safety number changed, run /verify"},
		row{"privacy", "Messages to contacts are end-to-end encrypted with forward secrecy; session starts are signed. The relay sees who talks to whom, when, and message sizes. Notes typed in System stay on this device."},
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
	)
	if m.cfg.Backend == nil {
		return append(rows, row{"e2e", "off · no identity loaded"})
	}
	if m.hasSelf {
		rows = append(rows, row{"identity", m.self.ShortID})
	}
	return append(rows,
		row{"e2e", "prekey sessions and KEM ratchet with ML-KEM-768 + X25519, session starts signed with Ed25519 + ML-DSA-65"},
		row{"limits", "the relay sees sender, recipient, time and size · not independently audited"},
	)
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
