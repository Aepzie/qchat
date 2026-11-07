// Package tui is the terminal user interface of the qchat client, built on
// Bubble Tea.
//
// The Model is a pure state machine: it reacts to window sizes, keys, mouse
// wheel events and client.Session events, and renders a View. All network
// activity happens in package client; the model only listens to the event
// channel through a tea.Cmd. Tests can therefore drive it entirely by
// feeding messages to Update and inspecting View.
//
// Nothing typed into the interface leaves the machine in this version:
// notes are shown locally, labelled as such, and the status bar says plainly
// that end-to-end encryption is not available yet.
package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/transport"
)

// Minimum terminal size for the full layout.
const (
	MinWidth  = 40
	MinHeight = 10
)

// Mode is the input mode, in the style of vim.
type Mode uint8

const (
	// ModeInsert sends keystrokes to the input line.
	ModeInsert Mode = iota
	// ModeNormal uses single keys for navigation.
	ModeNormal
)

// String returns the mode name as shown in the footer.
func (m Mode) String() string {
	if m == ModeNormal {
		return "NORMAL"
	}
	return "INSERT"
}

// Config configures a Model.
type Config struct {
	// Addr is the server address shown to the user.
	Addr string
	// Pin is the pinned server fingerprint.
	Pin transport.Fingerprint
	// Events is the session's event channel. It may be nil, for example in
	// tests that inject events directly.
	Events <-chan client.Event
	// Tor reports whether connections go through Tor.
	Tor bool
	// Version is the client version shown in the footer and welcome text.
	Version string
	// Theme selects colors; the zero value means DefaultTheme.
	Theme Theme
	// Now returns the current time, for timestamps. Nil means time.Now.
	Now func() time.Time
}

// conversation is one entry of the sidebar.
type conversation struct {
	name   string
	unread int
}

// connStatus is what the interface knows about the connection.
type connStatus struct {
	state   client.State
	info    client.ConnectionInfo
	rtt     time.Duration
	hasRTT  bool
	blocked bool
}

// sessionEventMsg carries one event from the session channel.
type sessionEventMsg struct{ event client.Event }

// sessionClosedMsg reports that the session's event channel was closed.
type sessionClosedMsg struct{}

// Model is the Bubble Tea model of the client. Create it with New.
type Model struct {
	cfg Config
	st  styles

	width, height int
	mode          Mode

	conn     connStatus
	awaitRTT bool
	ended    bool

	entries       []entry
	renderedLines []string
	renderedWidth int

	history viewport.Model
	input   inputLine

	conversations []conversation
	selected      int

	paletteSel     int
	completionBase string
	quitting       bool
}

// New returns a Model in insert mode, ready for its first WindowSizeMsg.
func New(cfg Config) Model {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	m := Model{
		cfg:           cfg,
		st:            newStyles(cfg.Theme),
		mode:          ModeInsert,
		conversations: []conversation{{name: "System"}},
	}

	m.history = viewport.New()
	m.history.KeyMap = viewport.KeyMap{}
	m.history.MouseWheelEnabled = true
	m.history.MouseWheelDelta = 3

	m.input = newInputLine(m.st)

	version := cfg.Version
	if version == "" {
		version = "dev"
	}
	m.log(entrySystem, fmt.Sprintf("qchat %s · connection preview. Notes you type stay on this device; end-to-end encrypted messaging is not available yet.", sanitizeText(version)))
	return m
}

// Mode returns the current input mode.
func (m Model) Mode() Mode { return m.mode }

// State returns the last connection state reported by the session, or zero
// before the first event.
func (m Model) State() client.State { return m.conn.state }

// Quitting reports whether the user asked to quit.
func (m Model) Quitting() bool { return m.quitting }

// Init starts listening for session events.
func (m Model) Init() tea.Cmd {
	return m.listen()
}

// listen waits for the next session event.
func (m Model) listen() tea.Cmd {
	ch := m.cfg.Events
	if ch == nil || m.ended {
		return nil
	}
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return sessionClosedMsg{}
		}
		return sessionEventMsg{event: ev}
	}
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil
	case sessionEventMsg:
		m.handleEvent(msg.event)
		return m, m.listen()
	case sessionClosedMsg:
		m.ended = true
		return m, nil
	case tea.KeyPressMsg:
		cmd := m.handleKey(msg)
		m.layout()
		return m, cmd
	case tea.MouseWheelMsg:
		var cmd tea.Cmd
		m.history, cmd = m.history.Update(msg)
		return m, cmd
	case tea.PasteMsg:
		if m.mode == ModeInsert && m.input.Update(msg) {
			m.resetPalette()
		}
		m.layout()
		return m, nil
	}
	return m, nil
}

// handleKey dispatches a key press according to the mode.
func (m *Model) handleKey(msg tea.KeyPressMsg) tea.Cmd {
	if msg.String() == "ctrl+c" {
		m.quitting = true
		return tea.Quit
	}
	if m.mode == ModeNormal {
		return m.handleNormalKey(msg)
	}
	return m.handleInsertKey(msg)
}

func (m *Model) handleInsertKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		m.setMode(ModeNormal)
		return nil
	case "enter":
		return m.submit()
	case "tab":
		m.complete()
		return nil
	case "pgup":
		m.history.PageUp()
		return nil
	case "pgdown":
		m.history.PageDown()
		return nil
	case "up", "down":
		if matches, ok := m.paletteMatches(); ok && len(matches) > 0 {
			delta := 1
			if msg.String() == "up" {
				delta = -1
			}
			m.paletteSel = (m.paletteSel + delta + len(matches)) % len(matches)
			return nil
		}
	}
	if m.input.Update(msg) {
		m.resetPalette()
	}
	return nil
}

func (m *Model) handleNormalKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "q":
		m.quitting = true
		return tea.Quit
	case "i", "a", "enter":
		m.setMode(ModeInsert)
	case ":", "/":
		m.setMode(ModeInsert)
		m.input.SetValue("/")
	case "j", "down":
		m.history.ScrollDown(1)
	case "k", "up":
		m.history.ScrollUp(1)
	case "ctrl+d":
		m.history.HalfPageDown()
	case "ctrl+u":
		m.history.HalfPageUp()
	case "ctrl+f", "pgdown", "space":
		m.history.PageDown()
	case "ctrl+b", "pgup":
		m.history.PageUp()
	case "g", "home":
		m.history.GotoTop()
	case "G", "shift+g", "end":
		m.history.GotoBottom()
	}
	return nil
}

// setMode switches modes, moving focus between the input and the history.
func (m *Model) setMode(mode Mode) {
	m.mode = mode
	m.resetPalette()
	if mode == ModeNormal {
		m.input.Blur()
		return
	}
	m.input.Focus()
}

// submit handles enter in insert mode: run a command or record a note.
func (m *Model) submit() tea.Cmd {
	raw := strings.TrimSpace(m.input.Value())
	m.input.Reset()
	defer m.resetPalette()
	if raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "/") {
		return m.runCommand(raw)
	}
	m.add(entry{kind: entryNote, text: sanitizeText(raw)})
	m.history.GotoBottom()
	return nil
}

// complete performs tab completion of command names. Repeated presses cycle
// through the commands matching what was typed before the first press.
func (m *Model) complete() {
	if m.completionBase == "" {
		q, ok := paletteQuery(m.input.Value())
		if !ok {
			return
		}
		m.completionBase = q
	}
	matches := matchCommands(m.completionBase)
	if len(matches) == 0 {
		return
	}
	idx := clampIndex(m.paletteSel, len(matches))
	if m.input.Value() == matches[idx].name {
		idx = (idx + 1) % len(matches)
	}
	m.input.SetValue(matches[idx].name)
	m.paletteSel = idx
}

// paletteMatches returns the commands matching the input, and false when
// the palette is not open.
func (m *Model) paletteMatches() ([]command, bool) {
	if m.mode != ModeInsert {
		return nil, false
	}
	if m.completionBase != "" {
		return matchCommands(m.completionBase), true
	}
	q, ok := paletteQuery(m.input.Value())
	if !ok {
		return nil, false
	}
	return matchCommands(q), true
}

// resetPalette forgets the palette selection and completion state.
func (m *Model) resetPalette() {
	m.paletteSel = 0
	m.completionBase = ""
}

// handleEvent records a session event in the status and history.
func (m *Model) handleEvent(ev client.Event) {
	switch e := ev.(type) {
	case client.StateChanged:
		m.handleState(e)
	case client.RTT:
		m.conn.rtt, m.conn.hasRTT = e.Duration, true
		if m.awaitRTT {
			m.awaitRTT = false
			m.log(entrySystem, "Round-trip time "+formatRTT(e.Duration)+".")
		}
	case client.ServerError:
		text := "Server error " + e.Code.String()
		if e.Message != "" {
			text += ": " + client.SanitizeASCII(e.Message, 256)
		}
		m.log(entryError, text+".")
	case client.SecurityAlert:
		m.conn.blocked = true
		m.add(entry{kind: entryAlert, alert: e, addr: sanitizeText(m.cfg.Addr)})
		m.history.GotoBottom()
	}
}

func (m *Model) handleState(e client.StateChanged) {
	m.conn.state = e.State
	addr := sanitizeText(m.cfg.Addr)
	switch e.State {
	case client.Connecting:
		m.conn.hasRTT = false
		if e.Attempt > 1 {
			m.log(entrySystem, fmt.Sprintf("Reconnecting to %s (attempt %d)…", addr, e.Attempt))
			return
		}
		m.log(entrySystem, "Connecting to "+addr+"…")
	case client.Connected:
		m.conn.info = e.Info
		m.awaitRTT = true
		m.log(entryGood, "Connected to "+addr+".")
		m.log(entrySystem, fmt.Sprintf("%s · protocol v%d · keepalive %s",
			sanitizeText(e.Info.Transport), e.Info.ProtocolVersion, e.Info.PingInterval))
		m.log(entrySystem, "Server key matches pin "+shortFingerprint(m.cfg.Pin)+"…")
	case client.Disconnected:
		m.conn.hasRTT = false
		if e.Err == nil {
			m.log(entrySystem, "Disconnected.")
			return
		}
		text := "Connection lost: " + describeError(e.Err) + "."
		if e.RetryIn > 0 {
			text += " Retrying in " + formatDelay(e.RetryIn) + "."
		}
		m.log(entryWarn, text)
	case client.Failed:
		m.conn.hasRTT = false
		if m.conn.blocked {
			m.log(entryError, "Connection blocked. qchat will not reconnect on its own.")
			return
		}
		m.log(entryError, "Stopped: "+describeError(e.Err)+". qchat will not reconnect on its own.")
	}
}

// log appends a one-line message.
func (m *Model) log(kind entryKind, text string) {
	m.add(entry{kind: kind, text: sanitizeText(text)})
}

// addOutput appends command output and scrolls to it.
func (m *Model) addOutput(title string, rows []row, note string) {
	for i := range rows {
		rows[i].value = sanitizeText(rows[i].value)
	}
	m.add(entry{kind: entryOutput, title: title, rows: rows, text: sanitizeText(note)})
	m.history.GotoBottom()
}

// add appends an entry, keeping the view pinned to the bottom if it was.
func (m *Model) add(e entry) {
	e.at = m.cfg.Now()
	m.entries = append(m.entries, e)
	if len(m.entries) > maxEntries {
		m.entries = append([]entry(nil), m.entries[len(m.entries)-maxEntries:]...)
		m.renderedWidth = 0
	}
	if m.renderedWidth > 0 {
		if len(m.entries) > 1 && (e.standsAlone() || m.entries[len(m.entries)-2].standsAlone()) {
			m.renderedLines = append(m.renderedLines, "")
		}
		m.renderedLines = append(m.renderedLines, renderEntry(e, m.renderedWidth, m.st)...)
	}
	m.syncHistory()
}

// refreshHistory re-renders every entry, after a width change or /clear.
func (m *Model) refreshHistory() {
	m.renderedWidth = 0
	m.syncHistory()
}

// syncHistory pushes the rendered history into the viewport. Short
// histories are bottom-aligned, like a chat.
func (m *Model) syncHistory() {
	width := m.historyWidth()
	if width <= 0 {
		return
	}
	if m.renderedWidth != width {
		m.renderedLines = renderEntries(m.entries, width, m.st)
		m.renderedWidth = width
	}
	atBottom := m.history.AtBottom()
	lines := m.renderedLines
	if pad := m.history.Height() - len(lines); pad > 0 {
		lines = append(make([]string, pad), lines...)
	}
	m.history.SetContentLines(slices.Clone(lines))
	if atBottom {
		m.history.GotoBottom()
	}
}

// describeError turns a session error into a short, human-readable phrase.
func describeError(err error) string {
	var remote *client.RemoteError
	switch {
	case err == nil:
		return "unknown error"
	case errors.Is(err, transport.ErrPinMismatch):
		return "the server key does not match the pinned fingerprint"
	case errors.Is(err, transport.ErrWeakHandshake):
		return "the server did not offer TLS 1.3 with X25519MLKEM768"
	case errors.Is(err, client.ErrIncompatibleVersion):
		return "the server speaks an incompatible protocol version; update qchat"
	case errors.Is(err, client.ErrHandshakeTimeout):
		return "the server did not answer the handshake"
	case errors.Is(err, client.ErrKeepaliveTimeout):
		return "the server stopped responding"
	case errors.As(err, &remote):
		return client.SanitizeASCII(remote.Error(), 300)
	case errors.Is(err, client.ErrProtocolViolation):
		return "the server sent an invalid message"
	case errors.Is(err, client.ErrConnectionLost):
		return "the connection dropped"
	}
	return "cannot reach the server (" + truncate(rootCause(err), 120) + ")"
}

// rootCause returns the message of the innermost wrapped error, which for
// network failures is the useful part ("connection refused").
func rootCause(err error) string {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			break
		}
		err = next
	}
	msg := sanitizeText(err.Error())
	msg = strings.TrimSuffix(strings.TrimSpace(msg), ".")
	for _, prefix := range []string{"transport: ", "client: "} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return msg
}

func formatDelay(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%d ms", d.Milliseconds())
	}
	return d.Round(time.Second).String()
}
