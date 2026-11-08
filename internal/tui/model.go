// Package tui is the terminal user interface of the qchat client, built on
// Bubble Tea.
//
// The Model is a pure state machine: it reacts to window sizes, keys, mouse
// wheel events, client.Session events and ChatEvents from the application
// layer, and renders a View. Everything that may block, network and disk
// alike, happens behind the Backend interface, which the model only calls
// from tea.Cmds. Tests can therefore drive it entirely by feeding messages to
// Update and inspecting View.
//
// The interface is honest about what Phases 3 and 4 protect: messages to
// contacts and groups are end-to-end encrypted and the relay stores them
// until they are delivered, but the relay sees who talks to whom, the
// recipients of every group message, when and how much. Notes typed in the
// System conversation never leave the device.
//
// CreateProfileModel and UnlockModel are separate small models for the
// steps before the chat starts.
package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"github.com/Aepzie/qchat/internal/client"
	"github.com/Aepzie/qchat/internal/transport"
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
	// Backend provides contacts and messaging. Nil means no identity is
	// loaded: the interface then works as a connection monitor with local
	// notes, and messaging commands explain that they are unavailable.
	Backend Backend
	// ChatEvents carries events from the application layer. It may be nil.
	ChatEvents <-chan ChatEvent
	// Tor reports whether connections go through Tor.
	Tor bool
	// Version is the client version shown in the footer and welcome text.
	Version string
	// Theme selects colors; the zero value means DefaultTheme.
	Theme Theme
	// Now returns the current time, for timestamps. Nil means time.Now.
	Now func() time.Time
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

// chatEventMsg carries one event from the application layer.
type chatEventMsg struct{ event ChatEvent }

// chatClosedMsg reports that the ChatEvents channel was closed.
type chatClosedMsg struct{}

// Model is the Bubble Tea model of the client. Create it with New.
type Model struct {
	cfg Config
	st  styles

	width, height int
	mode          Mode

	conn      connStatus
	awaitRTT  bool
	ended     bool
	chatEnded bool
	// sealed reports that the anonymous sealed sender connection is up.
	sealed bool

	self    SelfInfo
	hasSelf bool

	convs []conversation
	// open is the key of the conversation shown; cursor the key of the
	// sidebar row selected with J/K in normal mode.
	open, cursor string

	renderedLines []string
	renderedWidth int

	history viewport.Model
	input   inputLine

	overlay overlay
	confirm confirmation

	nextLocalID    int
	paletteSel     int
	completionBase string
	quitting       bool
	// searchSeq numbers searches, so that only the latest answer is shown.
	searchSeq int
}

// New returns a Model in insert mode, ready for its first WindowSizeMsg.
func New(cfg Config) Model {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	m := Model{
		cfg:    cfg,
		st:     newStyles(cfg.Theme),
		mode:   ModeInsert,
		convs:  []conversation{{key: systemKey, kind: convSystem, loaded: true}},
		open:   systemKey,
		cursor: systemKey,
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
	if cfg.Backend == nil {
		m.log(entrySystem, fmt.Sprintf("qchat %s · connection preview. No identity is loaded, so messaging is off; notes you type stay on this device.", sanitizeText(version)))
		return m
	}
	m.log(entrySystem, fmt.Sprintf("qchat %s · messages to contacts are end-to-end encrypted with forward secrecy. "+
		"The relay stores messages until they are delivered and sees who talks to whom and when. "+
		"Notes typed here in System stay on this device.", sanitizeText(version)))
	return m
}

// Mode returns the current input mode.
func (m Model) Mode() Mode { return m.mode }

// State returns the last connection state reported by the session, or zero
// before the first event.
func (m Model) State() client.State { return m.conn.state }

// Quitting reports whether the user asked to quit.
func (m Model) Quitting() bool { return m.quitting }

// Init starts listening for events and loads the identity and contacts.
func (m Model) Init() tea.Cmd {
	return tea.Batch(m.listen(), m.listenChat(), m.loadSettings(), m.loadSelf(), m.loadContacts(), m.loadGroups())
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

// listenChat waits for the next event from the application layer.
func (m Model) listenChat() tea.Cmd {
	ch := m.cfg.ChatEvents
	if ch == nil || m.chatEnded {
		return nil
	}
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return chatClosedMsg{}
		}
		return chatEventMsg{event: ev}
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
		m.layout()
		return m, m.listen()
	case sessionClosedMsg:
		m.ended = true
		return m, nil
	case chatEventMsg:
		cmd := m.handleChatEvent(msg.event)
		m.layout()
		return m, tea.Batch(cmd, m.listenChat())
	case chatClosedMsg:
		m.chatEnded = true
		return m, nil
	case tea.KeyPressMsg:
		cmd := m.handleKey(msg)
		m.layout()
		return m, cmd
	case tea.MouseWheelMsg:
		if m.overlay.kind != overlayNone {
			return m, nil
		}
		var cmd tea.Cmd
		m.history, cmd = m.history.Update(msg)
		return m, cmd
	case tea.PasteMsg:
		if m.overlay.kind == overlayNone && !m.confirm.active && m.mode == ModeInsert && m.input.Update(msg) {
			m.resetPalette()
		}
		m.layout()
		return m, nil
	}
	if cmd, ok := m.handleResult(msg); ok {
		m.layout()
		return m, cmd
	}
	return m, nil
}

// handleKey dispatches a key press according to what has focus.
func (m *Model) handleKey(msg tea.KeyPressMsg) tea.Cmd {
	if msg.String() == "ctrl+c" {
		m.quitting = true
		return tea.Quit
	}
	if m.overlay.kind != overlayNone {
		return m.handleOverlayKey(msg)
	}
	if m.confirm.active {
		return m.handleConfirmKey(msg)
	}
	switch msg.String() {
	case "ctrl+n":
		return m.step(1)
	case "ctrl+p":
		return m.step(-1)
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
	case "enter":
		cmd := m.openConversation(m.cursor)
		m.setMode(ModeInsert)
		return cmd
	case "i", "a":
		m.setMode(ModeInsert)
	case ":", "/":
		m.setMode(ModeInsert)
		m.input.SetValue("/")
	case "J", "shift+j":
		m.moveCursor(1)
	case "K", "shift+k":
		m.moveCursor(-1)
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
// Entering normal mode puts the sidebar cursor on the open conversation.
func (m *Model) setMode(mode Mode) {
	m.mode = mode
	m.resetPalette()
	if mode == ModeNormal {
		m.cursor = m.open
		m.input.Blur()
		return
	}
	m.input.Focus()
}

// submit handles enter in insert mode: run a command, send a message to the
// open contact, or record a local note.
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
	c := m.openConv()
	switch c.kind {
	case convContact:
		return m.sendMessage(c, raw)
	case convRequests:
		m.log(entryWarn, "Message requests cannot be answered. Add the sender with /add <qc1-id> [name] first.")
		return nil
	case convGroup:
		switch {
		case c.group.Left:
			m.log(entryWarn, "You are no longer a member of this group.")
			return nil
		case c.group.Invite:
			m.log(entryWarn, "Accept the invitation with /group accept first, or decline it with /group leave.")
			return nil
		}
		return m.sendMessage(c, raw)
	}
	m.add(entry{kind: entryNote, text: sanitizeText(raw)})
	m.history.GotoBottom()
	return nil
}

// complete performs tab completion. A command name is completed, cycling
// through the matches on repeated presses; "/add " is completed with the ID
// of a pending message request.
func (m *Model) complete() {
	if m.completeAddArgument() {
		return
	}
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

// completeAddArgument completes "/add " with the next unknown sender's ID.
func (m *Model) completeAddArgument() bool {
	value := m.input.Value()
	fields := strings.Fields(value)
	if len(fields) == 0 || strings.ToLower(fields[0]) != "/add" || !strings.Contains(value, " ") || len(fields) > 2 {
		return false
	}
	req := m.conv(requestsKey)
	if req == nil || len(req.senders) == 0 {
		return true
	}
	next := req.senders[0]
	if len(fields) == 2 {
		if i := slices.Index(req.senders, fields[1]); i >= 0 {
			next = req.senders[(i+1)%len(req.senders)]
		}
	}
	m.input.SetValue("/add " + next + " ")
	return true
}

// paletteMatches returns the commands matching the input, and false when
// the palette is not open.
func (m *Model) paletteMatches() ([]command, bool) {
	if m.mode != ModeInsert || m.confirm.active || m.overlay.kind != overlayNone {
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

// handleEvent records a session event in the status and the System log.
func (m *Model) handleEvent(ev client.Event) {
	switch e := ev.(type) {
	case client.StateChanged:
		m.handleState(e)
	case client.RTT:
		m.conn.rtt, m.conn.hasRTT = e.Duration, true
		if m.awaitRTT {
			m.awaitRTT = false
			m.sysLog(entrySystem, "Round-trip time "+formatRTT(e.Duration)+".")
		}
	case client.ServerError:
		text := "Server error " + e.Code.String()
		if e.Message != "" {
			text += ": " + client.SanitizeASCII(e.Message, 256)
		}
		m.sysLog(entryError, text+".")
	case client.SecurityAlert:
		m.conn.blocked = true
		m.addTo(systemKey, entry{kind: entryAlert, alert: e, addr: sanitizeText(m.cfg.Addr)})
		if m.open == systemKey {
			m.history.GotoBottom()
		}
	}
}

func (m *Model) handleState(e client.StateChanged) {
	m.conn.state = e.State
	addr := sanitizeText(m.cfg.Addr)
	switch e.State {
	case client.Connecting:
		m.conn.hasRTT = false
		if e.Attempt > 1 {
			m.sysLog(entrySystem, fmt.Sprintf("Reconnecting to %s (attempt %d)…", addr, e.Attempt))
			return
		}
		m.sysLog(entrySystem, "Connecting to "+addr+"…")
	case client.Authenticating:
		m.sysLog(entrySystem, "Signing in with your identity…")
	case client.Connected:
		m.conn.info = e.Info
		m.awaitRTT = true
		m.sysLog(entryGood, "Connected to "+addr+".")
		m.sysLog(entrySystem, fmt.Sprintf("%s · protocol v%d · keepalive %s",
			sanitizeText(e.Info.Transport), e.Info.ProtocolVersion, e.Info.PingInterval))
		m.sysLog(entrySystem, "Server key matches pin "+shortFingerprint(m.cfg.Pin)+"…")
	case client.Disconnected:
		m.conn.hasRTT = false
		if e.Err == nil {
			m.sysLog(entrySystem, "Disconnected.")
			return
		}
		text := "Connection lost: " + describeError(e.Err) + "."
		if e.RetryIn > 0 {
			text += " Retrying in " + formatDelay(e.RetryIn) + "."
		}
		m.sysLog(entryWarn, text)
	case client.Failed:
		m.conn.hasRTT = false
		if m.conn.blocked {
			m.sysLog(entryError, "Connection blocked. qchat will not reconnect on its own.")
			return
		}
		m.sysLog(entryError, "Stopped: "+describeError(e.Err)+". qchat will not reconnect on its own.")
	}
}

// log appends a one-line message to the open conversation.
func (m *Model) log(kind entryKind, text string) {
	m.add(entry{kind: kind, text: sanitizeText(text)})
}

// sysLog appends a one-line message to the System conversation.
func (m *Model) sysLog(kind entryKind, text string) {
	m.addTo(systemKey, entry{kind: kind, text: sanitizeText(text)})
}

// addOutput appends command output and scrolls to it.
func (m *Model) addOutput(title string, rows []row, note string) {
	for i := range rows {
		rows[i].value = sanitizeText(rows[i].value)
	}
	m.add(entry{kind: entryOutput, title: title, rows: rows, text: sanitizeText(note)})
	m.history.GotoBottom()
}

// add appends an entry to the open conversation, keeping the view pinned to
// the bottom if it was.
func (m *Model) add(e entry) {
	m.addTo(m.open, e)
}

// addTo appends an entry to a conversation. Warnings and errors in a
// conversation that is not open count as unread.
func (m *Model) addTo(key string, e entry) {
	c := m.conv(key)
	if c == nil {
		return
	}
	if e.at.IsZero() {
		e.at = m.cfg.Now()
	}
	c.entries = append(c.entries, e)
	trimmed := len(c.entries) > maxEntries
	if trimmed {
		c.entries = append([]entry(nil), c.entries[len(c.entries)-maxEntries:]...)
	}
	if key != m.open {
		if e.kind == entryWarn || e.kind == entryError || e.kind == entryAlert {
			c.unread++
		}
		return
	}
	if trimmed || e.file != nil {
		m.renderedWidth = 0
	}
	if m.renderedWidth > 0 {
		if n := len(c.entries); n > 1 {
			m.renderedLines = append(m.renderedLines, separator(c.entries[n-2], e, m.renderedWidth, m.st)...)
		}
		m.renderedLines = append(m.renderedLines, renderEntry(e, m.renderedWidth, m.st)...)
	}
	m.syncHistory()
}

// refreshHistory re-renders every entry of the open conversation, after a
// width change, a switch of conversation or a change to an entry.
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
		m.renderedLines = renderEntries(m.openConv().entries, width, m.st)
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

// describeBackendError renders an error returned by the Backend as one
// sanitised line.
func describeBackendError(err error) string {
	if err == nil {
		return "unknown error"
	}
	msg := strings.TrimSuffix(cleanLine(err.Error(), 300), ".")
	if msg == "" {
		return "unknown error"
	}
	return msg
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
