package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

// fileSendTimeout bounds SendFile, which returns once the offer is sent.
const fileSendTimeout = 2 * time.Minute

// timerCommands are the palette entries for the argument of /timer.
var timerCommands = []command{
	{"/timer off", "keep messages"},
	{"/timer 30s", "delete messages 30 seconds after they are sent or received"},
	{"/timer 5m", "after 5 minutes"},
	{"/timer 1h", "after an hour"},
	{"/timer 1d", "after a day"},
	{"/timer 1w", "after a week"},
}

// Results of the file and timer calls.
type (
	sendFileResultMsg struct {
		contactID, localID string
		message            MessageInfo
		err                error
	}
	saveFileResultMsg struct {
		contactID, name, path string
		err                   error
	}
	timerResultMsg struct {
		contactID string
		duration  time.Duration
		set       bool
		err       error
	}
)

func (m *Model) fileBackend() FileBackend {
	fb, _ := m.cfg.Backend.(FileBackend)
	return fb
}

func (m *Model) timerBackend() TimerBackend {
	tb, _ := m.cfg.Backend.(TimerBackend)
	return tb
}

// requireConversation returns the open contact or group conversation, or
// nil after explaining that the command needs one.
func (m *Model) requireConversation(name string) *conversation {
	if !m.requireBackend() {
		return nil
	}
	c := m.openConv()
	if c.kind != convContact && c.kind != convGroup {
		m.log(entryError, "Open a contact or group first (ctrl+n / ctrl+p), then run "+name+".")
		return nil
	}
	return c
}

// cleanFile sanitises a FileInfo from the Backend.
func cleanFile(f *FileInfo) *FileInfo {
	if f == nil {
		return nil
	}
	out := *f
	out.Name = cleanLine(f.Name, 255)
	out.MIME = cleanLine(f.MIME, 127)
	out.Done, out.Total = max(f.Done, 0), max(f.Total, 0)
	return &out
}

// formatSize renders a byte count with a binary unit.
func formatSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(max(n, 0), 10) + " B"
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// fileBody is the text of a file message.
func fileBody(e entry) string {
	f := e.file
	label := "file"
	if e.fileNo > 0 {
		label = "file " + strconv.Itoa(e.fileNo)
	}
	parts := []string{label, f.Name, formatSize(f.Size)}
	switch f.State {
	case FileReceiving, FileSending:
		progress := f.State.String()
		if f.Total > 0 {
			progress += fmt.Sprintf(" %d/%d (%d%%)", f.Done, f.Total, f.Done*100/f.Total)
		}
		parts = append(parts, progress)
	case FileComplete:
		if e.fileNo > 0 {
			parts = append(parts, "complete · /save "+strconv.Itoa(e.fileNo)+" to keep a copy")
		} else {
			parts = append(parts, "complete")
		}
	default:
		parts = append(parts, f.State.String())
	}
	return strings.Join(parts, " · ")
}

// numberFiles numbers the file messages of entries in order, from 1, as
// /save refers to them.
func numberFiles(entries []entry) []entry {
	n := 0
	for i := range entries {
		if entries[i].kind == entryMessage && entries[i].file != nil {
			n++
			entries[i].fileNo = n
		}
	}
	return entries
}

// fileEntries returns the file messages of a conversation, in /save order.
func fileEntries(c *conversation) []entry {
	var out []entry
	for _, e := range c.entries {
		if e.kind == entryMessage && e.file != nil {
			out = append(out, e)
		}
	}
	return out
}

// cmdSendFile runs /send <path>.
func (m *Model) cmdSendFile(name, rest string) tea.Cmd {
	c := m.requireConversation(name)
	if c == nil {
		return nil
	}
	fb := m.fileBackend()
	if fb == nil {
		m.log(entryError, "Sending files is not available.")
		return nil
	}
	path := expandPath(strings.Trim(strings.TrimSpace(rest), `"'`))
	if path == "" {
		m.log(entryError, "usage: "+name+" <path>")
		return nil
	}
	m.nextLocalID++
	localID := fmt.Sprintf("%s%d", localIDPrefix, m.nextLocalID)
	m.add(entry{kind: entryMessage, text: sanitizeText(filepath.Base(path)), from: "you", msgID: localID, outgoing: true, status: StatusSending,
		file: &FileInfo{Name: cleanLine(filepath.Base(path), 255), State: FileSending}})
	m.history.GotoBottom()
	id := c.key
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), fileSendTimeout)
		defer cancel()
		mi, err := fb.SendFile(ctx, id, path)
		return sendFileResultMsg{contactID: id, localID: localID, message: mi, err: err}
	}
}

// expandPath expands a leading "~" to the home directory.
func expandPath(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[1:])
}

func (m *Model) applySendFile(msg sendFileResultMsg) {
	c := m.conv(msg.contactID)
	if c == nil {
		return
	}
	for i := range c.entries {
		e := &c.entries[i]
		if e.kind != entryMessage || e.msgID != msg.localID {
			continue
		}
		if msg.err != nil {
			e.status, e.errText = StatusFailed, describeBackendError(msg.err)
			e.file.State = FileFailed
		} else {
			if msg.message.ID != "" {
				e.msgID = msg.message.ID
			}
			e.status, e.errText = msg.message.Status, cleanLine(msg.message.Error, 300)
			if f := cleanFile(msg.message.File); f != nil {
				e.file = f
			}
		}
		m.refreshIfOpen(msg.contactID)
		return
	}
}

// refreshIfOpen redraws the history if key is the open conversation.
func (m *Model) refreshIfOpen(key string) {
	if key == m.open {
		m.refreshHistory()
	}
}

// cmdSave runs /save [n [dir]]: without arguments it lists the files of
// the conversation.
func (m *Model) cmdSave(args []string, rest string) tea.Cmd {
	c := m.requireConversation("/save")
	if c == nil {
		return nil
	}
	fb := m.fileBackend()
	if fb == nil {
		m.log(entryError, "Saving files is not available.")
		return nil
	}
	files := fileEntries(c)
	if len(args) == 0 {
		if len(files) == 0 {
			m.log(entrySystem, "No files in this conversation.")
			return nil
		}
		rows := make([]row, len(files))
		for i, e := range numberFiles(files) {
			rows[i] = row{strconv.Itoa(i + 1), fileBody(e)}
		}
		m.addOutput("files", rows, "Save one with /save <n> [directory]. Without a directory it goes to your Downloads folder.")
		return nil
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n < 1 || n > len(files) {
		m.log(entryError, fmt.Sprintf("No file %s here. Type /save to list the files.", truncate(sanitizeText(args[0]), 16)))
		return nil
	}
	e := files[n-1]
	if strings.HasPrefix(e.msgID, localIDPrefix) {
		m.log(entryError, "That file is still being offered.")
		return nil
	}
	dir := expandPath(strings.Trim(strings.TrimSpace(strings.TrimPrefix(rest, args[0])), `"'`))
	id, msgID, name := c.key, e.msgID, e.file.Name
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
		defer cancel()
		path, err := fb.SaveFile(ctx, id, msgID, dir)
		return saveFileResultMsg{contactID: id, name: name, path: path, err: err}
	}
}

func (m *Model) applySaveFile(msg saveFileResultMsg) {
	if msg.err != nil {
		m.addTo(msg.contactID, entry{kind: entryError, text: "Cannot save " + sanitizeText(msg.name) + ": " + describeBackendError(msg.err) + "."})
		return
	}
	m.addTo(msg.contactID, entry{kind: entryGood, text: "Saved " + sanitizeText(msg.name) + " as " + cleanLine(msg.path, 400) +
		". The saved copy is not encrypted."})
}

// parseTimer parses a /timer argument: "off" or a whole number followed by
// s, m, h, d or w.
func parseTimer(s string) (time.Duration, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "off" || s == "0" {
		return 0, true
	}
	if len(s) < 2 {
		return 0, false
	}
	units := map[byte]time.Duration{'s': time.Second, 'm': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour, 'w': 7 * 24 * time.Hour}
	unit, ok := units[s[len(s)-1]]
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 || n > 10000 {
		return 0, false
	}
	return time.Duration(n) * unit, true
}

// formatTimer renders a timer the way /timer accepts it.
func formatTimer(d time.Duration) string {
	if d <= 0 {
		return "off"
	}
	for _, u := range []struct {
		suffix string
		size   time.Duration
	}{{"w", 7 * 24 * time.Hour}, {"d", 24 * time.Hour}, {"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}} {
		if d%u.size == 0 {
			return strconv.FormatInt(int64(d/u.size), 10) + u.suffix
		}
	}
	return d.String()
}

// cmdTimer runs /timer [off|<duration>].
func (m *Model) cmdTimer(args []string) tea.Cmd {
	c := m.requireConversation("/timer")
	if c == nil {
		return nil
	}
	tb := m.timerBackend()
	if tb == nil {
		m.log(entryError, "Disappearing messages are not available.")
		return nil
	}
	id := c.key
	if len(args) == 0 {
		return func() tea.Msg {
			d, err := tb.Timer(id)
			return timerResultMsg{contactID: id, duration: d, err: err}
		}
	}
	d, ok := parseTimer(args[0])
	if !ok || len(args) > 1 {
		m.log(entryError, "usage: /timer off|30s|5m|1h|1d|1w")
		return nil
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
		defer cancel()
		return timerResultMsg{contactID: id, duration: d, set: true, err: tb.SetTimer(ctx, id, d)}
	}
}

func (m *Model) applyTimer(msg timerResultMsg) {
	switch {
	case msg.err != nil:
		m.addTo(msg.contactID, entry{kind: entryError, text: "Cannot change disappearing messages: " + describeBackendError(msg.err) + "."})
	case !msg.set && msg.duration == 0:
		m.addTo(msg.contactID, entry{kind: entrySystem, text: "Disappearing messages are off. Turn them on with /timer 1d (or 30s, 5m, 1h, 1w)."})
	case !msg.set:
		m.addTo(msg.contactID, entry{kind: entrySystem, text: "Disappearing messages: new messages are deleted " + formatTimer(msg.duration) + " after they are sent or received."})
	case msg.duration == 0:
		m.addTo(msg.contactID, entry{kind: entrySystem, text: "You turned disappearing messages off."})
	default:
		m.addTo(msg.contactID, entry{kind: entrySystem, text: "You set disappearing messages to " + formatTimer(msg.duration) +
			". Messages from now on are deleted that long after they are sent or received, on both sides; the other side can still copy them."})
	}
}

// fileChanged updates the file message an event refers to.
func (m *Model) fileChanged(e FileChanged) {
	key := cleanLine(e.ConversationID, 128)
	c := m.conv(key)
	if c == nil || e.MessageID == "" {
		return
	}
	for i := range c.entries {
		x := &c.entries[i]
		if x.kind == entryMessage && x.msgID == e.MessageID && x.file != nil {
			x.file = cleanFile(&e.File)
			m.refreshIfOpen(key)
			return
		}
	}
}

// messagesExpired removes deleted disappearing messages, also from
// Message requests.
func (m *Model) messagesExpired(e MessagesExpired) {
	key := cleanLine(e.ConversationID, 128)
	gone := func(x entry) bool { return x.kind == entryMessage && slices.Contains(e.MessageIDs, x.msgID) }
	if c := m.conv(key); c != nil {
		c.entries = slices.DeleteFunc(c.entries, gone)
		m.refreshIfOpen(key)
	}
	if req := m.conv(requestsKey); req != nil {
		req.entries = slices.DeleteFunc(req.entries, func(x entry) bool { return x.sender == key && gone(x) })
		m.refreshIfOpen(requestsKey)
	}
}

// conversationNotice shows a system line in a conversation.
func (m *Model) conversationNotice(e ConversationNotice) {
	key := cleanLine(e.ConversationID, 128)
	if notice := cleanLine(e.Notice, 600); notice != "" && m.conv(key) != nil {
		m.addTo(key, entry{kind: entrySystem, text: notice})
	}
}
