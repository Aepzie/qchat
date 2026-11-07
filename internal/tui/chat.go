package tui

import (
	"context"
	"fmt"
	"slices"
	"time"

	tea "charm.land/bubbletea/v2"
)

const (
	// historyLimit is how many stored messages are loaded per conversation.
	historyLimit = 500
	// backendTimeout bounds calls that involve a relay round trip.
	backendTimeout = 30 * time.Second
	// localIDPrefix marks the temporary ID of a message that the Backend has
	// not answered yet. Real IDs never start with a NUL byte.
	localIDPrefix = "\x00local-"
)

// Results of Backend calls, delivered to Update by the commands below.
type (
	selfMsg     struct{ self SelfInfo }
	contactsMsg struct {
		contacts []ContactInfo
		err      error
	}
	historyMsg struct {
		contactID string
		messages  []MessageInfo
		err       error
	}
	markReadMsg struct {
		contactID string
		err       error
	}
	sendResultMsg struct {
		contactID, localID string
		message            MessageInfo
		err                error
	}
	addResultMsg struct {
		id      string
		contact ContactInfo
		err     error
	}
	renameResultMsg struct {
		contactID, name string
		err             error
	}
	removeResultMsg struct {
		contactID, name string
		err             error
	}
	verificationMsg struct {
		contactID string
		info      VerificationInfo
		err       error
	}
	markVerifiedMsg struct {
		contactID string
		verified  bool
		err       error
	}
)

func (m *Model) loadSelf() tea.Cmd {
	b := m.cfg.Backend
	if b == nil {
		return nil
	}
	return func() tea.Msg { return selfMsg{self: b.Self()} }
}

func (m *Model) loadContacts() tea.Cmd {
	b := m.cfg.Backend
	if b == nil {
		return nil
	}
	return func() tea.Msg {
		contacts, err := b.Contacts()
		return contactsMsg{contacts: contacts, err: err}
	}
}

func (m *Model) loadHistory(id string) tea.Cmd {
	b := m.cfg.Backend
	if b == nil {
		return nil
	}
	return func() tea.Msg {
		msgs, err := b.History(id, historyLimit)
		return historyMsg{contactID: id, messages: msgs, err: err}
	}
}

func (m *Model) markRead(id string) tea.Cmd {
	b := m.cfg.Backend
	if b == nil {
		return nil
	}
	return func() tea.Msg { return markReadMsg{contactID: id, err: b.MarkRead(id)} }
}

func sendCmd(b Backend, id, localID, text string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
		defer cancel()
		msg, err := b.Send(ctx, id, text)
		return sendResultMsg{contactID: id, localID: localID, message: msg, err: err}
	}
}

func addCmd(b Backend, id, name string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
		defer cancel()
		c, err := b.AddContact(ctx, id, name)
		return addResultMsg{id: id, contact: c, err: err}
	}
}

func renameCmd(b Backend, id, name string) tea.Cmd {
	return func() tea.Msg { return renameResultMsg{contactID: id, name: name, err: b.RenameContact(id, name)} }
}

func removeCmd(b Backend, id, name string) tea.Cmd {
	return func() tea.Msg { return removeResultMsg{contactID: id, name: name, err: b.RemoveContact(id)} }
}

func verificationCmd(b Backend, id string) tea.Cmd {
	return func() tea.Msg {
		info, err := b.Verification(id)
		return verificationMsg{contactID: id, info: info, err: err}
	}
}

func markVerifiedCmd(b Backend, id string, verified bool) tea.Cmd {
	return func() tea.Msg {
		return markVerifiedMsg{contactID: id, verified: verified, err: b.MarkVerified(id, verified)}
	}
}

// handleResult applies the result of a Backend call. It reports false for
// messages it does not know.
func (m *Model) handleResult(msg tea.Msg) (tea.Cmd, bool) {
	switch msg := msg.(type) {
	case selfMsg:
		m.self, m.hasSelf = cleanSelf(msg.self), true
	case contactsMsg:
		if msg.err != nil {
			m.sysLog(entryError, "Cannot load contacts: "+describeBackendError(msg.err)+".")
			return nil, true
		}
		return m.mergeContacts(msg.contacts), true
	case historyMsg:
		m.applyHistory(msg)
	case markReadMsg:
		if msg.err != nil {
			m.sysLog(entryError, "Cannot mark messages as read: "+describeBackendError(msg.err)+".")
		}
	case sendResultMsg:
		m.applySendResult(msg)
	case addResultMsg:
		return m.applyAdd(msg), true
	case renameResultMsg:
		m.applyRename(msg)
	case removeResultMsg:
		m.applyRemove(msg)
	case verificationMsg:
		m.applyVerification(msg)
	case markVerifiedMsg:
		m.applyMarkVerified(msg)
	default:
		return nil, false
	}
	return nil, true
}

// conv returns the conversation with the given key, or nil.
func (m *Model) conv(key string) *conversation {
	for i := range m.convs {
		if m.convs[i].key == key {
			return &m.convs[i]
		}
	}
	return nil
}

// openConv returns the open conversation, falling back to System.
func (m *Model) openConv() *conversation {
	if c := m.conv(m.open); c != nil {
		return c
	}
	m.open = systemKey
	return &m.convs[0]
}

func (m *Model) convIndex(key string) int {
	return slices.IndexFunc(m.convs, func(c conversation) bool { return c.key == key })
}

// step opens the next or previous conversation.
func (m *Model) step(delta int) tea.Cmd {
	n := len(m.convs)
	i := max(m.convIndex(m.open), 0)
	return m.openConversation(m.convs[(i+delta+n)%n].key)
}

// moveCursor moves the sidebar selection without opening anything.
func (m *Model) moveCursor(delta int) {
	n := len(m.convs)
	i := max(m.convIndex(m.cursor), 0)
	m.cursor = m.convs[(i+delta+n)%n].key
}

// openConversation shows a conversation, marking it read and loading its
// stored history the first time.
func (m *Model) openConversation(key string) tea.Cmd {
	c := m.conv(key)
	if c == nil {
		return nil
	}
	changed := key != m.open
	m.open, m.cursor = key, key
	m.input.placeholder = placeholderFor(c)
	var cmds []tea.Cmd
	if c.unread > 0 {
		c.unread = 0
		if c.kind == convContact {
			cmds = append(cmds, m.markRead(c.contact.ID))
		}
	}
	if c.kind == convContact && !c.loaded && !c.loading && m.cfg.Backend != nil {
		c.loading = true
		cmds = append(cmds, m.loadHistory(c.contact.ID))
	}
	if changed {
		m.refreshHistory()
		m.history.GotoBottom()
	}
	return tea.Batch(cmds...)
}

func placeholderFor(c *conversation) string {
	switch c.kind {
	case convContact:
		return "Message " + c.contact.label() + " · /help"
	case convRequests:
		return "Read only · /add <qc1-id> [name] to accept"
	}
	return "Type a note or /help"
}

// mergeContacts replaces the contact list, keeping the history of
// conversations that remain. System and Message requests stay first.
func (m *Model) mergeContacts(list []ContactInfo) tea.Cmd {
	next := []conversation{m.convs[0]}
	if req := m.conv(requestsKey); req != nil {
		next = append(next, *req)
	}
	seen := map[string]bool{}
	var cmds []tea.Cmd
	for _, raw := range list {
		ci := cleanContact(raw)
		if ci.ID == "" || seen[ci.ID] {
			continue
		}
		seen[ci.ID] = true
		c := conversation{key: ci.ID, kind: convContact}
		if old := m.conv(ci.ID); old != nil {
			c = *old
		}
		c.contact = ci
		c.unread = ci.Unread
		if ci.ID == m.open && c.unread > 0 {
			c.unread = 0
			cmds = append(cmds, m.markRead(ci.ID))
		}
		relabel(&c)
		next = append(next, c)
	}
	m.convs = next
	if m.conv(m.open) == nil {
		m.open = systemKey
		m.input.placeholder = placeholderFor(&m.convs[0])
	} else {
		m.input.placeholder = placeholderFor(m.openConv())
	}
	if m.conv(m.cursor) == nil {
		m.cursor = m.open
	}
	m.refreshHistory()
	return tea.Batch(cmds...)
}

// relabel updates the sender label of incoming messages after a rename.
func relabel(c *conversation) {
	if c.kind != convContact {
		return
	}
	for i := range c.entries {
		if c.entries[i].kind == entryMessage && !c.entries[i].outgoing {
			c.entries[i].from = c.contact.label()
		}
	}
}

// messageEntry turns a Backend message into a history entry.
func messageEntry(mi MessageInfo, from string) entry {
	at := mi.Sent
	if !mi.Outgoing && !mi.Received.IsZero() {
		at = mi.Received
	}
	e := entry{
		kind:     entryMessage,
		at:       at,
		text:     sanitizeText(mi.Text),
		from:     from,
		msgID:    mi.ID,
		outgoing: mi.Outgoing,
		skew:     mi.ClockSkew,
	}
	if mi.Outgoing {
		e.from = "you"
		e.status = mi.Status
		e.errText = cleanLine(mi.Error, 300)
	}
	return e
}

func (m *Model) applyHistory(msg historyMsg) {
	c := m.conv(msg.contactID)
	if c == nil {
		return
	}
	c.loading = false
	if msg.err != nil {
		m.addTo(msg.contactID, entry{kind: entryError, text: "Cannot load stored messages: " + describeBackendError(msg.err) + "."})
		return
	}
	known := map[string]bool{}
	entries := make([]entry, 0, len(msg.messages)+len(c.entries))
	for _, mi := range msg.messages {
		e := messageEntry(mi, c.contact.label())
		if e.at.IsZero() {
			e.at = m.cfg.Now()
		}
		if mi.ID != "" {
			known[mi.ID] = true
		}
		entries = append(entries, e)
	}
	for _, e := range c.entries {
		if e.kind == entryMessage && e.msgID != "" && known[e.msgID] {
			continue
		}
		entries = append(entries, e)
	}
	if len(entries) > maxEntries {
		entries = entries[len(entries)-maxEntries:]
	}
	c.entries, c.loaded = entries, true
	if msg.contactID == m.open {
		m.refreshHistory()
	}
}

// handleChatEvent applies an event pushed by the application layer.
func (m *Model) handleChatEvent(ev ChatEvent) tea.Cmd {
	switch e := ev.(type) {
	case IncomingMessage:
		return m.receive(e)
	case MessageStatusChanged:
		m.setStatus(cleanLine(e.ContactID, 128), e.MessageID, e.Status, e.Error)
	case ContactKeyChanged:
		return m.keyChanged(cleanLine(e.ContactID, 128))
	case ContactsChanged:
		return m.loadContacts()
	}
	return nil
}

// receive files an incoming message under its contact, or under Message
// requests when the sender is unknown.
func (m *Model) receive(e IncomingMessage) tea.Cmd {
	id := cleanLine(e.ContactID, 128)
	if id == "" {
		return nil
	}
	if e.UnknownSender && m.conv(id) == nil {
		m.receiveRequest(id, e.Message)
		return nil
	}
	var cmds []tea.Cmd
	if m.conv(id) == nil {
		m.convs = append(m.convs, conversation{key: id, kind: convContact, contact: cleanContact(ContactInfo{ID: id})})
		cmds = append(cmds, m.loadContacts())
	}
	c := m.conv(id)
	if e.Message.ID != "" && slices.ContainsFunc(c.entries, func(x entry) bool { return x.kind == entryMessage && x.msgID == e.Message.ID }) {
		return tea.Batch(cmds...)
	}
	m.addTo(id, messageEntry(e.Message, c.contact.label()))
	if id == m.open {
		return tea.Batch(append(cmds, m.markRead(id))...)
	}
	m.conv(id).unread++
	return tea.Batch(cmds...)
}

func (m *Model) receiveRequest(id string, mi MessageInfo) {
	if m.conv(requestsKey) == nil {
		m.convs = slices.Insert(m.convs, 1, conversation{key: requestsKey, kind: convRequests, loaded: true})
	}
	req := m.conv(requestsKey)
	if !slices.Contains(req.senders, id) {
		req.senders = append(req.senders, id)
		m.addTo(requestsKey, entry{kind: entrySystem, sender: id, text: "Message from " + groupID(id) +
			", who is not in your contacts. To reply, type /add and press tab to fill in the ID, then a name."})
	}
	e := messageEntry(mi, shortID(id))
	e.sender = id
	m.addTo(requestsKey, e)
	if m.open != requestsKey {
		m.conv(requestsKey).unread++
	}
}

// setStatus updates the delivery status of an outgoing message.
func (m *Model) setStatus(contactID, msgID string, status MessageStatus, errText string) {
	c := m.conv(contactID)
	if c == nil || msgID == "" {
		return
	}
	for i := range c.entries {
		e := &c.entries[i]
		if e.kind != entryMessage || !e.outgoing || e.msgID != msgID {
			continue
		}
		e.status, e.errText = status, cleanLine(errText, 300)
		if contactID == m.open {
			m.refreshHistory()
		}
		return
	}
}

func (m *Model) keyChanged(id string) tea.Cmd {
	c := m.conv(id)
	if c == nil || c.kind != convContact {
		return m.loadContacts()
	}
	c.contact.KeyChanged, c.contact.Verified = true, false
	m.addTo(id, entry{kind: entryError, text: "The safety number with " + c.contact.label() +
		" changed. Run /verify and compare it again before you trust this conversation."})
	return nil
}

// sendMessage shows the message as sending and hands it to the Backend.
func (m *Model) sendMessage(c *conversation, text string) tea.Cmd {
	b := m.cfg.Backend
	if b == nil {
		m.log(entryError, "Messaging is off: no identity is loaded.")
		return nil
	}
	m.nextLocalID++
	localID := fmt.Sprintf("%s%d", localIDPrefix, m.nextLocalID)
	id := c.contact.ID
	m.add(entry{kind: entryMessage, text: sanitizeText(text), from: "you", msgID: localID, outgoing: true, status: StatusSending})
	m.history.GotoBottom()
	return sendCmd(b, id, localID, text)
}

func (m *Model) applySendResult(msg sendResultMsg) {
	c := m.conv(msg.contactID)
	if c == nil {
		return
	}
	for i := range c.entries {
		e := &c.entries[i]
		if e.kind != entryMessage || e.msgID != msg.localID {
			continue
		}
		switch {
		case msg.err != nil:
			e.status, e.errText = StatusFailed, describeBackendError(msg.err)
		default:
			if msg.message.ID != "" {
				e.msgID = msg.message.ID
			}
			e.status, e.errText = msg.message.Status, cleanLine(msg.message.Error, 300)
		}
		if msg.contactID == m.open {
			m.refreshHistory()
		}
		return
	}
}

func (m *Model) applyAdd(msg addResultMsg) tea.Cmd {
	if msg.err != nil {
		m.log(entryError, "Cannot add "+shortID(msg.id)+": "+describeBackendError(msg.err)+".")
		return nil
	}
	ci := cleanContact(msg.contact)
	if ci.ID == "" {
		ci = cleanContact(ContactInfo{ID: msg.id, DisplayName: msg.contact.DisplayName, Verified: msg.contact.Verified})
	}
	if c := m.conv(ci.ID); c != nil {
		c.contact = ci
		relabel(c)
	} else {
		m.convs = append(m.convs, conversation{key: ci.ID, kind: convContact, contact: ci})
	}
	m.adoptRequests(ci)
	cmd := m.openConversation(ci.ID)
	m.log(entryGood, "Added "+ci.label()+". Compare safety numbers with /verify before you rely on this contact.")
	return cmd
}

// adoptRequests moves the message requests of a newly added contact into
// its conversation.
func (m *Model) adoptRequests(ci ContactInfo) {
	req := m.conv(requestsKey)
	if req == nil || !slices.Contains(req.senders, ci.ID) {
		return
	}
	var keep, moved []entry
	for _, e := range req.entries {
		switch {
		case e.sender != ci.ID:
			keep = append(keep, e)
		case e.kind == entryMessage:
			e.from, e.sender = ci.label(), ""
			moved = append(moved, e)
		}
	}
	req.entries = keep
	req.senders = slices.DeleteFunc(req.senders, func(s string) bool { return s == ci.ID })
	empty := len(req.senders) == 0
	c := m.conv(ci.ID)
	c.entries = append(moved, c.entries...)
	if empty {
		m.convs = slices.DeleteFunc(m.convs, func(c conversation) bool { return c.key == requestsKey })
		if m.open == requestsKey || m.cursor == requestsKey {
			m.open, m.cursor = systemKey, systemKey
		}
	}
	if m.open == requestsKey {
		m.refreshHistory()
	}
}

func (m *Model) applyRename(msg renameResultMsg) {
	c := m.conv(msg.contactID)
	if c == nil {
		return
	}
	if msg.err != nil {
		m.addTo(msg.contactID, entry{kind: entryError, text: "Cannot rename: " + describeBackendError(msg.err) + "."})
		return
	}
	c.contact.DisplayName = cleanLine(msg.name, maxNameRunes)
	relabel(c)
	if msg.contactID == m.open {
		m.input.placeholder = placeholderFor(c)
		m.refreshHistory()
	}
	m.addTo(msg.contactID, entry{kind: entryGood, text: "Renamed to " + c.contact.label() + ". The name stays on this device."})
}

func (m *Model) applyRemove(msg removeResultMsg) {
	if msg.err != nil {
		m.log(entryError, "Cannot remove "+msg.name+": "+describeBackendError(msg.err)+".")
		return
	}
	m.convs = slices.DeleteFunc(m.convs, func(c conversation) bool { return c.key == msg.contactID })
	if m.conv(m.open) == nil {
		m.openConversation(systemKey)
	}
	if m.conv(m.cursor) == nil {
		m.cursor = m.open
	}
	m.sysLog(entrySystem, "Removed "+msg.name+" from your contacts. Later messages from them arrive as message requests.")
}

func (m *Model) applyVerification(msg verificationMsg) {
	c := m.conv(msg.contactID)
	if c == nil {
		return
	}
	if msg.err != nil {
		m.addTo(msg.contactID, entry{kind: entryError, text: "Cannot compute the safety number: " + describeBackendError(msg.err) + "."})
		return
	}
	if !m.openVerify(c, msg.info) {
		m.addTo(msg.contactID, entry{kind: entryError, text: "The safety number is malformed; it must have 60 digits."})
	}
}

func (m *Model) applyMarkVerified(msg markVerifiedMsg) {
	if m.overlay.kind == overlayVerify && m.overlay.contactID == msg.contactID {
		m.overlay.busy = false
	}
	c := m.conv(msg.contactID)
	if c == nil {
		return
	}
	if msg.err != nil {
		text := "Cannot save the verification: " + describeBackendError(msg.err) + "."
		m.overlay.errText = text
		m.addTo(msg.contactID, entry{kind: entryError, text: text})
		return
	}
	c.contact.Verified, c.contact.KeyChanged = msg.verified, false
	if m.overlay.kind == overlayVerify && m.overlay.contactID == msg.contactID {
		m.overlay.verified, m.overlay.keyChanged, m.overlay.errText = msg.verified, false, ""
	}
	if msg.verified {
		m.addTo(msg.contactID, entry{kind: entryGood, text: "You marked " + c.contact.label() + " as verified."})
		return
	}
	m.addTo(msg.contactID, entry{kind: entryWarn, text: "You marked " + c.contact.label() + " as not verified."})
}
