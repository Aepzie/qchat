package tui

import (
	"context"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"
)

// groupPrefix starts every group ID.
const groupPrefix = "grp-"

// Results of group Backend calls.
type (
	groupsMsg struct {
		groups []GroupInfo
		err    error
	}
	groupResultMsg struct {
		// groupID is the group changed, or "" for a create.
		groupID string
		done    string
		info    GroupInfo
		err     error
	}
)

func (m *Model) loadGroups() tea.Cmd {
	b := m.cfg.Backend
	if b == nil {
		return nil
	}
	return func() tea.Msg {
		groups, err := b.Groups()
		return groupsMsg{groups: groups, err: err}
	}
}

func createGroupCmd(b Backend, name string, members []string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
		defer cancel()
		info, err := b.CreateGroup(ctx, name, members)
		return groupResultMsg{done: "Created the group " + cleanLine(name, maxNameRunes) + ".", info: info, err: err}
	}
}

func changeGroupCmd(b Backend, id string, change GroupChange, done string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
		defer cancel()
		info, err := b.ChangeGroup(ctx, id, change)
		return groupResultMsg{groupID: id, done: done, info: info, err: err}
	}
}

// cleanGroup sanitises every string of a group.
func cleanGroup(g GroupInfo) GroupInfo {
	g.ID = cleanLine(g.ID, 128)
	g.Name = cleanLine(g.Name, maxNameRunes)
	if g.Name == "" {
		g.Name = "unnamed group"
	}
	members := make([]GroupMember, 0, len(g.Members))
	for _, mem := range g.Members {
		mem.ID = cleanLine(mem.ID, 128)
		mem.ShortID = cleanLine(mem.ShortID, 32)
		if mem.ShortID == "" {
			mem.ShortID = shortID(mem.ID)
		}
		mem.DisplayName = cleanLine(mem.DisplayName, maxNameRunes)
		members = append(members, mem)
	}
	g.Members = members
	g.Unread = max(g.Unread, 0)
	return g
}

// memberLabel names the sender of a group message: the member's display
// name, a contact's name, or the short ID.
func (m *Model) memberLabel(c *conversation, id string) string {
	for _, mem := range c.group.Members {
		if mem.ID != id {
			continue
		}
		if mem.Self {
			return "you"
		}
		if mem.DisplayName != "" {
			return mem.DisplayName
		}
		return mem.ShortID
	}
	if ct := m.conv(id); ct != nil && ct.kind == convContact {
		return ct.contact.label()
	}
	return shortID(id)
}

// relabelGroup updates the sender labels of a group conversation.
func (m *Model) relabelGroup(c *conversation) {
	for i := range c.entries {
		e := &c.entries[i]
		if e.kind == entryMessage && !e.outgoing && e.sender != "" {
			e.from = m.memberLabel(c, e.sender)
		}
	}
}

// mergeGroups replaces the group conversations, keeping the history of
// those that remain. Groups follow the contacts in the sidebar.
func (m *Model) mergeGroups(list []GroupInfo) tea.Cmd {
	next := slices.DeleteFunc(slices.Clone(m.convs), func(c conversation) bool { return c.kind == convGroup })
	seen := map[string]bool{}
	var cmds []tea.Cmd
	for _, raw := range list {
		g := cleanGroup(raw)
		if !strings.HasPrefix(g.ID, groupPrefix) || seen[g.ID] {
			continue
		}
		seen[g.ID] = true
		m.noteInvite(g)
		c := conversation{key: g.ID, kind: convGroup}
		if old := m.conv(g.ID); old != nil {
			c = *old
		}
		c.group, c.unread = g, g.Unread
		if g.ID == m.open && c.unread > 0 {
			c.unread = 0
			cmds = append(cmds, m.markRead(g.ID))
		}
		m.relabelGroup(&c)
		next = append(next, c)
	}
	m.convs = next
	if m.conv(m.open) == nil {
		m.open = systemKey
	}
	if m.conv(m.cursor) == nil {
		m.cursor = m.open
	}
	m.input.placeholder = placeholderFor(m.openConv())
	m.refreshHistory()
	return tea.Batch(cmds...)
}

// receiveGroup files an incoming group message.
func (m *Model) receiveGroup(e IncomingMessage) tea.Cmd {
	id := cleanLine(e.GroupID, 128)
	if !strings.HasPrefix(id, groupPrefix) {
		return nil
	}
	var cmds []tea.Cmd
	if m.conv(id) == nil {
		m.convs = append(m.convs, conversation{key: id, kind: convGroup, group: GroupInfo{ID: id, Name: "new group"}})
		cmds = append(cmds, m.loadGroups())
	}
	c := m.conv(id)
	if e.OutOfSync {
		c.group.OutOfSync = true
	}
	if e.Message.ID != "" && slices.ContainsFunc(c.entries, func(x entry) bool { return x.kind == entryMessage && x.msgID == e.Message.ID }) {
		return tea.Batch(cmds...)
	}
	sender := cleanLine(e.Message.From, 128)
	if sender == "" {
		sender = cleanLine(e.ContactID, 128)
	}
	en := messageEntry(e.Message, m.memberLabel(c, sender))
	en.sender = sender
	m.addTo(id, m.freshEntry(en))
	if id == m.open {
		return tea.Batch(append(cmds, m.markRead(id))...)
	}
	m.conv(id).unread++
	return tea.Batch(cmds...)
}

// groupChanged reloads the groups and shows the notice of a change.
func (m *Model) groupChanged(e GroupChanged) tea.Cmd {
	id := cleanLine(e.GroupID, 128)
	if notice := cleanLine(e.Notice, 600); notice != "" && strings.HasPrefix(id, groupPrefix) {
		if m.conv(id) == nil {
			m.convs = append(m.convs, conversation{key: id, kind: convGroup, group: GroupInfo{ID: id, Name: "new group"}})
		}
		m.addTo(id, entry{kind: entrySystem, text: notice})
	}
	return m.loadGroups()
}

func (m *Model) applyGroupResult(msg groupResultMsg) tea.Cmd {
	if msg.err != nil {
		text := "Group change failed: " + describeBackendError(msg.err) + "."
		if msg.groupID != "" && m.conv(msg.groupID) != nil {
			m.addTo(msg.groupID, entry{kind: entryError, text: text})
			return nil
		}
		m.log(entryError, text)
		return nil
	}
	g := cleanGroup(msg.info)
	if !strings.HasPrefix(g.ID, groupPrefix) {
		return m.loadGroups()
	}
	if c := m.conv(g.ID); c != nil {
		c.group = g
		m.relabelGroup(c)
	} else {
		m.convs = append(m.convs, conversation{key: g.ID, kind: convGroup, group: g})
	}
	var cmd tea.Cmd
	if msg.groupID == "" {
		cmd = m.openConversation(g.ID)
	}
	m.input.placeholder = placeholderFor(m.openConv())
	m.addTo(g.ID, entry{kind: entryGood, text: msg.done})
	return tea.Batch(cmd, m.loadGroups())
}

// requireGroup returns the open group conversation, or nil after
// explaining that the command needs one.
func (m *Model) requireGroup(sub string) *conversation {
	if !m.requireBackend() {
		return nil
	}
	c := m.openConv()
	if c.kind != convGroup {
		m.log(entryError, "Open a group first (ctrl+n / ctrl+p), then run /group "+sub+".")
		return nil
	}
	return c
}

// groupCommands lists the /group subcommands, in palette order.
var groupCommands = []command{
	{"/group create", "<name> [qc1-ids…] start a group"},
	{"/group add", "<qc1-id> add a member"},
	{"/group remove", "<member> remove a member"},
	{"/group admin", "<member> make a member an admin"},
	{"/group unadmin", "<member> take admin rights away"},
	{"/group rename", "<name> rename the group"},
	{"/group leave", "leave the group"},
	{"/group accept", "accept an invitation"},
	{"/group members", "list the members"},
}

// resolveSub maps a typed subcommand of the command name to its full form.
// An exact name wins; when the palette showed the subcommands (alone is
// true), a prefix picks the selected match.
func resolveSub(name, arg string, alone bool, selected int) string {
	sub := strings.ToLower(arg)
	if !alone || slices.ContainsFunc(subCommands(name), func(c command) bool { return c.name == name+" "+sub }) {
		return sub
	}
	matches := matchCommands(name + " " + sub)
	if len(matches) == 0 {
		return sub
	}
	return strings.TrimPrefix(matches[clampIndex(selected, len(matches))].name, name+" ")
}

// leaveGroupCmd leaves a group after the user confirmed it.
func leaveGroupCmd(b Backend, id string) tea.Cmd {
	return changeGroupCmd(b, id, GroupChange{Op: GroupLeave}, "You left the group. Its history stays on this device.")
}

// selfAdmin reports whether the user is an admin of g.
func selfAdmin(g GroupInfo) bool {
	return slices.ContainsFunc(g.Members, func(mem GroupMember) bool { return mem.Self && mem.Admin })
}

const groupUsage = "usage: /group create <name> [qc1-ids…] · add <qc1-id> · remove|admin|unadmin <member> · rename <name> · leave · accept · members"

// cmdGroup runs /group and its subcommands.
func (m *Model) cmdGroup(args []string) tea.Cmd {
	if len(args) == 0 {
		m.log(entryError, groupUsage)
		return nil
	}
	sub, rest := resolveSub("/group", args[0], len(args) == 1, m.paletteSel), args[1:]
	if sub == "create" {
		return m.cmdGroupCreate(rest)
	}
	c := m.requireGroup(sub)
	if c == nil {
		return nil
	}
	b, id := m.cfg.Backend, c.key
	switch sub {
	case "add":
		member, ok := m.parseMemberID(rest)
		if !ok {
			return nil
		}
		return changeGroupCmd(b, id, GroupChange{Op: GroupAdd, Member: member}, "Added "+m.memberLabel(c, member)+".")
	case "remove", "admin", "unadmin":
		member, ok := m.resolveMember(c, rest)
		if !ok {
			return nil
		}
		ops := map[string]GroupOp{"remove": GroupRemove, "admin": GroupPromote, "unadmin": GroupDemote}
		done := map[string]string{"remove": "Removed %s.", "admin": "%s is now an admin.", "unadmin": "%s is no longer an admin."}
		label := m.memberLabel(c, member)
		return changeGroupCmd(b, id, GroupChange{Op: ops[sub], Member: member}, strings.Replace(done[sub], "%s", label, 1))
	case "rename":
		name := cleanLine(strings.Join(rest, " "), maxNameRunes)
		if name == "" {
			m.log(entryError, "usage: /group rename <name>")
			return nil
		}
		return changeGroupCmd(b, id, GroupChange{Op: GroupRename, Name: name}, "Renamed the group to "+name+".")
	case "leave":
		m.confirm = confirmation{active: true, groupID: id, name: c.title()}
		return nil
	case "accept":
		return changeGroupCmd(b, id, GroupChange{Op: GroupAccept}, "You accepted the invitation.")
	case "members":
		m.openMembers(c)
		return nil
	}
	m.log(entryError, groupUsage)
	return nil
}

func (m *Model) cmdGroupCreate(args []string) tea.Cmd {
	if !m.requireBackend() {
		return nil
	}
	split := slices.IndexFunc(args, func(s string) bool { return strings.HasPrefix(strings.ToLower(s), idPrefix) })
	if split < 0 {
		split = len(args)
	}
	name := cleanLine(strings.Join(args[:split], " "), maxNameRunes)
	if name == "" {
		m.log(entryError, "usage: /group create <name> [qc1-ids…]")
		return nil
	}
	var members []string
	for _, arg := range args[split:] {
		id, _, err := parseAddArgs([]string{arg})
		if err != nil {
			m.log(entryError, sanitizeText(err.Error())+".")
			return nil
		}
		if id != m.self.ID && !slices.Contains(members, id) {
			members = append(members, id)
		}
	}
	m.log(entrySystem, "Creating the group "+name+"…")
	return createGroupCmd(m.cfg.Backend, name, members)
}

// parseMemberID parses a full identity ID argument.
func (m *Model) parseMemberID(args []string) (string, bool) {
	id, _, err := parseAddArgs(args)
	if err != nil {
		m.log(entryError, sanitizeText(err.Error())+".")
		return "", false
	}
	return id, true
}

// resolveMember finds the member an argument names: a full ID, or the
// display name or short ID of exactly one member.
func (m *Model) resolveMember(c *conversation, args []string) (string, bool) {
	if len(args) == 0 {
		m.log(entryError, "Name a member: their qc1- ID, short ID or display name. /group members lists them.")
		return "", false
	}
	if id, _, err := parseAddArgs(args); err == nil {
		return id, true
	}
	want := strings.ToLower(cleanLine(strings.Join(args, " "), maxNameRunes))
	var found []string
	for _, mem := range c.group.Members {
		if strings.ToLower(mem.DisplayName) == want || strings.ToLower(mem.ShortID) == want {
			found = append(found, mem.ID)
		}
	}
	if len(found) != 1 {
		m.log(entryError, "No single member is called "+want+". Use their qc1- ID; /group members lists them.")
		return "", false
	}
	return found[0], true
}

// openMembers shows the member list of a group.
func (m *Model) openMembers(c *conversation) {
	m.overlay = overlay{kind: overlayMembers, name: c.group.Name, members: slices.Clone(c.group.Members), left: c.group.Left}
}

// membersText is the text of the members overlay.
func (m Model) membersText(width int) []string {
	st := m.st
	o := m.overlay
	var lines []string
	add := func(text string, render func(string) string) {
		for _, l := range wrapLines(text, width) {
			lines = append(lines, render(l))
		}
	}
	if o.left {
		add("You are no longer a member; this is the last membership you saw.", func(s string) string { return st.warn.Render(s) })
		lines = append(lines, "")
	}
	for _, mem := range o.members {
		label := mem.DisplayName
		if label == "" {
			label = mem.ShortID
		}
		var tags []string
		if mem.Self {
			tags = append(tags, "you")
		}
		if mem.Admin {
			tags = append(tags, "admin")
		}
		line := "• " + label
		if len(tags) > 0 {
			line += " (" + strings.Join(tags, ", ") + ")"
		}
		add(line, func(s string) string { return st.text.Render(s) })
		add("  "+groupID(mem.ID), func(s string) string { return st.faint.Render(s) })
	}
	lines = append(lines, "")
	add("The relay sees the recipients of every group message, but not the group's name or ID.", func(s string) string { return st.faint.Render(s) })
	add("esc close", func(s string) string { return st.muted.Render(s) })
	return lines
}

// noteInvite marks a new group invitation as unseen, and forgets it once it
// is no longer pending.
func (m *Model) noteInvite(g GroupInfo) {
	if !g.Invite || g.Left {
		delete(m.unseen, g.ID)
		return
	}
	if old := m.conv(g.ID); old == nil || !old.group.Invite {
		m.unseen[g.ID] = true
	}
}
