package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/craguS/qchat/internal/e2e"
	"github.com/craguS/qchat/internal/group"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/senderkey"
	"github.com/craguS/qchat/internal/store/clientdb"
	"github.com/craguS/qchat/internal/tui"
)

const (
	// maxGroupText is the longest group message: the encoded plaintext must
	// fit senderkey.MaxPlaintextSize.
	maxGroupText = senderkey.MaxPlaintextSize - (e2e.MaxPlaintextSize - e2e.MaxBodySize)
	// historyChunkSize bounds the controls packed into one onboarding
	// message, leaving room for the CBOR framing within e2e.MaxBodySize.
	historyChunkSize = e2e.MaxBodySize - 1024
	// backlogSettle is how long after connecting, and after the latest
	// delivery while that lasts, group messages are held back so that the
	// relay's backlog is processed first; backlogWait bounds the wait.
	backlogSettle = 2 * time.Second
	backlogQuiet  = 500 * time.Millisecond
	backlogWait   = 10 * time.Second
)

// groupStatusUpdater is implemented by a database that can change the
// status of a stored group message.
type groupStatusUpdater interface {
	UpdateGroupMessageStatus(ctx context.Context, group, sender [32]byte, msgID [16]byte, status uint8) error
}

// noteConnected starts holding group messages back while the relay's
// backlog arrives.
func (a *App) noteConnected() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.backlogUntil = time.Now().Add(backlogSettle)
}

// noteDelivery extends the hold while the backlog is still arriving.
func (a *App) noteDelivery() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now := time.Now(); now.Before(a.backlogUntil) {
		a.backlogUntil = now.Add(max(backlogQuiet, a.backlogUntil.Sub(now)))
	}
}

// awaitBacklog waits until the backlog after the latest connection has
// been processed, at most backlogWait.
func (a *App) awaitBacklog(ctx context.Context) {
	deadline := time.Now().Add(backlogWait)
	for {
		a.mu.Lock()
		until := a.backlogUntil
		a.mu.Unlock()
		now := time.Now()
		if !now.Before(until) || !now.Before(deadline) {
			return
		}
		t := time.NewTimer(min(until.Sub(now), deadline.Sub(now)))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// Groups returns every group, sorted by name.
func (a *App) Groups() ([]tui.GroupInfo, error) {
	ctx := context.Background()
	list, err := a.prof.DB.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	names, err := a.contactNames(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]tui.GroupInfo, 0, len(list))
	for _, g := range list {
		e, err := parseGroupEntry(g.State, g.Left)
		if err != nil {
			continue
		}
		out = append(out, a.groupInfo(e, names))
	}
	slices.SortStableFunc(out, func(x, y tui.GroupInfo) int {
		return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
	})
	return out, nil
}

// contactNames maps contacts to their shown names.
func (a *App) contactNames(ctx context.Context) (map[identity.ID]string, error) {
	contacts, err := a.prof.DB.ListContacts(ctx)
	if err != nil {
		return nil, err
	}
	names := make(map[identity.ID]string, len(contacts))
	for _, c := range contacts {
		names[identity.ID(c.ID)] = shownName(c)
	}
	return names, nil
}

func (a *App) groupInfo(e groupEntry, names map[identity.ID]string) tui.GroupInfo {
	self := a.selfID()
	info := tui.GroupInfo{ID: groupKey(e.state.GroupID), Name: e.state.Name, Left: e.left, Invite: e.invite && !e.left}
	for _, id := range e.state.Members {
		m := tui.GroupMember{ID: canonicalID(id), ShortID: id.ShortString(), DisplayName: names[id], Admin: e.state.IsAdmin(id), Self: id == self}
		if m.Self {
			m.DisplayName = a.prof.DisplayName()
		}
		info.Members = append(info.Members, m)
	}
	a.mu.Lock()
	info.Unread = a.groupUnread[e.state.GroupID]
	info.OutOfSync = a.groupOutOfSync[e.state.GroupID] && !e.left
	a.mu.Unlock()
	return info
}

// currentGroupInfo returns the interface's view of the stored group id.
func (a *App) currentGroupInfo(ctx context.Context, id group.ID) (tui.GroupInfo, error) {
	e, found, err := a.loadGroup(ctx, id)
	if err != nil {
		return tui.GroupInfo{}, err
	}
	if !found {
		return tui.GroupInfo{}, ErrUnknownGroup
	}
	names, err := a.contactNames(ctx)
	if err != nil {
		return tui.GroupInfo{}, err
	}
	return a.groupInfo(e, names), nil
}

// groupError turns a rule violation reported by package group into text for
// the user.
func groupError(err error) error {
	switch {
	case errors.Is(err, group.ErrNotAdmin):
		return errors.New("only admins can do that")
	case errors.Is(err, group.ErrNotMember):
		return ErrNotGroupMember
	case errors.Is(err, group.ErrLastAdmin):
		return errors.New("the last admin cannot step down; make someone else an admin first")
	case errors.Is(err, group.ErrTooManyMembers):
		return fmt.Errorf("groups have at most %d members", group.MaxMembers)
	case errors.Is(err, group.ErrInvalidName):
		return fmt.Errorf("group names have 1 to %d characters and no control characters", group.MaxNameRunes)
	case errors.Is(err, group.ErrInvalidOp):
		return errors.New("that change does not apply to this group")
	case errors.Is(err, group.ErrMalformed):
		return errors.New("invalid member list")
	}
	return err
}

// CreateGroup creates a group, tells every member and shares the user's
// first sender key with them. Members need not be contacts but must be
// registered with the relay.
func (a *App) CreateGroup(ctx context.Context, name string, memberIDs []string) (tui.GroupInfo, error) {
	members := make([]identity.ID, 0, len(memberIDs))
	for _, s := range memberIDs {
		id, err := parseContactID(s)
		if err != nil {
			return tui.GroupInfo{}, err
		}
		members = append(members, id)
	}
	var later []tui.ChatEvent
	defer func() {
		for _, ev := range later {
			a.emit(ev)
		}
	}()
	a.groupMu.Lock()
	defer a.groupMu.Unlock()
	for _, id := range members {
		if _, err := a.memberBundle(ctx, id, nil); err != nil {
			return tui.GroupInfo{}, fmt.Errorf("%s: %w", id.ShortString(), err)
		}
	}
	st, control, err := group.NewGroup(a.prof.Identity, name, members)
	if err != nil {
		return tui.GroupInfo{}, groupError(err)
	}
	e := groupEntry{state: st, history: [][]byte{control}, installed: map[identity.ID][]installedGen{}}
	if err := a.storeGroup(ctx, e); err != nil {
		return tui.GroupInfo{}, err
	}
	s, err := a.startSender(ctx, &e)
	if err != nil {
		return tui.GroupInfo{}, err
	}
	defer s.Destroy()
	body, err := marshalControlMessage(controlMessage{Control: control})
	if err != nil {
		return tui.GroupInfo{}, err
	}
	send := context.WithoutCancel(ctx)
	notice := joinNotices(a.fanOut(send, st.Members, e2e.KindGroupControl, body), a.distribute(send, s, st.Epoch, a.others(st)))
	if notice != "" {
		later = append(later, tui.GroupChanged{GroupID: groupKey(st.GroupID), Notice: notice})
	}
	return a.currentGroupInfo(ctx, st.GroupID)
}

// ChangeGroup applies a change made by the user: it signs the control,
// stores the new state, sends the control to everyone group.Recipients
// names (an added member first gets the control history) and then the
// sender keys the change calls for. GroupAccept accepts an invitation and
// changes nothing for the other members.
func (a *App) ChangeGroup(ctx context.Context, groupID string, change tui.GroupChange) (tui.GroupInfo, error) {
	gid, err := parseGroupKey(groupID)
	if err != nil {
		return tui.GroupInfo{}, err
	}
	if change.Op == tui.GroupAccept {
		return a.acceptInvitation(ctx, gid)
	}
	var target identity.ID
	op, needsTarget := groupOp(change.Op)
	if op == 0 {
		return tui.GroupInfo{}, errors.New("unknown group change")
	}
	if needsTarget {
		if target, err = parseContactID(change.Member); err != nil {
			return tui.GroupInfo{}, err
		}
	}
	var later []tui.ChatEvent
	defer func() {
		for _, ev := range later {
			a.emit(ev)
		}
	}()
	a.groupMu.Lock()
	defer a.groupMu.Unlock()
	cur, found, err := a.loadGroup(ctx, gid)
	switch {
	case err != nil:
		return tui.GroupInfo{}, err
	case !found:
		return tui.GroupInfo{}, ErrUnknownGroup
	case cur.left:
		return tui.GroupInfo{}, ErrLeftGroup
	case cur.invite && op != group.OpLeave:
		return tui.GroupInfo{}, ErrInvitation
	}
	if op == group.OpAdd {
		if _, err := a.memberBundle(ctx, target, nil); err != nil {
			return tui.GroupInfo{}, err
		}
	}
	name := ""
	if op == group.OpRename {
		name = change.Name
	}
	raw, err := group.NewControl(a.prof.Identity, cur.state, op, target, name)
	if err != nil {
		return tui.GroupInfo{}, groupError(err)
	}
	c, err := group.ParseControl(raw)
	if err != nil {
		return tui.GroupInfo{}, err
	}
	next, err := group.Apply(&cur.state, c, a.self)
	if err != nil {
		return tui.GroupInfo{}, groupError(err)
	}
	history := slices.Clone(cur.history)
	plan, err := a.commitChange(ctx, cur, next, raw, false)
	if err != nil {
		return tui.GroupInfo{}, err
	}
	body, err := marshalControlMessage(controlMessage{Control: raw})
	if err != nil {
		return tui.GroupInfo{}, err
	}
	send := context.WithoutCancel(ctx)
	var notices []string
	for _, id := range group.Recipients(cur.state, next) {
		bodies := [][]byte{body}
		if op == group.OpAdd && id == target {
			if bodies, err = onboardingBodies(history, body); err != nil {
				return tui.GroupInfo{}, err
			}
		}
		notices = append(notices, a.fanOut(send, []identity.ID{id}, e2e.KindGroupControl, bodies...))
	}
	notices = append(notices, a.carryOut(send, plan))
	if notice := joinNotices(notices...); notice != "" {
		later = append(later, tui.GroupChanged{GroupID: groupID, Notice: notice})
	}
	return a.currentGroupInfo(ctx, gid)
}

// onboardingBodies returns the control messages for a member being added:
// the history in chunks, then the add control.
func onboardingBodies(history [][]byte, add []byte) ([][]byte, error) {
	var bodies [][]byte
	for _, chunk := range historyChunks(history, historyChunkSize) {
		b, err := marshalControlMessage(controlMessage{History: chunk})
		if err != nil {
			return nil, err
		}
		bodies = append(bodies, b)
	}
	return append(bodies, add), nil
}

// acceptInvitation lets the user write to a group it was invited to.
func (a *App) acceptInvitation(ctx context.Context, gid group.ID) (tui.GroupInfo, error) {
	a.groupMu.Lock()
	defer a.groupMu.Unlock()
	e, found, err := a.loadGroup(ctx, gid)
	switch {
	case err != nil:
		return tui.GroupInfo{}, err
	case !found:
		return tui.GroupInfo{}, ErrUnknownGroup
	case e.left:
		return tui.GroupInfo{}, ErrLeftGroup
	}
	if e.invite {
		e.invite = false
		if err := a.storeGroup(ctx, e); err != nil {
			return tui.GroupInfo{}, err
		}
	}
	return a.currentGroupInfo(ctx, gid)
}

// groupOp maps an interface change to a control operation and reports
// whether it names a member.
func groupOp(op tui.GroupOp) (group.Op, bool) {
	switch op {
	case tui.GroupAdd:
		return group.OpAdd, true
	case tui.GroupRemove:
		return group.OpRemove, true
	case tui.GroupPromote:
		return group.OpPromote, true
	case tui.GroupDemote:
		return group.OpDemote, true
	case tui.GroupRename:
		return group.OpRename, false
	case tui.GroupLeave:
		return group.OpLeave, false
	}
	return 0, false
}

// sendGroup encrypts text once with the user's sender key and hands it to
// the relay for every other member. Like Send, relay failures are reported
// in the returned message's status. The advanced sender key and the message
// are stored together before the envelope leaves the device.
func (a *App) sendGroup(ctx context.Context, groupID, text string) (tui.MessageInfo, error) {
	gid, err := parseGroupKey(groupID)
	if err != nil {
		return tui.MessageInfo{}, err
	}
	switch {
	case text == "":
		return tui.MessageInfo{}, ErrEmptyMessage
	case len(text) > maxGroupText:
		return tui.MessageInfo{}, fmt.Errorf("message is longer than %d bytes", maxGroupText)
	case !utf8.ValidString(text):
		return tui.MessageInfo{}, errors.New("message is not valid UTF-8")
	}
	a.awaitBacklog(ctx)
	m, envelope, to, notice, err := a.sealGroup(ctx, gid, text)
	if notice != "" {
		a.emit(tui.GroupChanged{GroupID: groupID, Notice: notice})
	}
	if err != nil {
		return tui.MessageInfo{}, err
	}
	return a.deliverGroupMessage(ctx, groupID, m, envelope, to)
}

// deliverGroupMessage hands the envelope of the stored outgoing group
// message m to the relay and records the resulting status.
func (a *App) deliverGroupMessage(ctx context.Context, groupID string, m clientdb.GroupMessage, envelope []byte, to []identity.ID) (tui.MessageInfo, error) {
	gid := group.ID(m.Group)
	key := messageKey{peer: identity.ID(gid), msgID: m.MsgID}
	status, reason, missed := a.deliverMulti(ctx, to, envelope)
	if len(missed) > 0 {
		labels := make([]string, len(missed))
		for i, id := range missed {
			labels[i] = a.memberLabel(ctx, id)
		}
		a.emit(tui.GroupChanged{GroupID: groupID, Notice: "The relay could not store your message for " + strings.Join(labels, ", ") + "."})
	}
	a.mu.Lock()
	delete(a.inflight, key)
	a.groupStatus[key] = status
	a.mu.Unlock()
	var updateErr error
	if u, ok := any(a.prof.DB).(groupStatusUpdater); ok {
		updateErr = u.UpdateGroupMessageStatus(context.Background(), gid, m.Sender, m.MsgID, status)
	}
	m.Status = status
	info := a.groupMessageInfo(m)
	info.Error = reason
	return info, updateErr
}

// sealGroup encrypts a group message, starting a sender key generation
// first if there is none or the current one NeedsRotation, and commits the
// advanced sender key together with the outgoing message. It returns the
// stored message, the envelope, the recipients and a notice for members
// a new sender key could not reach.
func (a *App) sealGroup(ctx context.Context, gid group.ID, text string) (clientdb.GroupMessage, []byte, []identity.ID, string, error) {
	return a.sealGroupKind(ctx, gid, e2e.KindGroupText, []byte(text), &clientdb.GroupMessage{Body: text})
}

// sealGroupKind is sealGroup for a plaintext of any kind a group envelope
// carries. With a record template (Body and Flags set), the message is
// stored with the advanced sender key; without one (nil), only the sender
// key is stored, for messages that are not shown in the conversation, and
// the returned message only carries the message ID and send time.
func (a *App) sealGroupKind(ctx context.Context, gid group.ID, kind e2e.Kind, body []byte, record *clientdb.GroupMessage) (clientdb.GroupMessage, []byte, []identity.ID, string, error) {
	fail := func(err error) (clientdb.GroupMessage, []byte, []identity.ID, string, error) {
		return clientdb.GroupMessage{}, nil, nil, "", err
	}
	a.groupMu.Lock()
	defer a.groupMu.Unlock()
	e, found, err := a.loadGroup(ctx, gid)
	switch {
	case err != nil:
		return fail(err)
	case !found:
		return fail(ErrUnknownGroup)
	case e.left:
		return fail(ErrLeftGroup)
	case e.invite:
		return fail(ErrInvitation)
	}
	to := a.others(e.state)
	if len(to) == 0 {
		return fail(ErrAloneInGroup)
	}
	s, err := a.ownSender(ctx, gid)
	if err != nil {
		return fail(err)
	}
	notice := ""
	if s == nil || s.NeedsRotation(a.now()) {
		if s != nil {
			s.Destroy()
		}
		if s, err = a.startSender(ctx, &e); err != nil {
			return fail(err)
		}
		notice = a.distribute(ctx, s, e.state.Epoch, to)
	}
	defer s.Destroy()
	pt, err := e2e.NewPlaintext(kind, body, a.now())
	if err != nil {
		return fail(err)
	}
	plain, err := e2e.MarshalPlaintext(pt)
	if err != nil {
		return fail(err)
	}
	defer clear(plain)
	envelope, err := s.Encrypt(plain, e.state.Epoch, e.state.Binding())
	if err != nil {
		return fail(err)
	}
	state, err := s.Marshal()
	if err != nil {
		return fail(err)
	}
	defer clear(state)
	if record == nil {
		a.mu.Lock()
		defer a.mu.Unlock()
		if err := a.prof.DB.PutOwnSenderKey(ctx, gid, state); err != nil {
			return clientdb.GroupMessage{}, nil, nil, notice, err
		}
		return clientdb.GroupMessage{MsgID: pt.MsgID, Sent: pt.Sent}, envelope, to, notice, nil
	}
	m := clientdb.GroupMessage{Group: gid, Sender: a.selfID(), MsgID: pt.MsgID, Dir: clientdb.Outgoing, Sent: pt.Sent,
		Body: record.Body, Status: clientdb.StatusSent, Flags: record.Flags, Expires: a.expiryFor(ctx, gid, pt.Sent)}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.prof.DB.CommitGroupSend(ctx, state, m); err != nil {
		return clientdb.GroupMessage{}, nil, nil, notice, err
	}
	a.inflight[messageKey{peer: identity.ID(gid), msgID: m.MsgID}] = struct{}{}
	return m, envelope, to, notice, nil
}

// deliverMulti hands a group envelope to the relay for every recipient.
// The relay may store it for some recipients only; those it could not
// reach are returned. The message counts as sent when at least one
// recipient got it.
func (a *App) deliverMulti(ctx context.Context, to []identity.ID, payload []byte) (uint8, string, []identity.ID) {
	sess := a.session()
	if sess == nil {
		return clientdb.StatusFailed, "not connected", nil
	}
	ids := make([][]byte, len(to))
	for i, id := range to {
		ids[i] = id[:]
	}
	frame, err := sess.Request(ctx, protocol.TypeSendMulti, protocol.SendMulti{To: ids, Payload: payload})
	if reason := relayFailure(err); reason != "" {
		return clientdb.StatusFailed, reason, nil
	}
	result, err := protocol.DecodeBody[protocol.SendMultiResult](frame, protocol.TypeSendMultiResult)
	if err != nil || result.Status != protocol.SendAccepted {
		return clientdb.StatusFailed, "unexpected answer from the server", nil
	}
	var missed []identity.ID
	for _, raw := range result.Failed {
		if len(raw) == identity.IDSize && slices.Contains(to, identity.ID(raw)) {
			missed = append(missed, identity.ID(raw))
		}
	}
	if len(missed) == len(to) {
		return clientdb.StatusFailed, "the server could not store it for any member", missed
	}
	return clientdb.StatusDelivered, "", missed
}

// groupHistory returns the latest messages of a group, oldest first.
func (a *App) groupHistory(groupID string, limit int) ([]tui.MessageInfo, error) {
	gid, err := parseGroupKey(groupID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	msgs, err := a.prof.DB.GroupMessages(context.Background(), gid, min(limit, clientdb.MaxPageSize), 0)
	if err != nil {
		return nil, err
	}
	out := make([]tui.MessageInfo, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, a.groupMessageInfo(m))
	}
	return out, nil
}

// groupMessageEvent is the event for a received group message. outOfSync
// reports that its sender's group state, as bound in the message header,
// differs from the own.
func (a *App) groupMessageEvent(m clientdb.GroupMessage, outOfSync bool) tui.ChatEvent {
	return tui.IncomingMessage{ContactID: canonicalID(identity.ID(m.Sender)), GroupID: groupKey(m.Group), Message: a.groupMessageInfo(m), OutOfSync: outOfSync}
}

// groupMessageInfo maps a stored group message to the interface's form.
// The status of an outgoing message sent in this run is taken from memory
// when the database cannot update it.
func (a *App) groupMessageInfo(m clientdb.GroupMessage) tui.MessageInfo {
	peer := identity.ID(m.Group)
	if m.Dir == clientdb.Outgoing && m.Status == clientdb.StatusSent {
		a.mu.Lock()
		if status, ok := a.groupStatus[messageKey{peer: peer, msgID: m.MsgID}]; ok {
			m.Status = status
		}
		a.mu.Unlock()
	}
	info := a.messageInfo(clientdb.Message{Peer: peer, MsgID: m.MsgID, Dir: m.Dir, Sent: m.Sent, Received: m.Received, Body: m.Body, Status: m.Status, Flags: m.Flags &^ clientdb.FlagFile})
	if m.Dir == clientdb.Incoming {
		info.From = canonicalID(identity.ID(m.Sender))
	}
	if m.Flags&clientdb.FlagFile != 0 {
		info.File = a.fileInfo(context.Background(), m.Group, m.Sender, m.MsgID)
	}
	return info
}

// markGroupRead resets the unread count of a group.
func (a *App) markGroupRead(groupID string) error {
	gid, err := parseGroupKey(groupID)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.groupUnread, gid)
	return nil
}
