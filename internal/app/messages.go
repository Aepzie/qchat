package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/e2e"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/store/clientdb"
	"github.com/craguS/qchat/internal/tui"
)

// ErrMessageTooLong is returned by Send for text above e2e.MaxBodySize bytes.
var ErrMessageTooLong = fmt.Errorf("message is longer than %d bytes", e2e.MaxBodySize)

// ErrEmptyMessage is returned by Send for empty text.
var ErrEmptyMessage = errors.New("message is empty")

// messageKey identifies a message within all conversations.
type messageKey struct {
	peer  identity.ID
	msgID [e2e.MsgIDSize]byte
}

// handleDelivery decrypts, verifies and files one relayed message. Anything
// that fails is dropped without telling the interface: the relay, or
// whoever controls it, must not be able to inject content or noise.
func (a *App) handleDelivery(ctx context.Context, d client.Delivery) {
	from := identity.ID(d.From)
	stored, known := a.storedBundle(from)
	lookup := func(id identity.ID) (*identity.Bundle, error) {
		if known {
			return identity.ParseBundleForID(stored, id)
		}
		return a.fetchBundle(ctx, id)
	}
	now := a.now()
	m, err := e2e.Open(a.prof.Identity, from, d.Payload, lookup, now)
	if err != nil {
		a.countDropped()
		return
	}
	defer clear(m.Body)
	if m.Kind != e2e.KindText || !utf8.Valid(m.Body) {
		a.countDropped()
		return
	}
	var flags uint8
	if m.ClockSkew {
		flags |= clientdb.FlagClockSkew
	}
	record := clientdb.Message{
		Peer:     from,
		MsgID:    m.MsgID,
		Dir:      clientdb.Incoming,
		Sent:     m.Sent,
		Received: now,
		Body:     string(m.Body),
		Status:   clientdb.StatusReceived,
		Flags:    flags,
	}
	unknown, ok := a.file(record)
	if !ok {
		return
	}
	a.emit(tui.IncomingMessage{ContactID: canonicalID(from), Message: a.messageInfo(record), UnknownSender: unknown})
}

// storedBundle returns the bundle stored for a contact.
func (a *App) storedBundle(id identity.ID) ([]byte, bool) {
	c, err := a.prof.DB.GetContact(context.Background(), id)
	if err != nil {
		return nil, false
	}
	return c.Bundle, true
}

// file stores an incoming message under its contact, or as a message
// request when the sender is not a contact. It reports whether the sender
// is unknown, and false as ok for a replay or a full request store.
func (a *App) file(m clientdb.Message) (unknown, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx := context.Background()
	_, err := a.prof.DB.GetContact(ctx, m.Peer)
	switch {
	case errors.Is(err, clientdb.ErrNotFound):
		return true, a.addRequestLocked(m)
	case err != nil:
		a.dropped++
		return false, false
	}
	if err := a.prof.DB.AppendMessage(ctx, m); err != nil {
		a.dropped++
		return false, false
	}
	a.unread[m.Peer]++
	return false, true
}

func (a *App) addRequestLocked(m clientdb.Message) bool {
	pending, exists := a.requests[m.Peer]
	if slices.ContainsFunc(pending, func(r clientdb.Message) bool { return r.MsgID == m.MsgID }) {
		a.dropped++
		return false
	}
	if (!exists && len(a.requests) >= maxRequestSenders) || len(pending) >= maxRequestMessages {
		a.dropped++
		return false
	}
	a.requests[m.Peer] = append(pending, m)
	return true
}

// persistRequestsLocked moves the message requests of a new contact into
// the database.
func (a *App) persistRequestsLocked(ctx context.Context, id identity.ID) error {
	for _, r := range a.requests[id] {
		err := a.prof.DB.AppendMessage(ctx, r)
		if errors.Is(err, clientdb.ErrDuplicate) {
			continue
		}
		if err != nil {
			return err
		}
		a.unread[id]++
	}
	delete(a.requests, id)
	return nil
}

func (a *App) countDropped() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dropped++
}

// Send encrypts text for a contact, stores it and hands it to the relay.
// Relay and network failures are reported in the returned message's status,
// not as an error.
func (a *App) Send(ctx context.Context, contactID, text string) (tui.MessageInfo, error) {
	id, err := parseContactID(contactID)
	if err != nil {
		return tui.MessageInfo{}, err
	}
	switch {
	case text == "":
		return tui.MessageInfo{}, ErrEmptyMessage
	case len(text) > e2e.MaxBodySize:
		return tui.MessageInfo{}, ErrMessageTooLong
	case !utf8.ValidString(text):
		return tui.MessageInfo{}, errors.New("message is not valid UTF-8")
	}
	c, err := a.getContact(context.Background(), id)
	if err != nil {
		return tui.MessageInfo{}, err
	}
	recipient, err := identity.ParseBundleForID(c.Bundle, id)
	if err != nil {
		return tui.MessageInfo{}, fmt.Errorf("stored key of this contact is invalid: %w", err)
	}
	now := a.now()
	payload, msgID, err := e2e.Seal(a.prof.Identity, recipient, e2e.KindText, []byte(text), now)
	if err != nil {
		return tui.MessageInfo{}, err
	}
	record := clientdb.Message{Peer: id, MsgID: msgID, Dir: clientdb.Outgoing, Sent: now, Body: text, Status: clientdb.StatusSent}
	key := messageKey{peer: id, msgID: msgID}
	a.mu.Lock()
	err = a.prof.DB.AppendMessage(context.Background(), record)
	if err == nil {
		a.inflight[key] = struct{}{}
	}
	a.mu.Unlock()
	if err != nil {
		return tui.MessageInfo{}, err
	}

	status, reason := a.deliver(ctx, id, payload)
	record.Status = status
	a.mu.Lock()
	delete(a.inflight, key)
	updateErr := a.prof.DB.UpdateMessageStatus(context.Background(), id, msgID, status)
	a.mu.Unlock()
	info := a.messageInfo(record)
	info.Error = reason
	if updateErr != nil {
		return info, updateErr
	}
	return info, nil
}

// deliver hands a sealed payload to the relay and returns the stored status
// of the message with a short reason for failures.
func (a *App) deliver(ctx context.Context, to identity.ID, payload []byte) (uint8, string) {
	sess := a.session()
	if sess == nil {
		return clientdb.StatusFailed, "not connected"
	}
	frame, err := sess.Request(ctx, protocol.TypeSend, protocol.Send{To: to[:], Payload: payload})
	var remote *client.RemoteError
	switch {
	case errors.Is(err, client.ErrNotConnected):
		return clientdb.StatusFailed, "not connected"
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return clientdb.StatusFailed, "no answer from the server"
	case errors.As(err, &remote) && remote.Code == protocol.ErrCodeTooLarge:
		return clientdb.StatusFailed, "too large for this server"
	case errors.As(err, &remote) && remote.Code == protocol.ErrCodeRateLimited:
		return clientdb.StatusFailed, "rate limited, try again shortly"
	case errors.As(err, &remote):
		return clientdb.StatusFailed, "rejected by the server (" + remote.Code.String() + ")"
	case err != nil:
		return clientdb.StatusFailed, "connection lost"
	}
	result, err := protocol.DecodeBody[protocol.SendResult](frame, protocol.TypeSendResult)
	switch {
	case err != nil:
		return clientdb.StatusFailed, "unexpected answer from the server"
	case result.Status == protocol.SendDelivered:
		return clientdb.StatusDelivered, ""
	default:
		return clientdb.StatusOffline, ""
	}
}

// History returns up to limit of the latest messages with a contact,
// oldest first.
func (a *App) History(contactID string, limit int) ([]tui.MessageInfo, error) {
	id, err := parseContactID(contactID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	msgs, err := a.prof.DB.Messages(context.Background(), id, limit, 0)
	if err != nil {
		return nil, err
	}
	out := make([]tui.MessageInfo, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, a.messageInfo(m))
	}
	return out, nil
}

// messageInfo maps a stored message to the interface's form. An outgoing
// message still marked as handed to the relay that is not in flight was
// interrupted, for example by a crash, and is shown as failed.
func (a *App) messageInfo(m clientdb.Message) tui.MessageInfo {
	info := tui.MessageInfo{
		ID:        hex.EncodeToString(m.MsgID[:]),
		Outgoing:  m.Dir == clientdb.Outgoing,
		Text:      m.Body,
		Sent:      m.Sent,
		ClockSkew: m.Flags&clientdb.FlagClockSkew != 0,
	}
	if !info.Outgoing {
		info.Received = m.Received
		return info
	}
	switch m.Status {
	case clientdb.StatusSent:
		a.mu.Lock()
		_, pending := a.inflight[messageKey{peer: m.Peer, msgID: m.MsgID}]
		a.mu.Unlock()
		info.Status = tui.StatusSending
		if !pending {
			info.Status, info.Error = tui.StatusFailed, "interrupted"
		}
	case clientdb.StatusDelivered:
		info.Status = tui.StatusSent
	case clientdb.StatusOffline:
		info.Status = tui.StatusRecipientOffline
	default:
		info.Status, info.Error = tui.StatusFailed, "not sent"
	}
	return info
}
