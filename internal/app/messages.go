package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
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

// handleDelivery decrypts, verifies and files one relayed message, and
// acknowledges it to the relay unless it failed for a reason that may not
// recur (see transientError). Anything that fails is dropped without
// telling the interface: the relay, or whoever controls it, must not be
// able to inject content or noise.
func (a *App) handleDelivery(ctx context.Context, d client.Delivery) {
	ack, events := a.receive(ctx, d)
	if ack && d.QueueID != 0 {
		if sess := a.session(); sess != nil {
			_ = sess.Ack(d.QueueID)
		}
	}
	for _, ev := range events {
		a.emit(ev)
	}
}

// receive processes one delivery. It reports whether the delivery may be
// acknowledged (it was filed, or it can never be read) and returns the
// events to show.
func (a *App) receive(ctx context.Context, d client.Delivery) (bool, []tui.ChatEvent) {
	from := identity.ID(d.From)
	env, err := e2e.ParseEnvelope(d.Payload)
	if err != nil || from == a.prof.Identity.ID() {
		a.countDropped()
		return true, nil
	}
	return a.openAndFile(ctx, from, env)
}

func (a *App) openAndFile(ctx context.Context, from identity.ID, env e2e.Envelope) (bool, []tui.ChatEvent) {
	a.ratchetMu.Lock()
	defer a.ratchetMu.Unlock()
	o, err := a.open(ctx, from, env)
	if err != nil {
		a.countDropped()
		return !isTransient(err), nil
	}
	defer clear(o.plaintext.Body)
	return a.fileOpened(ctx, from, o)
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
// not as an error; a message that could not even be encrypted, because no
// session could be started, is stored as failed.
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
	pt, err := e2e.NewPlaintext(e2e.KindText, []byte(text), a.now())
	if err != nil {
		return tui.MessageInfo{}, err
	}
	record := clientdb.Message{Peer: id, MsgID: pt.MsgID, Dir: clientdb.Outgoing, Sent: pt.Sent, Body: text, Status: clientdb.StatusSent}
	payload, reason, err := a.sealOutgoing(ctx, c, pt, record)
	if err != nil {
		return tui.MessageInfo{}, err
	}
	if reason != "" {
		record.Status = clientdb.StatusFailed
		if err := a.prof.DB.AppendMessage(context.Background(), record); err != nil {
			return tui.MessageInfo{}, err
		}
		info := a.messageInfo(record)
		info.Error = reason
		return info, nil
	}

	key := messageKey{peer: id, msgID: record.MsgID}
	status, reason := a.deliver(ctx, id, payload)
	record.Status = status
	a.mu.Lock()
	delete(a.inflight, key)
	updateErr := a.prof.DB.UpdateMessageStatus(context.Background(), id, record.MsgID, status)
	a.mu.Unlock()
	info := a.messageInfo(record)
	info.Error = reason
	if updateErr != nil {
		return info, updateErr
	}
	return info, nil
}

// relayFailure returns a short reason for a failed relay request, or ""
// for err == nil.
func relayFailure(err error) string {
	var remote *client.RemoteError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, client.ErrNotConnected):
		return "not connected"
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return "no answer from the server"
	case errors.As(err, &remote) && remote.Code == protocol.ErrCodeTooLarge:
		return "too large for this server"
	case errors.As(err, &remote) && remote.Code == protocol.ErrCodeRateLimited:
		return "rate limited, try again shortly"
	case errors.As(err, &remote) && remote.Code == protocol.ErrCodeQueueFull:
		return "the recipient's mailbox on the server is full"
	case errors.As(err, &remote) && remote.Code == protocol.ErrCodeNotFound:
		return "the recipient is not registered on this server"
	case errors.As(err, &remote):
		return "rejected by the server (" + remote.Code.String() + ")"
	default:
		return "connection lost"
	}
}

// deliver hands an envelope to the relay and returns the stored status of
// the message with a short reason for failures.
func (a *App) deliver(ctx context.Context, to identity.ID, payload []byte) (uint8, string) {
	sess := a.session()
	if sess == nil {
		return clientdb.StatusFailed, "not connected"
	}
	frame, err := sess.Request(ctx, protocol.TypeSend, protocol.Send{To: to[:], Payload: payload})
	if reason := relayFailure(err); reason != "" {
		return clientdb.StatusFailed, reason
	}
	result, err := protocol.DecodeBody[protocol.SendResult](frame, protocol.TypeSendResult)
	switch {
	case err != nil:
		return clientdb.StatusFailed, "unexpected answer from the server"
	case result.Status == protocol.SendAccepted || result.Status == protocol.SendDelivered:
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
// interrupted, for example by a crash, and is shown as failed. A message
// the relay accepted (StatusDelivered) is shown as sent: the relay stores
// it until the recipient fetches it.
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
