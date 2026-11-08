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
	"github.com/craguS/qchat/internal/sealed"
	"github.com/craguS/qchat/internal/senderkey"
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

// outcome says what becomes of a relay delivery after processing.
type outcome uint8

const (
	// outcomeDone: the delivery was filed, or can never be read; it is
	// acknowledged.
	outcomeDone outcome = iota
	// outcomeRetry: a local failure that may not recur; the delivery is
	// not acknowledged, so the relay delivers it again.
	outcomeRetry
	// outcomeWait: the delivery needs a group state or sender key that has
	// not arrived yet; it waits (see groups.go) and is not acknowledged.
	outcomeWait
)

// handleDelivery decrypts, verifies and files one relayed message, and
// acknowledges it to the relay unless it failed for a reason that may not
// recur (see transientError) or waits for group input. Anything that fails
// is dropped without telling the interface: the relay, or whoever controls
// it, must not be able to inject content or noise.
func (a *App) handleDelivery(ctx context.Context, d client.Delivery) {
	a.groupMu.Lock()
	r := a.receive(ctx, d)
	var acks []uint64
	switch r.outcome {
	case outcomeDone:
		acks = append(acks, d.QueueID)
	case outcomeWait:
		if r.hold != nil && a.holdLocked(*r.hold) {
			acks = append(acks, d.QueueID)
		}
	}
	retried, events := a.retryPendingLocked(ctx, r.changed)
	a.groupMu.Unlock()
	acks = append(acks, retried...)
	if sess := a.session(); sess != nil {
		for _, q := range acks {
			if q != 0 {
				_ = sess.Ack(q)
			}
		}
	}
	for _, ev := range append(r.events, events...) {
		a.emit(ev)
	}
	if r.peer != nil {
		a.shareAccessKey(ctx, *r.peer)
	}
}

// received is the result of processing one delivery.
type received struct {
	outcome outcome
	// hold is the input to keep when the outcome is outcomeWait.
	hold *pendingGroup
	// changed reports a stored group state or sender key.
	changed bool
	events  []tui.ChatEvent
	// peer is the authenticated sender of a pairwise message that was
	// decrypted, nil otherwise.
	peer *identity.ID
}

// receive processes one delivery. a.groupMu must be held.
func (a *App) receive(ctx context.Context, d client.Delivery) received {
	if d.IsSealed() {
		return a.receiveSealed(ctx, d)
	}
	from := identity.ID(d.From)
	if from == a.prof.Identity.ID() {
		a.countDropped()
		return received{outcome: outcomeDone}
	}
	if senderkey.IsGroupEnvelope(d.Payload) {
		r := a.receiveGroupEnvelope(ctx, from, d.Payload)
		out := received{outcome: r.outcome, changed: r.changed, events: r.events}
		if r.outcome == outcomeWait {
			out.hold = &pendingGroup{queueID: d.QueueID, from: from, envelope: slices.Clone(d.Payload)}
		}
		return out
	}
	if sealed.IsEnvelope(d.Payload) {
		return a.receiveSealedPairwise(ctx, d, &from)
	}
	env, err := e2e.ParseEnvelope(d.Payload)
	if err != nil {
		a.countDropped()
		return received{outcome: outcomeDone}
	}
	return a.openAndFile(ctx, d.QueueID, from, env, from)
}

// openAndFile decrypts a pairwise envelope from from and files its
// content: a text message in the conversation, group input through
// applyGroupPayload once the session has been committed. A session start
// counts against the limiter bucket limit (see allowHandshake). a.groupMu
// must be held.
func (a *App) openAndFile(ctx context.Context, queueID uint64, from identity.ID, env e2e.Envelope, limit identity.ID) received {
	a.ratchetMu.Lock()
	o, err := a.open(ctx, from, env, limit)
	if err != nil {
		a.ratchetMu.Unlock()
		a.countDropped()
		return received{outcome: outcomeOf(err)}
	}
	defer clear(o.plaintext.Body)
	switch o.plaintext.Kind {
	case e2e.KindText:
		ack, events := a.fileOpened(ctx, from, o)
		a.ratchetMu.Unlock()
		if !ack {
			return received{outcome: outcomeRetry}
		}
		return received{outcome: outcomeDone, events: events, peer: &from}
	case e2e.KindAccessKey:
		r := a.fileAccessKey(ctx, from, o)
		a.ratchetMu.Unlock()
		if r.peer != nil && o.sender != nil && a.adoptBundle(from, o.sender) {
			r.events = append(r.events, tui.ContactKeyChanged{ContactID: canonicalID(from)})
		}
		return r
	case e2e.KindGroupControl, e2e.KindSenderKey:
	default:
		a.ratchetMu.Unlock()
		a.countDropped()
		return received{outcome: outcomeDone}
	}
	err = a.commitSession(ctx, from, o)
	a.ratchetMu.Unlock()
	if err != nil {
		a.countDropped()
		return received{outcome: outcomeOf(err)}
	}
	var events []tui.ChatEvent
	if o.sender != nil && a.adoptBundle(from, o.sender) {
		events = append(events, tui.ContactKeyChanged{ContactID: canonicalID(from)})
	}
	body := slices.Clone(o.plaintext.Body)
	r := a.applyGroupPayload(ctx, from, o.plaintext.Kind, body, o.sender)
	out := received{outcome: r.outcome, changed: r.changed, events: append(events, r.events...), peer: &from}
	if r.outcome == outcomeWait {
		out.hold = &pendingGroup{queueID: queueID, from: from, kind: o.plaintext.Kind, body: body, bundle: o.sender}
	}
	return out
}

// outcomeOf classifies a processing error.
func outcomeOf(err error) outcome {
	if isTransient(err) {
		return outcomeRetry
	}
	return outcomeDone
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
// For a group ID it sends a group message (see sendGroup).
// Relay and network failures are reported in the returned message's status,
// not as an error; a message that could not even be encrypted, because no
// session could be started, is stored as failed.
func (a *App) Send(ctx context.Context, contactID, text string) (tui.MessageInfo, error) {
	if isGroupKey(contactID) {
		return a.sendGroup(ctx, contactID, text)
	}
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
	route, err := a.routeTo(ctx, id)
	if err != nil {
		return tui.MessageInfo{}, err
	}
	record := clientdb.Message{Peer: id, MsgID: pt.MsgID, Dir: clientdb.Outgoing, Sent: pt.Sent, Body: text, Status: clientdb.StatusSent, Flags: route.flag()}
	payload, reason, err := a.sealOutgoing(ctx, c, pt, &record, route)
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
	status, reason := a.deliverPairwise(ctx, c, route, payload)
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
	if status == clientdb.StatusDelivered {
		a.shareAccessKey(ctx, id)
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

// History returns up to limit of the latest messages with a contact or in
// a group, oldest first.
func (a *App) History(contactID string, limit int) ([]tui.MessageInfo, error) {
	if isGroupKey(contactID) {
		return a.groupHistory(contactID, limit)
	}
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
	info.Route = routeOf(m.Flags)
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
