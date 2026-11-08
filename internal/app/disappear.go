package app

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/craguS/qchat/internal/e2e"
	"github.com/craguS/qchat/internal/group"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/store/clientdb"
	"github.com/craguS/qchat/internal/tui"
)

// Disappearing messages (docs/design/phase-7-files.md)
//
// Every conversation has a timer, off by default. Setting it sends an
// e2e.KindTimer message (the duration in whole seconds, four bytes big
// endian) over the pairwise session or the own sender key, so both sides
// switch together; the setting with the latest sender time wins, and of
// two with the same time the longer one. A message filed while the timer
// is on stores its expiry: the send time for an outgoing message, the
// arrival time for an incoming one, plus the timer. The sweeper deletes
// expired messages from the database (with a WAL checkpoint), together with
// the files they offered, and tells the interface to remove them.

const (
	// MaxTimer is the longest disappearing message timer.
	MaxTimer = 4 * 7 * 24 * time.Hour
	// sweepInterval is how often expired messages are looked for.
	sweepInterval = 2 * time.Second
	// transferSweepInterval is how often stale transfers are looked for.
	transferSweepInterval = 10 * time.Minute
	// timerBodySize is the size of a timer message body.
	timerBodySize = 4
)

// ErrInvalidTimer is returned by SetTimer for a duration it does not
// support.
var ErrInvalidTimer = fmt.Errorf("the timer must be off or whole seconds up to %s", MaxTimer)

// timerBody encodes a timer message body.
func timerBody(d time.Duration) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(d/time.Second))
}

// parseTimerBody decodes a timer message body.
func parseTimerBody(b []byte) (time.Duration, error) {
	if len(b) != timerBodySize {
		return 0, ErrInvalidTimer
	}
	d := time.Duration(binary.BigEndian.Uint32(b)) * time.Second
	if d > MaxTimer {
		return 0, ErrInvalidTimer
	}
	return d, nil
}

// expiryFor returns when a message filed at base in the conversation conv
// expires, or the zero time when its timer is off.
func (a *App) expiryFor(ctx context.Context, conv [32]byte, base time.Time) time.Time {
	t, err := a.prof.DB.GetTimer(ctx, conv)
	if err != nil || t.Duration <= 0 {
		return time.Time{}
	}
	return base.Add(t.Duration)
}

// Timer returns the disappearing message timer of a conversation.
func (a *App) Timer(conversationID string) (time.Duration, error) {
	conv, err := parseConversation(conversationID)
	if err != nil {
		return 0, err
	}
	t, err := a.prof.DB.GetTimer(context.Background(), conv.id)
	if errors.Is(err, clientdb.ErrNotFound) {
		return 0, nil
	}
	return t.Duration, err
}

// SetTimer sets the disappearing message timer of a conversation and tells
// the other side. The new timer applies once the relay accepted the timer
// message.
func (a *App) SetTimer(ctx context.Context, conversationID string, d time.Duration) error {
	if d < 0 || d > MaxTimer || d%time.Second != 0 {
		return ErrInvalidTimer
	}
	conv, err := parseConversation(conversationID)
	if err != nil {
		return err
	}
	sent, err := a.sendTimer(ctx, conv, timerBody(d))
	if err != nil {
		return err
	}
	return a.prof.DB.PutTimer(context.Background(), clientdb.Timer{Conv: conv.id, Duration: d, SetAt: sent})
}

// sendTimer sends a timer message and returns its send time.
func (a *App) sendTimer(ctx context.Context, conv conversationRef, body []byte) (time.Time, error) {
	if conv.group {
		gid := group.ID(conv.id)
		a.awaitBacklog(ctx)
		out, notice, err := a.sealGroupKind(ctx, gid, e2e.KindTimer, body, nil)
		if notice != "" {
			a.emit(tui.GroupChanged{GroupID: groupKey(gid), Notice: notice})
		}
		if err != nil {
			return time.Time{}, err
		}
		if status, reason, _ := a.deliverMulti(ctx, out.to, out.proofs, out.envelope); status == clientdb.StatusFailed {
			return time.Time{}, errors.New(reason)
		}
		return out.message.Sent, nil
	}
	id := identity.ID(conv.id)
	c, err := a.getContact(ctx, id)
	if err != nil {
		return time.Time{}, err
	}
	pt, err := e2e.NewPlaintext(e2e.KindTimer, body, a.now())
	if err != nil {
		return time.Time{}, err
	}
	route, err := a.routeTo(ctx, id)
	if err != nil {
		return time.Time{}, err
	}
	payload, reason, err := a.sealOutgoing(ctx, c, pt, nil, route)
	switch {
	case err != nil:
		return time.Time{}, err
	case reason != "":
		return time.Time{}, errors.New(reason)
	}
	if status, reason := a.deliverPairwise(ctx, c, route, payload); status == clientdb.StatusFailed {
		return time.Time{}, errors.New(reason)
	}
	return pt.Sent, nil
}

// applyTimer adopts a timer set by by at sent in a conversation, if it is
// newer than the stored one, and returns the notice to show.
func (a *App) applyTimer(ctx context.Context, conv [32]byte, isGroup bool, by identity.ID, d time.Duration, sent time.Time) []tui.ChatEvent {
	cur, err := a.prof.DB.GetTimer(ctx, conv)
	switch {
	case err == nil && sent.Before(cur.SetAt):
		return nil
	case err == nil && sent.Equal(cur.SetAt) && d <= cur.Duration:
		return nil
	case err != nil && !errors.Is(err, clientdb.ErrNotFound):
		return nil
	}
	if a.prof.DB.PutTimer(ctx, clientdb.Timer{Conv: conv, Duration: d, SetAt: sent}) != nil {
		return nil
	}
	if err == nil && cur.Duration == d {
		return nil
	}
	who := a.memberLabel(ctx, by)
	notice := who + " turned disappearing messages off."
	if d > 0 {
		notice = who + " set disappearing messages to " + FormatTimer(d) + ". New messages are deleted that long after they are sent or received."
	}
	return []tui.ChatEvent{tui.ConversationNotice{ConversationID: conversationKey(conv, isGroup), Notice: notice}}
}

// FormatTimer renders a timer the way /timer accepts it, such as "5m" or
// "1w"; zero is "off".
func FormatTimer(d time.Duration) string {
	units := []struct {
		suffix string
		size   time.Duration
	}{{"w", 7 * 24 * time.Hour}, {"d", 24 * time.Hour}, {"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}}
	if d <= 0 {
		return "off"
	}
	for _, u := range units {
		if d%u.size == 0 {
			return fmt.Sprint(int64(d/u.size)) + u.suffix
		}
	}
	return d.String()
}

// sweep deletes expired messages and their files, removes them from the
// interface, and every transferSweepInterval expires stale transfers. It
// holds groupMu so that no delivery files a chunk of a file being deleted.
func (a *App) sweep(ctx context.Context) {
	a.groupMu.Lock()
	events := a.sweepLocked(ctx)
	a.groupMu.Unlock()
	for _, ev := range events {
		a.emit(ev)
	}
}

func (a *App) sweepLocked(ctx context.Context) []tui.ChatEvent {
	now := a.now()
	expired := map[string][]string{}
	var order []string
	note := func(key string, msgID [e2e.MsgIDSize]byte) {
		if _, ok := expired[key]; !ok {
			order = append(order, key)
		}
		expired[key] = append(expired[key], hex.EncodeToString(msgID[:]))
	}
	for {
		gone, err := a.prof.DB.DeleteExpiredMessages(ctx, now)
		if err != nil {
			break
		}
		for _, e := range gone {
			if e.Flags&clientdb.FlagFile != 0 {
				a.dropMessageFile(ctx, e)
			}
			note(conversationKey(e.Conv, e.Group), e.MsgID)
		}
		if len(gone) == 0 || len(gone) < 500 {
			break
		}
	}
	a.mu.Lock()
	for id, reqs := range a.requests {
		kept := slices.DeleteFunc(reqs, func(m clientdb.Message) bool {
			if m.Expires.IsZero() || m.Expires.After(now) {
				return false
			}
			note(canonicalID(id), m.MsgID)
			return true
		})
		if len(kept) == 0 {
			delete(a.requests, id)
			continue
		}
		a.requests[id] = kept
	}
	a.mu.Unlock()
	var events []tui.ChatEvent
	for _, key := range order {
		events = append(events, tui.MessagesExpired{ConversationID: key, MessageIDs: expired[key]})
	}
	if now.Sub(a.lastTransferSweep) >= transferSweepInterval || now.Before(a.lastTransferSweep) {
		a.lastTransferSweep = now
		events = append(events, a.expireTransfers(ctx)...)
	}
	return events
}

// dropMessageFile deletes the file offered by an expired message.
func (a *App) dropMessageFile(ctx context.Context, e clientdb.ExpiredMessage) {
	sender := e.Sender
	if !e.Group {
		sender = e.Conv
		if e.Dir == clientdb.Outgoing {
			sender = a.selfID()
		}
	}
	t, err := a.prof.DB.FileTransferByMessage(ctx, e.Conv, sender, e.MsgID)
	if err != nil {
		return
	}
	a.abandonTransfer(ctx, t.Conv, t.Sender, t.FileID)
}

var _ tui.TimerBackend = (*App)(nil)
