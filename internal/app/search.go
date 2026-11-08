package app

import (
	"cmp"
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/craguS/qchat/internal/group"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/store/clientdb"
	"github.com/craguS/qchat/internal/tui"
)

// searchScanLimit is how many of the most recent messages of each
// conversation Search reads at most.
var searchScanLimit = 2000

// Search implements tui.SearchBackend.
//
// The client database encrypts every message row on its own and keeps no
// plaintext anywhere, so there is no search index to consult: an index of
// the words in the history would be a second, searchable copy of it, and
// even keyed tokens would reveal which messages share words and how often.
// Search therefore decrypts and scans. To keep that bounded it reads, for
// each conversation, at most the searchScanLimit most recent messages,
// newest page first, and stops early once the context is done. Matching
// ignores case. Message requests are kept in memory only and are not
// searched.
//
// Hits are returned newest first, at most limit of them.
func (a *App) Search(ctx context.Context, query, conversationID string, limit int) ([]tui.SearchHit, error) {
	needle := strings.ToLower(strings.TrimSpace(query))
	if needle == "" || limit <= 0 {
		return nil, nil
	}
	var hits []tui.SearchHit
	scanContact := func(id identity.ID) error {
		found, err := a.searchContact(ctx, id, needle)
		hits = append(hits, found...)
		return err
	}
	scanGroup := func(id group.ID) error {
		found, err := a.searchGroup(ctx, id, needle)
		hits = append(hits, found...)
		return err
	}
	switch {
	case conversationID != "" && isGroupKey(conversationID):
		gid, err := parseGroupKey(conversationID)
		if err != nil {
			return nil, err
		}
		if err := scanGroup(gid); err != nil {
			return nil, err
		}
	case conversationID != "":
		id, err := parseContactID(conversationID)
		if err != nil {
			return nil, err
		}
		if err := scanContact(id); err != nil {
			return nil, err
		}
	default:
		contacts, err := a.prof.DB.ListContacts(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range contacts {
			if err := scanContact(identity.ID(c.ID)); err != nil {
				return nil, err
			}
		}
		groups, err := a.prof.DB.ListGroups(ctx)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			if err := scanGroup(group.ID(g.ID)); err != nil {
				return nil, err
			}
		}
	}
	slices.SortStableFunc(hits, func(x, y tui.SearchHit) int { return y.At.Compare(x.At) })
	return hits[:min(len(hits), limit)], nil
}

// searchContact scans the most recent messages exchanged with a contact.
func (a *App) searchContact(ctx context.Context, id identity.ID, needle string) ([]tui.SearchHit, error) {
	var hits []tui.SearchHit
	var before int64
	for scanned := 0; scanned < searchScanLimit; {
		if err := ctx.Err(); err != nil {
			return hits, err
		}
		page, err := a.prof.DB.Messages(ctx, id, min(clientdb.MaxPageSize, searchScanLimit-scanned), before)
		if err != nil {
			return hits, err
		}
		for _, m := range page {
			if strings.Contains(strings.ToLower(m.Body), needle) {
				hits = append(hits, tui.SearchHit{
					ConversationID: canonicalID(id),
					MessageID:      hex.EncodeToString(m.MsgID[:]),
					Outgoing:       m.Dir == clientdb.Outgoing,
					Text:           m.Body,
					At:             messageTime(m.Dir, m.Sent, m.Received),
				})
			}
		}
		if len(page) < clientdb.MaxPageSize || len(page) == 0 {
			return hits, nil
		}
		scanned += len(page)
		before = page[0].Seq
	}
	return hits, nil
}

// searchGroup scans the most recent messages of a group.
func (a *App) searchGroup(ctx context.Context, gid group.ID, needle string) ([]tui.SearchHit, error) {
	var hits []tui.SearchHit
	var before int64
	for scanned := 0; scanned < searchScanLimit; {
		if err := ctx.Err(); err != nil {
			return hits, err
		}
		page, err := a.prof.DB.GroupMessages(ctx, gid, min(clientdb.MaxPageSize, searchScanLimit-scanned), before)
		if err != nil {
			return hits, err
		}
		for _, m := range page {
			if !strings.Contains(strings.ToLower(m.Body), needle) {
				continue
			}
			hit := tui.SearchHit{
				ConversationID: groupKey(gid),
				MessageID:      hex.EncodeToString(m.MsgID[:]),
				Outgoing:       m.Dir == clientdb.Outgoing,
				Text:           m.Body,
				At:             messageTime(m.Dir, m.Sent, m.Received),
			}
			if !hit.Outgoing {
				hit.From = canonicalID(identity.ID(m.Sender))
			}
			hits = append(hits, hit)
		}
		if len(page) < clientdb.MaxPageSize || len(page) == 0 {
			return hits, nil
		}
		scanned += len(page)
		before = page[0].Seq
	}
	return hits, nil
}

// messageTime is when a message reached this device: the receive time of
// an incoming message, the send time of an outgoing one.
func messageTime(dir clientdb.Direction, sent, received time.Time) time.Time {
	if dir == clientdb.Incoming && !received.IsZero() {
		return received
	}
	return cmp.Or(sent, received)
}

var _ tui.SearchBackend = (*App)(nil)
