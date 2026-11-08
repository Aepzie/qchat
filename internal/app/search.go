package app

import (
	"cmp"
	"container/heap"
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Aepzie/qchat/internal/group"
	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/store/clientdb"
	"github.com/Aepzie/qchat/internal/tui"
)

var (
	// searchScanLimit is how many of the most recent messages of each
	// conversation Search reads at most.
	searchScanLimit = 2000
	// searchTotalScanLimit is how many messages one Search reads at most
	// across all conversations.
	searchTotalScanLimit = 20000
)

// searchSnippetBytes bounds the text of a hit: an excerpt of the body
// around the match, not the whole body.
const searchSnippetBytes = 1024

// Search implements tui.SearchBackend.
//
// The client database encrypts every message row on its own and keeps no
// plaintext anywhere, so there is no search index to consult: an index of
// the words in the history would be a second, searchable copy of it, and
// even keyed tokens would reveal which messages share words and how often.
// Search therefore decrypts and scans. To keep that bounded it reads, for
// each conversation, at most the searchScanLimit most recent messages,
// newest page first, at most searchTotalScanLimit messages in all, and
// stops early once the context is done. Rows that cannot be decrypted are
// skipped rather than failing the search. Matching ignores case. Message
// requests are kept in memory only and are not searched.
//
// Hits are returned newest first, at most limit of them. Only the limit
// newest hits are kept while scanning, and each holds an excerpt of at most
// searchSnippetBytes around the match instead of the whole body.
func (a *App) Search(ctx context.Context, query, conversationID string, limit int) ([]tui.SearchHit, error) {
	hits, _, err := a.search(ctx, query, conversationID, limit)
	return hits, err
}

// search is Search that also reports how many rows it skipped because they
// could not be decrypted or decoded.
func (a *App) search(ctx context.Context, query, conversationID string, limit int) ([]tui.SearchHit, int, error) {
	needle := strings.ToLower(strings.TrimSpace(query))
	if needle == "" || limit <= 0 {
		return nil, 0, nil
	}
	s := &searcher{app: a, needle: needle, limit: limit, budget: searchTotalScanLimit}
	if err := s.run(ctx, conversationID); err != nil {
		return nil, s.skipped, err
	}
	return s.results(), s.skipped, nil
}

// searcher holds the state of one search.
type searcher struct {
	app    *App
	needle string
	limit  int
	// budget is how many more messages may be read.
	budget int
	// skipped counts rows that could not be decrypted or decoded.
	skipped int
	// found counts the hits kept so far, to order hits of the same time.
	found int
	hits  hitHeap
}

// run scans one conversation, or all of them when conversationID is "".
func (s *searcher) run(ctx context.Context, conversationID string) error {
	switch {
	case conversationID != "" && isGroupKey(conversationID):
		gid, err := parseGroupKey(conversationID)
		if err != nil {
			return err
		}
		return s.scanGroup(ctx, gid)
	case conversationID != "":
		id, err := parseContactID(conversationID)
		if err != nil {
			return err
		}
		return s.scanContact(ctx, id)
	}
	contacts, err := s.app.prof.DB.ListContacts(ctx)
	if err != nil {
		return err
	}
	for _, c := range contacts {
		if err := s.scanContact(ctx, identity.ID(c.ID)); err != nil {
			return err
		}
	}
	groups, err := s.app.prof.DB.ListGroups(ctx)
	if err != nil {
		return err
	}
	for _, g := range groups {
		if err := s.scanGroup(ctx, group.ID(g.ID)); err != nil {
			return err
		}
	}
	return nil
}

// scanContact scans the most recent messages exchanged with a contact.
func (s *searcher) scanContact(ctx context.Context, id identity.ID) error {
	var before int64
	for scanned := 0; scanned < searchScanLimit && s.budget > 0; {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := s.app.prof.DB.ScanMessages(ctx, id, s.pageSize(scanned), before)
		if err != nil {
			return err
		}
		s.account(page.Rows, page.Skipped)
		for _, m := range page.Messages {
			s.consider(m.Body, messageTime(m.Dir, m.Sent, m.Received), func(text string) tui.SearchHit {
				return tui.SearchHit{
					ConversationID: canonicalID(id),
					MessageID:      hex.EncodeToString(m.MsgID[:]),
					Outgoing:       m.Dir == clientdb.Outgoing,
					Text:           text,
				}
			})
		}
		if page.Rows < clientdb.MaxPageSize {
			return nil
		}
		scanned += page.Rows
		before = page.Next
	}
	return nil
}

// scanGroup scans the most recent messages of a group.
func (s *searcher) scanGroup(ctx context.Context, gid group.ID) error {
	var before int64
	for scanned := 0; scanned < searchScanLimit && s.budget > 0; {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := s.app.prof.DB.ScanGroupMessages(ctx, gid, s.pageSize(scanned), before)
		if err != nil {
			return err
		}
		s.account(page.Rows, page.Skipped)
		for _, m := range page.Messages {
			s.consider(m.Body, messageTime(m.Dir, m.Sent, m.Received), func(text string) tui.SearchHit {
				hit := tui.SearchHit{
					ConversationID: groupKey(gid),
					MessageID:      hex.EncodeToString(m.MsgID[:]),
					Outgoing:       m.Dir == clientdb.Outgoing,
					Text:           text,
				}
				if !hit.Outgoing {
					hit.From = canonicalID(identity.ID(m.Sender))
				}
				return hit
			})
		}
		if page.Rows < clientdb.MaxPageSize {
			return nil
		}
		scanned += page.Rows
		before = page.Next
	}
	return nil
}

// pageSize is how many rows the next page of a conversation may read, given
// how many of its rows were read already.
func (s *searcher) pageSize(scanned int) int {
	return min(clientdb.MaxPageSize, searchScanLimit-scanned, s.budget)
}

// account charges rows read against the total budget.
func (s *searcher) account(rows, skipped int) {
	s.budget -= rows
	s.skipped += skipped
}

// consider keeps a matching message when it is among the limit newest hits
// so far. hit builds the hit from the excerpt; it is called only for
// messages that are kept.
func (s *searcher) consider(body string, at time.Time, hit func(text string) tui.SearchHit) {
	if len(s.hits) >= s.limit && !s.hits[0].hit.At.Before(at) {
		return
	}
	start, end, ok := foldIndex(body, s.needle)
	if !ok {
		return
	}
	h := hit(excerpt(body, start, end, searchSnippetBytes))
	h.At = at
	s.found++
	heap.Push(&s.hits, keptHit{hit: h, order: s.found})
	if len(s.hits) > s.limit {
		heap.Pop(&s.hits)
	}
}

// results returns the kept hits, newest first; hits of the same time keep
// the order in which they were found.
func (s *searcher) results() []tui.SearchHit {
	kept := slices.Clone(s.hits)
	slices.SortFunc(kept, func(x, y keptHit) int { return y.compare(x) })
	hits := make([]tui.SearchHit, len(kept))
	for i, k := range kept {
		hits[i] = k.hit
	}
	return hits
}

// keptHit is a hit and the order in which it was found.
type keptHit struct {
	hit   tui.SearchHit
	order int
}

// compare orders hits by time, and hits of the same time so that the one
// found later comes first, which makes it the first to be dropped.
func (k keptHit) compare(o keptHit) int {
	if c := k.hit.At.Compare(o.hit.At); c != 0 {
		return c
	}
	return cmp.Compare(o.order, k.order)
}

// hitHeap is a min-heap of hits in compare order, so that the oldest kept
// hit is the one dropped when a newer one arrives.
type hitHeap []keptHit

func (h hitHeap) Len() int           { return len(h) }
func (h hitHeap) Less(i, j int) bool { return h[i].compare(h[j]) < 0 }
func (h hitHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *hitHeap) Push(x any)        { *h = append(*h, x.(keptHit)) }
func (h *hitHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	old[len(old)-1] = keptHit{}
	*h = old[:len(old)-1]
	return last
}

// foldIndex returns the byte range in body of the first match of needle,
// which must be lower case, comparing body lower-cased as strings.ToLower
// does. Lower-casing can change the length of a rune, so an offset found in
// the lower-cased body is mapped back rune by rune.
func foldIndex(body, needle string) (start, end int, ok bool) {
	lower := strings.ToLower(body)
	at := strings.Index(lower, needle)
	if at < 0 {
		return 0, 0, false
	}
	if isASCII(body) {
		return at, at + len(needle), true
	}
	start, end = len(body), len(body)
	found := false
	folded := 0
	for i, r := range body {
		if !found && folded >= at {
			start, found = i, true
		}
		if folded >= at+len(needle) {
			end = i
			break
		}
		folded += utf8.RuneLen(unicode.ToLower(r))
	}
	return start, end, true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// excerpt returns at most size bytes of body around body[start:end], cut on
// rune boundaries and marked with an ellipsis where text was left out.
func excerpt(body string, start, end, size int) string {
	if len(body) <= size {
		return body
	}
	const ellipsis = "…"
	room := size - 2*len(ellipsis)
	end = min(end, start+room)
	from := max(0, start-(room-(end-start))/2)
	to := min(len(body), from+room)
	from = max(0, to-room)
	for from < to && !utf8.RuneStart(body[from]) {
		from++
	}
	for to > from && to < len(body) && !utf8.RuneStart(body[to]) {
		to--
	}
	out := body[from:to]
	if from > 0 {
		out = ellipsis + out
	}
	if to < len(body) {
		out += ellipsis
	}
	return out
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
