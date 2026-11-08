package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Aepzie/qchat/internal/profile"
	"github.com/Aepzie/qchat/internal/store/clientdb"
	"github.com/Aepzie/qchat/internal/tui"
)

func hitTexts(hits []tui.SearchHit) []string {
	out := make([]string, len(hits))
	for i, h := range hits {
		out[i] = h.Text
	}
	return out
}

func TestSearchHistory(t *testing.T) {
	r, alice, bob, carol, gid := newGroupOfThree(t)
	bob.send(alice, "do you have the LIBRARY card?")
	wantTexts(t, "alice", alice.receive(), "do you have the LIBRARY card?")
	r.clock.Advance(time.Minute)
	carol.sendGroup(gid, "meet at the library at six")
	settle(t, alice, bob, carol)
	r.clock.Advance(time.Minute)
	alice.sendGroup(gid, "see you there")
	settle(t, alice, bob, carol)

	ctx := context.Background()
	hits, err := alice.app.Search(ctx, "  Library ", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("hits %q", hitTexts(hits))
	}
	byText := map[string]tui.SearchHit{}
	for _, h := range hits {
		byText[h.Text] = h
	}
	g := byText["meet at the library at six"]
	if g.ConversationID != gid || g.From != carol.cid() || g.Outgoing || g.MessageID == "" || g.At.IsZero() {
		t.Errorf("group hit %+v", g)
	}
	c := byText["do you have the LIBRARY card?"]
	if c.ConversationID != bob.cid() || c.From != "" || c.Outgoing {
		t.Errorf("contact hit %+v", c)
	}
	if hits[0].At.Before(hits[1].At) {
		t.Errorf("hits not newest first: %v, %v", hits[0].At, hits[1].At)
	}

	only, err := alice.app.Search(ctx, "library", bob.cid(), 10)
	if err != nil || len(only) != 1 || only[0].ConversationID != bob.cid() {
		t.Errorf("contact scope: %q, %v", hitTexts(only), err)
	}
	only, err = alice.app.Search(ctx, "LIBRARY", gid, 10)
	if err != nil || len(only) != 1 || only[0].ConversationID != gid {
		t.Errorf("group scope: %q, %v", hitTexts(only), err)
	}
	own, err := alice.app.Search(ctx, "see you", "", 10)
	if err != nil || len(own) != 1 || !own[0].Outgoing || own[0].From != "" {
		t.Errorf("own message: %+v, %v", own, err)
	}
	if limited, _ := alice.app.Search(ctx, "library", "", 1); len(limited) != 1 {
		t.Errorf("limit not applied: %d", len(limited))
	}
	if none, err := alice.app.Search(ctx, "   ", "", 10); err != nil || none != nil {
		t.Errorf("empty query: %v, %v", none, err)
	}
	if _, err := alice.app.Search(ctx, "x", "qc1-bogus", 10); err == nil {
		t.Error("bad conversation ID accepted")
	}
	if _, err := alice.app.Search(ctx, "x", "grp-zz", 10); err == nil {
		t.Error("bad group ID accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := alice.app.Search(cancelled, "library", "", 10); err == nil {
		t.Error("cancelled search succeeded")
	}
}

func TestSearchScanIsBounded(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "alice"), newFakeUser(t, r, "bob")
	alice.add(bob)
	ctx := context.Background()
	base := r.clock.Now().Add(-time.Hour)
	const total = 620
	for i := 0; i < total; i++ {
		var msgID [16]byte
		if _, err := rand.Read(msgID[:]); err != nil {
			t.Fatal(err)
		}
		body := fmt.Sprintf("message %d", i)
		if i == 0 {
			body = "the oldest needle"
		}
		at := base.Add(time.Duration(i) * time.Second)
		if err := alice.prof.DB.AppendMessage(ctx, clientdb.Message{Peer: bob.id, MsgID: msgID, Dir: clientdb.Incoming, Sent: at, Received: at, Body: body, Status: clientdb.StatusReceived}); err != nil {
			t.Fatal(err)
		}
	}

	hits, err := alice.app.Search(ctx, "needle", bob.cid(), 10)
	if err != nil || len(hits) != 1 || hits[0].Text != "the oldest needle" {
		t.Fatalf("search across pages: %q, %v", hitTexts(hits), err)
	}
	all, err := alice.app.Search(ctx, "message", "", 1000)
	if err != nil || len(all) != total-1 || !strings.HasSuffix(all[0].Text, fmt.Sprint(total-1)) {
		t.Fatalf("got %d hits, first %q, %v", len(all), all[0].Text, err)
	}

	old := searchScanLimit
	searchScanLimit = total - 10
	t.Cleanup(func() { searchScanLimit = old })
	if hits, err := alice.app.Search(ctx, "needle", "", 10); err != nil || len(hits) != 0 {
		t.Errorf("message beyond the scan limit found: %q, %v", hitTexts(hits), err)
	}
	if hits, _ := alice.app.Search(ctx, "message", "", 1000); len(hits) != total-10 {
		t.Errorf("scanned %d messages, want %d", len(hits), total-10)
	}
}

// appendIncoming stores an incoming message from peer directly in u's
// database.
func appendIncoming(t *testing.T, u *fakeUser, peer *fakeUser, body string, at time.Time) {
	t.Helper()
	var msgID [16]byte
	if _, err := rand.Read(msgID[:]); err != nil {
		t.Fatal(err)
	}
	m := clientdb.Message{Peer: peer.id, MsgID: msgID, Dir: clientdb.Incoming, Sent: at, Received: at, Body: body, Status: clientdb.StatusReceived}
	if err := u.prof.DB.AppendMessage(context.Background(), m); err != nil {
		t.Fatal(err)
	}
}

func TestSearchSkipsUndecryptableRows(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "alice"), newFakeUser(t, r, "bob")
	alice.add(bob)
	base := r.clock.Now().Add(-time.Hour)
	for i := range 3 {
		appendIncoming(t, alice, bob, fmt.Sprintf("needle %d", i), base.Add(time.Duration(i)*time.Second))
	}

	conn, err := sql.Open("sqlite", filepath.Join(alice.dir, profile.DBFileName)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Exec(`UPDATE messages SET value = x'00' WHERE seq = (SELECT seq FROM messages ORDER BY seq LIMIT 1 OFFSET 1)`); err != nil {
		t.Fatal(err)
	}

	hits, skipped, err := alice.app.search(context.Background(), "needle", "", 10)
	if err != nil {
		t.Fatalf("search failed on a damaged row: %v", err)
	}
	if skipped != 1 || len(hits) != 2 || hits[0].Text != "needle 2" || hits[1].Text != "needle 0" {
		t.Errorf("skipped %d, hits %q", skipped, hitTexts(hits))
	}
}

func TestSearchKeepsExcerptsAndBoundsTotalWork(t *testing.T) {
	r := newFakeRelay()
	alice, bob, carol := newFakeUser(t, r, "alice"), newFakeUser(t, r, "bob"), newFakeUser(t, r, "carol")
	alice.add(bob)
	alice.add(carol)
	ctx := context.Background()
	base := r.clock.Now().Add(-time.Hour)

	long := strings.Repeat("x", 5000) + "The NEEDLE here" + strings.Repeat("y", 5000)
	appendIncoming(t, alice, bob, long, base)
	kelvin := strings.Repeat(kelvinSign, 3000) + " needle after folded runes " + strings.Repeat(kelvinSign, 3000)
	appendIncoming(t, alice, bob, kelvin, base.Add(time.Second))
	hits, err := alice.app.Search(ctx, "needle", bob.cid(), 10)
	if err != nil || len(hits) != 2 {
		t.Fatalf("hits %d, %v", len(hits), err)
	}
	for _, h := range hits {
		if len(h.Text) > searchSnippetBytes || !utf8.ValidString(h.Text) || !strings.HasPrefix(h.Text, "…") || !strings.HasSuffix(h.Text, "…") {
			t.Errorf("excerpt of %d bytes: %.40q…", len(h.Text), h.Text)
		}
		if !strings.Contains(strings.ToLower(h.Text), "needle") {
			t.Errorf("excerpt lacks the match: %.80q", h.Text)
		}
	}

	for i := range 30 {
		appendIncoming(t, alice, carol, fmt.Sprintf("hay %d", i), base.Add(time.Minute+time.Duration(i)*time.Second))
	}
	old := searchTotalScanLimit
	searchTotalScanLimit = 20
	t.Cleanup(func() { searchTotalScanLimit = old })
	hits, err = alice.app.Search(ctx, "hay", "", 100)
	if err != nil || len(hits) > 20 {
		t.Errorf("total scan limit not applied: %d hits, %v", len(hits), err)
	}
	searchTotalScanLimit = old

	top, err := alice.app.Search(ctx, "hay", "", 3)
	if err != nil || strings.Join(hitTexts(top), ",") != "hay 29,hay 28,hay 27" {
		t.Errorf("newest hits: %q, %v", hitTexts(top), err)
	}
}

// kelvinSign is three bytes long but lower-cases to the one-byte "k".
const kelvinSign = "\xe2\x84\xaa"

func TestExcerpt(t *testing.T) {
	body := strings.Repeat("é", 2000)
	for _, at := range []int{0, 2, 1000, 3998} {
		got := excerpt(body, at, at+2, 100)
		if len(got) > 100 || !utf8.ValidString(got) {
			t.Errorf("excerpt at %d: %d bytes, valid %v", at, len(got), utf8.ValidString(got))
		}
	}
	if got := excerpt("short", 0, 1, 100); got != "short" {
		t.Errorf("short body: %q", got)
	}
	start, end, ok := foldIndex(kelvinSign+kelvinSign+"ABC"+kelvinSign, "abc")
	if !ok || start != 6 || end != 9 {
		t.Errorf("foldIndex = %d, %d, %v", start, end, ok)
	}
}
