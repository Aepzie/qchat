package clientdb

import (
	"context"
	"errors"
	"testing"
)

func TestScanSkipsDamagedRows(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	c := sampleContact(t, "Alice")
	if err := d.PutContact(ctx, c); err != nil {
		t.Fatal(err)
	}
	group, sender := randomID(t), randomID(t)
	for _, body := range []string{"one", "two", "three"} {
		if err := d.AppendMessage(ctx, sampleMessage(t, c.ID, body)); err != nil {
			t.Fatal(err)
		}
		if err := d.AppendGroupMessage(ctx, sampleGroupMessage(t, group, sender, body)); err != nil {
			t.Fatal(err)
		}
	}
	damage := func(peerLookup []byte) {
		t.Helper()
		var seq int64
		var value []byte
		if err := d.conn.QueryRow(`SELECT seq, value FROM messages WHERE peer = ? ORDER BY seq LIMIT 1 OFFSET 1`, peerLookup).Scan(&seq, &value); err != nil {
			t.Fatal(err)
		}
		value[len(value)/2] ^= 0x40
		if _, err := d.conn.Exec(`UPDATE messages SET value = ? WHERE seq = ?`, value, seq); err != nil {
			t.Fatal(err)
		}
	}
	damage(d.keys.contactLookup(c.ID))
	damage(d.keys.groupLookup(group))

	if _, err := d.Messages(ctx, c.ID, 10, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Messages on a damaged row: %v, want ErrCorrupt", err)
	}
	page, err := d.ScanMessages(ctx, c.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Rows != 3 || page.Skipped != 1 || len(page.Messages) != 2 || page.Messages[0].Body != "one" || page.Messages[1].Body != "three" || page.Next != page.Messages[0].Seq {
		t.Errorf("contact scan: %+v", page)
	}
	older, err := d.ScanMessages(ctx, c.ID, 10, page.Next)
	if err != nil || older.Rows != 0 || older.Next != 0 {
		t.Errorf("page past the oldest row: %+v, %v", older, err)
	}

	gpage, err := d.ScanGroupMessages(ctx, group, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if gpage.Rows != 2 || gpage.Skipped != 1 || len(gpage.Messages) != 1 || gpage.Messages[0].Body != "three" {
		t.Errorf("group scan: %+v", gpage)
	}
	gnext, err := d.ScanGroupMessages(ctx, group, 2, gpage.Next)
	if err != nil || gnext.Rows != 1 || len(gnext.Messages) != 1 || gnext.Messages[0].Body != "one" {
		t.Errorf("second group page: %+v, %v", gnext, err)
	}
	if _, err := d.ScanMessages(ctx, c.ID, 0, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero limit: %v", err)
	}
	if _, err := d.ScanGroupMessages(ctx, group, 1, -1); !errors.Is(err, ErrInvalid) {
		t.Errorf("negative cursor: %v", err)
	}
}
