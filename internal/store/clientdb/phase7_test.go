package clientdb

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func sampleTransfer(t *testing.T, conv, sender [32]byte) FileTransfer {
	t.Helper()
	return FileTransfer{
		Conv:    conv,
		Sender:  sender,
		FileID:  randomMsgID(t),
		MsgID:   randomMsgID(t),
		Local:   randomMsgID(t),
		Dir:     Incoming,
		Offer:   []byte("encoded offer with a key"),
		State:   FileReceiving,
		Done:    3,
		Created: time.Unix(1_800_000_000, 0).UTC(),
	}
}

func TestFileTransferRoundTrip(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	conv := randomID(t)
	f := sampleTransfer(t, conv, conv)
	if err := d.PutFileTransfer(ctx, f); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetFileTransfer(ctx, conv, conv, f.FileID)
	if err != nil || !slices.Equal(got.Offer, f.Offer) || got.Local != f.Local || got.State != f.State || !got.Created.Equal(f.Created) {
		t.Fatalf("GetFileTransfer = %+v, %v", got, err)
	}
	byMsg, err := d.FileTransferByMessage(ctx, conv, conv, f.MsgID)
	if err != nil || byMsg.FileID != f.FileID {
		t.Fatalf("FileTransferByMessage = %+v, %v", byMsg, err)
	}
	if _, err := d.GetFileTransfer(ctx, conv, randomID(t), f.FileID); !errors.Is(err, ErrNotFound) {
		t.Errorf("same file ID from another sender: %v", err)
	}
	f.State, f.Done = FileComplete, 10
	if err := d.PutFileTransfer(ctx, f); err != nil {
		t.Fatal(err)
	}
	list, err := d.ListFileTransfers(ctx)
	if err != nil || len(list) != 1 || list[0].State != FileComplete || list[0].Done != 10 {
		t.Fatalf("ListFileTransfers = %+v, %v", list, err)
	}
	if err := d.DeleteFileTransfer(ctx, conv, conv, f.FileID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetFileTransfer(ctx, conv, conv, f.FileID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
	bad := f
	bad.State = 0
	if err := d.PutFileTransfer(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid state: %v", err)
	}
}

func TestTimerRoundTrip(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	conv := randomID(t)
	if _, err := d.GetTimer(ctx, conv); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unset timer: %v", err)
	}
	want := Timer{Conv: conv, Duration: 5 * time.Minute, SetAt: time.Unix(1_800_000_000, 0).UTC()}
	if err := d.PutTimer(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetTimer(ctx, conv)
	if err != nil || got.Duration != want.Duration || !got.SetAt.Equal(want.SetAt) {
		t.Fatalf("GetTimer = %+v, %v", got, err)
	}
	if err := d.PutTimer(ctx, Timer{Conv: conv, Duration: -1}); !errors.Is(err, ErrInvalid) {
		t.Errorf("negative timer: %v", err)
	}
}

func TestDeleteExpiredMessages(t *testing.T) {
	ctx := context.Background()
	d, path, _ := openTemp(t)
	now := time.Now()
	peer := randomID(t)
	expired := sampleMessage(t, peer, "secret that disappears")
	expired.Expires = now.Add(-time.Minute)
	kept := sampleMessage(t, peer, "not yet")
	kept.Expires = now.Add(time.Hour)
	forever := sampleMessage(t, peer, "forever")
	for _, m := range []Message{expired, kept, forever} {
		if err := d.AppendMessage(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	gid, sender := randomID(t), randomID(t)
	gm := sampleGroupMessage(t, gid, sender, "group secret that disappears")
	gm.Expires = now.Add(-time.Second)
	if err := d.AppendGroupMessage(ctx, gm); err != nil {
		t.Fatal(err)
	}
	stored, err := d.Messages(ctx, peer, 10, 0)
	if err != nil || len(stored) != 3 || !stored[0].Expires.Equal(expired.Expires.UTC()) {
		t.Fatalf("stored messages = %+v, %v", stored, err)
	}

	var sealed []byte
	if err := d.conn.QueryRow(`SELECT value FROM messages WHERE lookup = ?`, d.keys.messageLookup(peer, expired.MsgID)).Scan(&sealed); err != nil {
		t.Fatal(err)
	}

	gone, err := d.DeleteExpiredMessages(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 2 {
		t.Fatalf("deleted %d messages, want 2: %+v", len(gone), gone)
	}
	for _, e := range gone {
		switch {
		case !e.Group && e.Conv == peer && e.MsgID == expired.MsgID:
		case e.Group && e.Conv == gid && e.Sender == sender && e.MsgID == gm.MsgID:
		default:
			t.Errorf("unexpected deletion %+v", e)
		}
	}
	left, err := d.Messages(ctx, peer, 10, 0)
	if err != nil || len(left) != 2 || left[0].Body != "not yet" || left[1].Body != "forever" {
		t.Fatalf("messages left = %+v, %v", left, err)
	}
	if g, err := d.GroupMessages(ctx, gid, 10, 0); err != nil || len(g) != 0 {
		t.Fatalf("group messages left = %+v, %v", g, err)
	}
	if err := d.AppendMessage(ctx, expired); !errors.Is(err, ErrDuplicate) {
		t.Errorf("replaying a deleted message: %v", err)
	}
	if again, err := d.DeleteExpiredMessages(ctx, now); err != nil || len(again) != 0 {
		t.Errorf("second sweep = %+v, %v", again, err)
	}
	if later, err := d.DeleteExpiredMessages(ctx, now.Add(2*time.Hour)); err != nil || len(later) != 1 || later[0].MsgID != kept.MsgID {
		t.Errorf("later sweep = %+v, %v", later, err)
	}
	if found := filesContain(t, path, sealed[:40]); len(found) > 0 {
		t.Errorf("the deleted row is still in %v", found)
	}
}

func TestExpiresColumnRoundsUp(t *testing.T) {
	if got := expiresColumn(time.Time{}); got != 0 {
		t.Errorf("zero time: %d", got)
	}
	at := time.Unix(100, 1)
	if got := expiresColumn(at); got != 101 {
		t.Errorf("expiresColumn(100.000000001) = %d, want 101", got)
	}
	if got := expiresColumn(time.Unix(100, 0)); got != 100 {
		t.Errorf("expiresColumn(100) = %d, want 100", got)
	}
}
