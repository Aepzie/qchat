package clientdb

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestMarkInitSeen(t *testing.T) {
	ctx := context.Background()
	d, path, key := openTemp(t)
	now := time.Unix(1_800_000_000, 0)
	var replay [32]byte
	copy(replay[:], randomBytes(t, 32))

	seen, err := d.MarkInitSeen(ctx, 7, replay, now.Add(time.Hour))
	if err != nil || seen {
		t.Fatalf("first mark: seen %v, %v", seen, err)
	}
	if seen, err := d.MarkInitSeen(ctx, 7, replay, now.Add(48*time.Hour)); err != nil || !seen {
		t.Fatalf("second mark: seen %v, %v", seen, err)
	}
	if seen, err := d.MarkInitSeen(ctx, 8, replay, now.Add(time.Hour)); err != nil || seen {
		t.Fatalf("same key under another signed prekey: seen %v, %v", seen, err)
	}

	var raw []byte
	if err := d.conn.QueryRow(`SELECT lookup FROM seen_inits LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != lookupSize || bytes.Contains(raw, replay[:8]) {
		t.Fatal("replay set stores more than an HMAC")
	}

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if d, err = OpenExisting(path, key); err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if seen, err := d.MarkInitSeen(ctx, 7, replay, now.Add(time.Hour)); err != nil || !seen {
		t.Fatalf("after reopen: seen %v, %v", seen, err)
	}

	if n, err := d.PruneSeenInits(ctx, now.Add(time.Hour-time.Second)); err != nil || n != 0 {
		t.Fatalf("prune before expiry: %d, %v", n, err)
	}
	if n, err := d.PruneSeenInits(ctx, now.Add(time.Hour)); err != nil || n != 2 {
		t.Fatalf("prune at expiry: %d, %v (the expiry must not have been extended)", n, err)
	}
	if seen, err := d.MarkInitSeen(ctx, 7, replay, now.Add(time.Hour+time.Nanosecond)); err != nil || seen {
		t.Fatalf("after prune: seen %v, %v", seen, err)
	}
	if n, err := d.PruneSeenInits(ctx, now.Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("sub-second expiry pruned early: %d, %v", n, err)
	}

	for name, call := range map[string]func() error{
		"zero spk":     func() error { _, err := d.MarkInitSeen(ctx, 0, replay, now); return err },
		"zero expires": func() error { _, err := d.MarkInitSeen(ctx, 1, replay, time.Time{}); return err },
		"epoch":        func() error { _, err := d.MarkInitSeen(ctx, 1, replay, time.Unix(0, 0)); return err },
	} {
		if err := call(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestCommitReceiveInit(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	peer := randomID(t)
	opk := samplePrekey(t, PrekeyOneTime, 99, time.Now())
	if err := d.PutPrekeySecret(ctx, opk); err != nil {
		t.Fatal(err)
	}
	init := SeenInit{SPKID: 5, Expires: time.Now().Add(time.Hour)}
	copy(init.Key[:], randomBytes(t, 32))

	s := sampleSession(t, peer)
	m := sampleMessage(t, peer, "first")
	if err := d.CommitReceiveInit(ctx, s, m, opk.KeyID, init); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetSession(ctx, peer); err != nil || !equalSession(got, s) {
		t.Fatalf("session after commit = %+v, %v", got, err)
	}
	if _, err := d.GetPrekeySecret(ctx, PrekeyOneTime, opk.KeyID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed prekey: got %v, want ErrNotFound", err)
	}
	if seen, err := d.MarkInitSeen(ctx, init.SPKID, init.Key, init.Expires); err != nil || !seen {
		t.Fatalf("init not recorded: seen %v, %v", seen, err)
	}

	replayed := sampleSession(t, peer)
	if err := d.CommitReceiveInit(ctx, replayed, sampleMessage(t, peer, "replayed"), 0, init); !errors.Is(err, ErrInitSeen) {
		t.Fatalf("replayed init: got %v, want ErrInitSeen", err)
	}
	if got, _ := d.GetSession(ctx, peer); !equalSession(got, s) {
		t.Fatal("replayed init replaced the session")
	}
	if msgs, err := d.Messages(ctx, peer, 10, 0); err != nil || len(msgs) != 1 {
		t.Fatalf("replayed init stored a message: %d, %v", len(msgs), err)
	}

	fresh := SeenInit{SPKID: 5, Expires: init.Expires}
	copy(fresh.Key[:], randomBytes(t, 32))
	if err := d.CommitReceiveInit(ctx, sampleSession(t, peer), m, 0, fresh); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate message: got %v, want ErrDuplicate", err)
	}
	if seen, err := d.MarkInitSeen(ctx, fresh.SPKID, fresh.Key, fresh.Expires); err != nil || seen {
		t.Fatalf("failed commit recorded its init: seen %v, %v", seen, err)
	}

	if err := d.CommitReceiveInit(ctx, s, m, 0, SeenInit{Key: init.Key, Expires: init.Expires}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero SPKID: got %v, want ErrInvalid", err)
	}
	out := sampleMessage(t, peer, "out")
	out.Dir = Outgoing
	if err := d.CommitReceiveInit(ctx, s, out, 0, fresh); !errors.Is(err, ErrInvalid) {
		t.Fatalf("outgoing message: got %v, want ErrInvalid", err)
	}
}
