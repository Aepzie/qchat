package clientdb

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func sampleSession(t *testing.T, peer [32]byte) Session {
	t.Helper()
	now := time.Now()
	return Session{
		Peer:        peer,
		State:       randomBytes(t, 300),
		Initiator:   true,
		PendingInit: randomBytes(t, 50),
		Created:     now.Add(-time.Minute),
		Updated:     now,
	}
}

func samplePrekey(t *testing.T, kind PrekeyKind, keyID uint32, created time.Time) PrekeySecret {
	t.Helper()
	return PrekeySecret{
		Kind:    kind,
		KeyID:   keyID,
		Private: randomBytes(t, 64),
		Public:  randomBytes(t, 40),
		Created: created,
	}
}

func equalSession(a, b Session) bool {
	return a.Peer == b.Peer && bytes.Equal(a.State, b.State) && a.Initiator == b.Initiator &&
		a.Confirmed == b.Confirmed && bytes.Equal(a.PendingInit, b.PendingInit) &&
		a.Created.Equal(b.Created) && a.Updated.Equal(b.Updated)
}

func equalPrekey(a, b PrekeySecret) bool {
	return a.Kind == b.Kind && a.KeyID == b.KeyID && bytes.Equal(a.Private, b.Private) &&
		bytes.Equal(a.Public, b.Public) && a.Created.Equal(b.Created) &&
		a.RetireAt.Equal(b.RetireAt) && a.Uploaded == b.Uploaded
}

func TestSessionRoundTrip(t *testing.T) {
	ctx := context.Background()
	d, path, key := openTemp(t)
	peer := randomID(t)
	if _, err := d.GetSession(ctx, peer); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing session: got %v, want ErrNotFound", err)
	}
	s := sampleSession(t, peer)
	if err := d.PutSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetSession(ctx, peer)
	if err != nil || !equalSession(got, s) {
		t.Fatalf("GetSession = %+v, %v; want %+v", got, err, s)
	}

	s.State = randomBytes(t, 500)
	s.Confirmed = true
	s.PendingInit = nil
	if err := d.PutSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = OpenExisting(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	got, err = d.GetSession(ctx, peer)
	if err != nil || !equalSession(got, s) || got.PendingInit != nil {
		t.Fatalf("updated session after reopen = %+v, %v; want %+v", got, err, s)
	}

	if err := d.DeleteSession(ctx, peer); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetSession(ctx, peer); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session: got %v, want ErrNotFound", err)
	}
	if err := d.DeleteSession(ctx, peer); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting again: got %v, want ErrNotFound", err)
	}
	if err := d.PutSession(ctx, Session{Peer: peer}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty state: got %v, want ErrInvalid", err)
	}
	if err := d.PutSession(ctx, Session{Peer: peer, State: make([]byte, MaxSessionStateSize+1)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized state: got %v, want ErrInvalid", err)
	}
}

func TestSessionRowSwapDetected(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	alice, bob := randomID(t), randomID(t)
	for _, peer := range [][32]byte{alice, bob} {
		if err := d.PutSession(ctx, sampleSession(t, peer)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := d.conn.Exec(`UPDATE sessions SET value = (SELECT value FROM sessions WHERE lookup = ?) WHERE lookup = ?`,
		d.keys.sessionLookup(alice), d.keys.sessionLookup(bob))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetSession(ctx, bob); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("swapped session row: got %v, want ErrCorrupt", err)
	}
}

func TestPrekeyRoundTrip(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	base := time.Now().Add(-time.Hour)
	signed := samplePrekey(t, PrekeySigned, 7, base)
	signed.RetireAt = base.Add(21 * 24 * time.Hour)
	signed.Uploaded = true
	oneTimes := []PrekeySecret{
		samplePrekey(t, PrekeyOneTime, 30, base.Add(2*time.Second)),
		samplePrekey(t, PrekeyOneTime, 20, base.Add(time.Second)),
		samplePrekey(t, PrekeyOneTime, 10, base.Add(time.Second)),
	}
	oneTimes[0].Public = nil
	for _, p := range append([]PrekeySecret{signed}, oneTimes...) {
		if err := d.PutPrekeySecret(ctx, p); err != nil {
			t.Fatal(err)
		}
	}

	got, err := d.GetPrekeySecret(ctx, PrekeySigned, 7)
	if err != nil || !equalPrekey(got, signed) {
		t.Fatalf("GetPrekeySecret = %+v, %v; want %+v", got, err, signed)
	}
	if _, err := d.GetPrekeySecret(ctx, PrekeyOneTime, 7); !errors.Is(err, ErrNotFound) {
		t.Fatalf("same ID, other kind: got %v, want ErrNotFound", err)
	}

	list, err := d.ListPrekeySecrets(ctx, PrekeyOneTime)
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []PrekeySecret{oneTimes[2], oneTimes[1], oneTimes[0]}
	if len(list) != len(wantOrder) {
		t.Fatalf("ListPrekeySecrets returned %d secrets, want %d", len(list), len(wantOrder))
	}
	for i := range wantOrder {
		if !equalPrekey(list[i], wantOrder[i]) {
			t.Errorf("list[%d] = key %d, want key %d", i, list[i].KeyID, wantOrder[i].KeyID)
		}
	}
	if list[2].Public != nil {
		t.Errorf("empty Public decoded as %v, want nil", list[2].Public)
	}
	signedList, err := d.ListPrekeySecrets(ctx, PrekeySigned)
	if err != nil || len(signedList) != 1 || !equalPrekey(signedList[0], signed) {
		t.Fatalf("signed list = %+v, %v", signedList, err)
	}

	signed.Uploaded = false
	signed.Private = randomBytes(t, 64)
	if err := d.PutPrekeySecret(ctx, signed); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetPrekeySecret(ctx, PrekeySigned, 7); err != nil || !equalPrekey(got, signed) {
		t.Fatalf("replaced secret = %+v, %v", got, err)
	}

	if err := d.DeletePrekeySecret(ctx, PrekeyOneTime, 20); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetPrekeySecret(ctx, PrekeyOneTime, 20); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted secret: got %v, want ErrNotFound", err)
	}
	if err := d.DeletePrekeySecret(ctx, PrekeyOneTime, 20); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting again: got %v, want ErrNotFound", err)
	}

	invalid := []struct {
		name string
		err  error
	}{
		{"put kind 0", d.PutPrekeySecret(ctx, PrekeySecret{Kind: 0, KeyID: 1, Private: []byte{1}})},
		{"put ID 0", d.PutPrekeySecret(ctx, PrekeySecret{Kind: PrekeySigned, Private: []byte{1}})},
		{"put empty private", d.PutPrekeySecret(ctx, PrekeySecret{Kind: PrekeySigned, KeyID: 1})},
		{"get kind 3", func() error { _, err := d.GetPrekeySecret(ctx, 3, 1); return err }()},
		{"delete ID 0", d.DeletePrekeySecret(ctx, PrekeyOneTime, 0)},
		{"list kind 0", func() error { _, err := d.ListPrekeySecrets(ctx, 0); return err }()},
	}
	for _, tc := range invalid {
		if !errors.Is(tc.err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", tc.name, tc.err)
		}
	}
}

func TestPruneRetiredPrekeys(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	now := time.Now()
	expired := samplePrekey(t, PrekeySigned, 1, now.Add(-30*24*time.Hour))
	expired.RetireAt = now.Add(-time.Hour)
	exact := samplePrekey(t, PrekeySigned, 2, now.Add(-20*24*time.Hour))
	exact.RetireAt = now
	future := samplePrekey(t, PrekeySigned, 3, now.Add(-time.Hour))
	future.RetireAt = now.Add(time.Hour)
	never := samplePrekey(t, PrekeySigned, 4, now)
	oneTime := samplePrekey(t, PrekeyOneTime, 5, now)
	for _, p := range []PrekeySecret{expired, exact, future, never, oneTime} {
		if err := d.PutPrekeySecret(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	n, err := d.PruneRetiredPrekeys(ctx, now)
	if err != nil || n != 2 {
		t.Fatalf("PruneRetiredPrekeys = %d, %v; want 2", n, err)
	}
	for _, id := range []uint32{1, 2} {
		if _, err := d.GetPrekeySecret(ctx, PrekeySigned, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("retired key %d: got %v, want ErrNotFound", id, err)
		}
	}
	for _, id := range []uint32{3, 4} {
		if _, err := d.GetPrekeySecret(ctx, PrekeySigned, id); err != nil {
			t.Errorf("kept key %d: %v", id, err)
		}
	}
	if _, err := d.GetPrekeySecret(ctx, PrekeyOneTime, 5); err != nil {
		t.Errorf("one-time key: %v", err)
	}
	if n, err := d.PruneRetiredPrekeys(ctx, now); err != nil || n != 0 {
		t.Fatalf("second prune = %d, %v; want 0", n, err)
	}
}

func TestCommitReceive(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	peer := randomID(t)
	opk := samplePrekey(t, PrekeyOneTime, 99, time.Now())
	other := samplePrekey(t, PrekeyOneTime, 100, time.Now())
	for _, p := range []PrekeySecret{opk, other} {
		if err := d.PutPrekeySecret(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	s := sampleSession(t, peer)
	m := sampleMessage(t, peer, "first")
	if err := d.CommitReceive(ctx, s, m, opk.KeyID); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetSession(ctx, peer); err != nil || !equalSession(got, s) {
		t.Fatalf("session after commit = %+v, %v", got, err)
	}
	if msgs, err := d.Messages(ctx, peer, 10, 0); err != nil || len(msgs) != 1 || !equalMessage(msgs[0], m) {
		t.Fatalf("messages after commit = %+v, %v", msgs, err)
	}
	if _, err := d.GetPrekeySecret(ctx, PrekeyOneTime, opk.KeyID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed prekey: got %v, want ErrNotFound", err)
	}

	s2 := sampleSession(t, peer)
	m2 := sampleMessage(t, peer, "second")
	if err := d.CommitReceive(ctx, s2, m2, 0); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.GetSession(ctx, peer); !equalSession(got, s2) {
		t.Fatal("session not updated by commit without prekey")
	}

	assertUnchanged := func(stage string, unwanted Message) {
		t.Helper()
		if got, err := d.GetSession(ctx, peer); err != nil || !equalSession(got, s2) {
			t.Errorf("%s: session changed: %+v, %v", stage, got, err)
		}
		if _, err := d.GetPrekeySecret(ctx, PrekeyOneTime, other.KeyID); err != nil {
			t.Errorf("%s: prekey deleted: %v", stage, err)
		}
		if seen, err := d.HasMessage(ctx, peer, unwanted.MsgID); err != nil || seen {
			t.Errorf("%s: message recorded: %v, %v", stage, seen, err)
		}
		if msgs, err := d.Messages(ctx, peer, 10, 0); err != nil || len(msgs) != 2 {
			t.Errorf("%s: %d messages, %v; want 2", stage, len(msgs), err)
		}
	}

	if err := d.CommitReceive(ctx, sampleSession(t, peer), m, other.KeyID); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: got %v, want ErrDuplicate", err)
	}
	assertUnchanged("duplicate", Message{})

	m3 := sampleMessage(t, peer, "unknown prekey")
	if err := d.CommitReceive(ctx, sampleSession(t, peer), m3, opk.KeyID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("already consumed prekey: got %v, want ErrNotFound", err)
	}
	assertUnchanged("unknown prekey", m3)

	if _, err := d.conn.Exec(`CREATE TRIGGER fail_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'forced failure'); END`); err != nil {
		t.Fatal(err)
	}
	m4 := sampleMessage(t, peer, "forced failure")
	if err := d.CommitReceive(ctx, sampleSession(t, peer), m4, other.KeyID); err == nil {
		t.Fatal("CommitReceive succeeded despite the failing session write")
	}
	assertUnchanged("forced failure", m4)
	if _, err := d.conn.Exec(`DROP TRIGGER fail_session`); err != nil {
		t.Fatal(err)
	}
	if err := d.CommitReceive(ctx, sampleSession(t, peer), m4, other.KeyID); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}

	stranger := sampleMessage(t, randomID(t), "wrong peer")
	if err := d.CommitReceive(ctx, s, stranger, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("peer mismatch: got %v, want ErrInvalid", err)
	}
	outgoing := sampleMessage(t, peer, "outgoing")
	outgoing.Dir = Outgoing
	if err := d.CommitReceive(ctx, s, outgoing, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("outgoing message: got %v, want ErrInvalid", err)
	}
}

func TestCommitSend(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	peer := randomID(t)
	s := sampleSession(t, peer)
	m := sampleMessage(t, peer, "hello")
	m.Dir = Outgoing
	m.Status = StatusSent
	if err := d.CommitSend(ctx, s, m); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetSession(ctx, peer); err != nil || !equalSession(got, s) {
		t.Fatalf("session after send = %+v, %v", got, err)
	}
	if msgs, err := d.Messages(ctx, peer, 10, 0); err != nil || len(msgs) != 1 || !equalMessage(msgs[0], m) {
		t.Fatalf("messages after send = %+v, %v", msgs, err)
	}
	if err := d.CommitSend(ctx, sampleSession(t, peer), m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate send: got %v, want ErrDuplicate", err)
	}
	if got, _ := d.GetSession(ctx, peer); !equalSession(got, s) {
		t.Fatal("session changed by duplicate send")
	}
	incoming := sampleMessage(t, peer, "incoming")
	if err := d.CommitSend(ctx, s, incoming); !errors.Is(err, ErrInvalid) {
		t.Errorf("incoming message: got %v, want ErrInvalid", err)
	}
}

func filesContain(t *testing.T, path string, needle []byte) []string {
	t.Helper()
	var found []string
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		raw, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, needle) {
			found = append(found, filepath.Base(p))
		}
	}
	return found
}

func sealedPrekeyRow(t *testing.T, d *DB, kind PrekeyKind, keyID uint32) []byte {
	t.Helper()
	var sealed []byte
	if err := d.conn.QueryRow(`SELECT value FROM prekeys WHERE lookup = ?`, d.keys.prekeyLookup(kind, keyID)).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestDeletedPrekeyLeavesNoTrace(t *testing.T) {
	ctx := context.Background()
	d, path, _ := openTemp(t)
	peer := randomID(t)
	if err := d.PutContact(ctx, sampleContact(t, "Filler")); err != nil {
		t.Fatal(err)
	}
	signed := samplePrekey(t, PrekeySigned, 1, time.Now())
	oneTime := samplePrekey(t, PrekeyOneTime, 2, time.Now())
	control := samplePrekey(t, PrekeyOneTime, 3, time.Now())
	for _, p := range []PrekeySecret{signed, oneTime, control} {
		if err := d.PutPrekeySecret(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	signedSealed := sealedPrekeyRow(t, d, PrekeySigned, signed.KeyID)
	oneTimeSealed := sealedPrekeyRow(t, d, PrekeyOneTime, oneTime.KeyID)
	controlSealed := sealedPrekeyRow(t, d, PrekeyOneTime, control.KeyID)
	if len(filesContain(t, path, signedSealed)) == 0 {
		t.Fatal("stored ciphertext not found in the files; the scan would prove nothing")
	}

	if _, err := d.conn.Exec(`DELETE FROM prekeys WHERE lookup = ?`, d.keys.prekeyLookup(PrekeyOneTime, control.KeyID)); err != nil {
		t.Fatal(err)
	}
	if found := filesContain(t, path, controlSealed); len(found) == 0 {
		t.Fatal("a delete without checkpoint left no trace; the scan would prove nothing")
	}
	d.checkpoint(ctx)

	if err := d.DeletePrekeySecret(ctx, PrekeySigned, signed.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := d.CommitReceive(ctx, sampleSession(t, peer), sampleMessage(t, peer, "uses opk"), oneTime.KeyID); err != nil {
		t.Fatal(err)
	}

	needles := map[string][]byte{
		"signed private key":      signed.Private,
		"signed row":              signedSealed,
		"one-time private key":    oneTime.Private,
		"one-time row":            oneTimeSealed,
		"control row":             controlSealed,
		"signed row nonce":        signedSealed[:24],
		"one-time row ciphertext": oneTimeSealed[24:],
	}
	for what, needle := range needles {
		if found := filesContain(t, path, needle); len(found) > 0 {
			t.Errorf("%s still present in %v after delete", what, found)
		}
	}
	if info, err := os.Stat(path + "-wal"); err == nil && info.Size() != 0 {
		t.Errorf("-wal file is %d bytes after checkpoint, want 0", info.Size())
	}
}

func TestMigrationFromV2(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "qchat.db")
	key := randomKey(t)

	all := migrations
	migrations = all[:2]
	v2, err := Open(path, key)
	migrations = all
	if err != nil {
		t.Fatal(err)
	}
	c := sampleContact(t, "Old Friend")
	m := sampleMessage(t, c.ID, "from schema 2")
	if err := v2.PutContact(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := v2.AppendMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	var tables int
	if err := v2.conn.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('sessions', 'prekeys')`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("v2 database has %d new tables, %v", tables, err)
	}
	if err := v2.Close(); err != nil {
		t.Fatal(err)
	}

	d, err := OpenExisting(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var version int
	if err := d.conn.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != 3 {
		t.Fatalf("schema version = %d, %v; want 3", version, err)
	}
	if got, err := d.GetContact(ctx, c.ID); err != nil || !equalContact(got, c) {
		t.Fatalf("contact after migration = %+v, %v", got, err)
	}
	if msgs, err := d.Messages(ctx, c.ID, 10, 0); err != nil || len(msgs) != 1 || !equalMessage(msgs[0], m) {
		t.Fatalf("messages after migration = %+v, %v", msgs, err)
	}
	if err := d.AppendMessage(ctx, m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay after migration: got %v, want ErrDuplicate", err)
	}
	s := sampleSession(t, c.ID)
	reply := sampleMessage(t, c.ID, "after migration")
	if err := d.CommitReceive(ctx, s, reply, 0); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetSession(ctx, c.ID); err != nil || !equalSession(got, s) {
		t.Fatalf("session after migration = %+v, %v", got, err)
	}
	p := samplePrekey(t, PrekeySigned, 5, time.Now())
	if err := d.PutPrekeySecret(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetPrekeySecret(ctx, PrekeySigned, 5); err != nil || !equalPrekey(got, p) {
		t.Fatalf("prekey after migration = %+v, %v", got, err)
	}
}
