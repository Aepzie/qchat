package serverdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// stored returns the stored form of key.
func stored(key AccessKey) StoredAccessKey {
	return StoredAccessKey{VerifierHash: sha256.Sum256(key.Verifier[:]), AllowUnidentified: key.AllowUnidentified}
}

func TestAccessKeys(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice, stranger := testID(1), testID(9)
	registerTestIdentity(t, db, alice)

	first := AccessKey{Verifier: testID(0x41)}
	if err := db.SetAccessKey(ctx, stranger, first); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetAccessKey(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := db.GetAccessKey(ctx, stranger); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAccessKey(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := db.GetAccessKey(ctx, alice); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAccessKey(no key) = %v, want ErrNotFound", err)
	}
	if err := db.SetAccessKey(ctx, alice, first); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetAccessKey(ctx, alice)
	if err != nil || got != stored(first) {
		t.Fatalf("GetAccessKey = %+v, %v; want %+v", got, err, stored(first))
	}
	if !got.Matches(first.Verifier[:]) || got.Matches(got.VerifierHash[:]) || got.Matches(first.Verifier[:31]) {
		t.Fatal("Matches accepts the wrong proofs")
	}
	var raw []byte
	if err := db.sql.QueryRow("SELECT verifier_hash FROM access_keys WHERE id = ?", alice[:]).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, first.Verifier[:]) {
		t.Fatal("the verifier itself is stored")
	}
	second := AccessKey{Verifier: testID(0x42), AllowUnidentified: true}
	if err := db.SetAccessKey(ctx, alice, second); err != nil {
		t.Fatal(err)
	}
	if got, err := db.GetAccessKey(ctx, alice); err != nil || got != stored(second) || got.Matches(first.Verifier[:]) {
		t.Fatalf("GetAccessKey after replace = %+v, %v; want %+v", got, err, stored(second))
	}
	if err := db.SetAccessKey(ctx, alice, AccessKey{AllowUnidentified: true}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("SetAccessKey(zero verifier) = %v, want ErrInvalidArgument", err)
	}
	var rows int
	if err := db.sql.QueryRow("SELECT count(*) FROM access_keys").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("access_keys has %d rows (%v), want 1", rows, err)
	}
	if _, err := db.sql.Exec("DELETE FROM identities WHERE id = ?", alice[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetAccessKey(ctx, alice); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAccessKey after deleting the identity = %v, want ErrNotFound", err)
	}
}

func TestAccessKeyColumnChecks(t *testing.T) {
	db, _ := openTestDB(t)
	alice := testID(1)
	registerTestIdentity(t, db, alice)
	for name, stmt := range map[string]string{
		"ShortVerifier": "INSERT INTO access_keys (id, verifier_hash, allow_unidentified) VALUES (?, x'01', 0)",
		"BadFlag":       "INSERT INTO access_keys (id, verifier_hash, allow_unidentified) VALUES (?, zeroblob(32), 2)",
	} {
		if _, err := db.sql.Exec(stmt, alice[:]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// senderColumn returns the raw sender column of the queue row qid.
func senderColumn(t *testing.T, db *DB, qid uint64) []byte {
	t.Helper()
	var sender []byte
	if err := db.sql.QueryRow("SELECT sender FROM queue WHERE qid = ?", int64(qid)).Scan(&sender); err != nil {
		t.Fatal(err)
	}
	return sender
}

func TestEnqueueSealed(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice, bob, carol, stranger := testID(1), testID(2), testID(3), testID(9)
	registerTestIdentity(t, db, bob)
	registerTestIdentity(t, db, carol)
	now := time.Unix(1_700_000_000, 0)

	identified := mustEnqueue(t, db, bob, alice, "identified", now, time.Hour)
	sealed, err := db.EnqueueSealed(ctx, bob, []byte("sealed"), now, now.Add(time.Hour), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	if sealed <= identified {
		t.Fatalf("sealed queue ID %d not after %d", sealed, identified)
	}
	if got := senderColumn(t, db, sealed); got != nil {
		t.Fatalf("sealed row stores sender %x, want NULL", got)
	}
	if got := senderColumn(t, db, identified); len(got) != 32 {
		t.Fatalf("identified row stores sender %x", got)
	}
	if _, err := db.EnqueueSealed(ctx, stranger, []byte("x"), now, now.Add(time.Hour), testLimits); !errors.Is(err, ErrNotFound) {
		t.Fatalf("EnqueueSealed(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := db.EnqueueSealed(ctx, bob, nil, now, now.Add(time.Hour), testLimits); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("EnqueueSealed(empty) = %v, want ErrInvalidArgument", err)
	}

	msgs, err := db.QueuedFor(ctx, bob, 0, 10, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].Sealed || msgs[0].Sender != alice || !msgs[1].Sealed || msgs[1].Sender != ([32]byte{}) ||
		string(msgs[1].Payload) != "sealed" {
		t.Fatalf("QueuedFor = %+v", msgs)
	}

	outcomes, err := db.EnqueueSealedMulti(ctx, [][32]byte{bob, stranger, carol}, []byte("group"), now, now.Add(time.Hour), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	if outcomes[0].Err != nil || !errors.Is(outcomes[1].Err, ErrNotFound) || outcomes[2].Err != nil {
		t.Fatalf("EnqueueSealedMulti outcomes %+v", outcomes)
	}
	for _, i := range []int{0, 2} {
		if got := senderColumn(t, db, outcomes[i].QID); got != nil {
			t.Fatalf("sealed multi row %d stores sender %x", i, got)
		}
	}
	if rows, _, refs := payloadStats(t, db); rows != 3 || refs != 4 {
		t.Fatalf("payloads: %d rows, %d references; want 3 and 4", rows, refs)
	}
	carolMsgs, err := db.QueuedFor(ctx, carol, 0, 10, now)
	if err != nil || len(carolMsgs) != 1 || !carolMsgs[0].Sealed {
		t.Fatalf("carol's messages %+v, %v", carolMsgs, err)
	}
	for _, step := range []struct {
		who [32]byte
		qid uint64
	}{{bob, sealed}, {bob, outcomes[0].QID}, {carol, outcomes[2].QID}} {
		if err := db.Ack(ctx, step.who, step.qid); err != nil {
			t.Fatal(err)
		}
	}
	if rows, _, refs := payloadStats(t, db); rows != 1 || refs != 1 {
		t.Fatalf("payloads after acks: %d rows, %d references; want 1 and 1", rows, refs)
	}
	if _, err := db.EnqueueSealedMulti(ctx, [][32]byte{bob, bob}, []byte("x"), now, now.Add(time.Hour), testLimits); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("EnqueueSealedMulti(duplicate) = %v", err)
	}
}

func TestSealedQueueCap(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice, bob := testID(1), testID(2)
	registerTestIdentity(t, db, bob)
	now := time.Unix(1_700_000_000, 0)
	limits := QueueLimits{MaxMessages: 4, MaxBytes: 1 << 20, MaxSealedMessages: 2, MaxSealedBytes: 1 << 20}
	for i := range 2 {
		if _, err := db.EnqueueSealed(ctx, bob, []byte("junk"), now, now.Add(time.Hour), limits); err != nil {
			t.Fatalf("sealed %d: %v", i, err)
		}
	}
	if _, err := db.EnqueueSealed(ctx, bob, []byte("junk"), now, now.Add(time.Hour), limits); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("sealed above the sealed cap = %v, want ErrQueueFull", err)
	}
	outcomes, err := db.EnqueueSealedMulti(ctx, [][32]byte{bob}, []byte("junk"), now, now.Add(time.Hour), limits)
	if err != nil || !errors.Is(outcomes[0].Err, ErrQueueFull) {
		t.Fatalf("sealed multi above the sealed cap = %+v, %v", outcomes, err)
	}
	for i := range 2 {
		if _, err := db.Enqueue(ctx, bob, alice, []byte("identified"), now, now.Add(time.Hour), limits); err != nil {
			t.Fatalf("identified %d next to sealed junk: %v", i, err)
		}
	}
	if _, err := db.Enqueue(ctx, bob, alice, []byte("identified"), now, now.Add(time.Hour), limits); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("identified above MaxMessages = %v, want ErrQueueFull", err)
	}
	later := now.Add(2 * time.Hour)
	if _, err := db.EnqueueSealed(ctx, bob, []byte("fresh"), later, later.Add(time.Hour), limits); err != nil {
		t.Fatalf("sealed after the junk expired: %v", err)
	}

	carol := testID(3)
	registerTestIdentity(t, db, carol)
	bytesCap := QueueLimits{MaxMessages: 100, MaxBytes: 1 << 20, MaxSealedBytes: 10}
	if _, err := db.EnqueueSealed(ctx, carol, bytes.Repeat([]byte{1}, 6), now, now.Add(time.Hour), bytesCap); err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnqueueSealed(ctx, carol, bytes.Repeat([]byte{1}, 6), now, now.Add(time.Hour), bytesCap); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("sealed above MaxSealedBytes = %v, want ErrQueueFull", err)
	}
	if _, err := db.Enqueue(ctx, carol, alice, bytes.Repeat([]byte{1}, 6), now, now.Add(time.Hour), bytesCap); err != nil {
		t.Fatalf("identified next to sealed bytes: %v", err)
	}
	if _, err := db.EnqueueSealed(ctx, carol, []byte("x"), now, now.Add(time.Hour), QueueLimits{MaxMessages: 1, MaxBytes: 1, MaxSealedMessages: -1}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("negative sealed cap = %v, want ErrInvalidArgument", err)
	}
}

// TestMigrateHashesVerifiers opens a schema version 4 database holding a
// plain verifier and a zero verifier and checks that migration 5 hashes
// the first in place and drops the second.
func TestMigrateHashesVerifiers(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "qchat.db")
	alice, bob := testID(1), testID(2)
	verifier := testID(0x41)

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		"PRAGMA foreign_keys = ON",
		"CREATE TABLE schema_migrations (version INTEGER NOT NULL PRIMARY KEY) STRICT",
		migrations[0],
		migrations[1],
		migrations[2],
		migrations[3],
		"INSERT INTO schema_migrations (version) VALUES (1), (2), (3), (4)",
	}
	for _, stmt := range statements {
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatalf("build version 4 schema: %v", err)
		}
	}
	for _, id := range [][32]byte{alice, bob} {
		if _, err := conn.Exec("INSERT INTO identities (id, bundle, serial) VALUES (?, x'01', 1)", id[:]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec("INSERT INTO access_keys (id, verifier, allow_unidentified) VALUES (?, ?, 1)", alice[:], verifier[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec("INSERT INTO access_keys (id, verifier, allow_unidentified) VALUES (?, zeroblob(32), 0)", bob[:]); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open version 4 database: %v", err)
	}
	defer db.Close()
	if got := countMigrations(t, path); got != len(migrations) {
		t.Fatalf("schema_migrations has %d rows, want %d", got, len(migrations))
	}
	key, err := db.GetAccessKey(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if key != stored(AccessKey{Verifier: verifier, AllowUnidentified: true}) || !key.Matches(verifier[:]) {
		t.Fatalf("migrated access key %+v", key)
	}
	if _, err := db.GetAccessKey(ctx, bob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("zero verifier after migration: %v, want ErrNotFound", err)
	}
}

func TestSenderColumnChecks(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	bob := testID(2)
	registerTestIdentity(t, db, bob)
	now := time.Unix(1_700_000_000, 0)
	qid, err := db.EnqueueSealed(ctx, bob, []byte("x"), now, now.Add(time.Hour), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec("UPDATE queue SET sender = x'0102' WHERE qid = ?", int64(qid)); err == nil {
		t.Fatal("short sender accepted")
	}
}

// TestMigrateQueueToNullableSender opens a schema version 3 database with
// stored messages and checks that migration 4 keeps every message, its
// sender and queue ID, the queue ID sequence and the payload trigger.
func TestMigrateQueueToNullableSender(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "qchat.db")
	alice, bob := testID(1), testID(2)
	expires := time.Unix(1_700_003_600, 0).Unix()

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		"PRAGMA foreign_keys = ON",
		"CREATE TABLE schema_migrations (version INTEGER NOT NULL PRIMARY KEY) STRICT",
		migrations[0],
		migrations[1],
		migrations[2],
		"INSERT INTO schema_migrations (version) VALUES (1), (2), (3)",
	}
	for _, stmt := range statements {
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatalf("build version 3 schema: %v", err)
		}
	}
	if _, err := conn.Exec("INSERT INTO identities (id, bundle, serial) VALUES (?, x'01', 1)", bob[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec("INSERT INTO queue_payloads (pid, payload, size, refs) VALUES (1, x'aa', 1, 3)"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := conn.Exec("INSERT INTO queue (recipient, sender, pid, size, expires) VALUES (?, ?, 1, 1, ?)", bob[:], alice[:], expires); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec("DELETE FROM queue WHERE qid = 3"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open version 3 database: %v", err)
	}
	defer db.Close()
	if got := countMigrations(t, path); got != len(migrations) {
		t.Fatalf("schema_migrations has %d rows, want %d", got, len(migrations))
	}
	now := time.Unix(1_700_000_000, 0)
	msgs, err := db.QueuedFor(ctx, bob, 0, 10, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].QID != 1 || msgs[1].QID != 2 || msgs[0].Sender != alice || msgs[0].Sealed || string(msgs[1].Payload) != "\xaa" {
		t.Fatalf("messages after migration: %+v", msgs)
	}
	var legacy int
	if err := db.sql.QueryRow("SELECT count(*) FROM sqlite_master WHERE name = 'queue_v4' OR sql LIKE '%queue_v4%'").Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	if legacy != 0 {
		t.Fatalf("%d schema objects still mention the temporary table", legacy)
	}
	var triggers int
	if err := db.sql.QueryRow("SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'queue'").Scan(&triggers); err != nil || triggers != 1 {
		t.Fatalf("%d triggers on queue (%v), want 1", triggers, err)
	}
	for _, qid := range []uint64{1, 2} {
		if err := db.Ack(ctx, bob, qid); err != nil {
			t.Fatal(err)
		}
	}
	if rows, _, _ := payloadStats(t, db); rows != 0 {
		t.Fatalf("%d payloads after acknowledging every migrated message, want 0", rows)
	}
	next, err := db.EnqueueSealed(ctx, bob, []byte("sealed"), now, now.Add(time.Hour), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	if next != 4 {
		t.Fatalf("first queue ID after migration %d, want 4 (IDs are never reused)", next)
	}
}
