package serverdb

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestDB(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "qchat.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func testID(b byte) [32]byte {
	var id [32]byte
	for i := range id {
		id[i] = b
	}
	return id
}

func countMigrations(t *testing.T, path string) int {
	t.Helper()
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var n int
	if err := conn.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOpenAppliesMigrationsOnce(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "qchat.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutIdentity(ctx, testID(1), []byte("bundle"), 1); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		db, err = Open(path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		bundle, serial, err := db.GetBundle(ctx, testID(1))
		if err != nil || string(bundle) != "bundle" || serial != 1 {
			t.Fatalf("after reopen GetBundle = %q, %d, %v", bundle, serial, err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := countMigrations(t, path); got != len(migrations) {
		t.Fatalf("schema_migrations has %d rows, want %d", got, len(migrations))
	}
}

func TestOpenSetsPragmas(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	conn, err := db.sql.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for pragma, want := range map[string]string{
		"journal_mode":  "wal",
		"foreign_keys":  "1",
		"secure_delete": "1",
		"busy_timeout":  "5000",
		"synchronous":   "2",
	} {
		var got string
		if err := conn.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil {
			t.Fatalf("PRAGMA %s: %v", pragma, err)
		}
		if got != want {
			t.Errorf("PRAGMA %s = %q, want %q", pragma, got, want)
		}
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	_, path := openTestDB(t)
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec("INSERT INTO schema_migrations (version) VALUES (?)", len(migrations)+5); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if db, err := Open(path); !errors.Is(err, ErrSchemaTooNew) {
		if db != nil {
			_ = db.Close()
		}
		t.Fatalf("Open of newer schema: %v, want ErrSchemaTooNew", err)
	}
}

func TestOpenRejectsBadPaths(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{"", filepath.Join(dir, "a?mode=ro"), filepath.Join(dir, "a#b"), dir} {
		if db, err := Open(path); err == nil {
			_ = db.Close()
			t.Errorf("Open(%q) succeeded", path)
		}
	}
	if db, err := Open(filepath.Join(dir, "missing", "qchat.db")); err == nil {
		_ = db.Close()
		t.Error("Open in a missing directory succeeded")
	}
}

func TestOpenRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symbolic link: %v", err)
	}
	if db, err := Open(link); err == nil {
		_ = db.Close()
		t.Fatal("Open through a symbolic link succeeded")
	}
}

func TestCloseLeavesNoWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qchat.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateInvite(context.Background(), time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path + "-wal"); err == nil && info.Size() != 0 {
		t.Fatalf("-wal file has %d bytes after Close", info.Size())
	}
}

func TestConcurrentOpenOfNewDatabase(t *testing.T) {
	const openers = 8
	for round := range 10 {
		path := filepath.Join(t.TempDir(), "qchat.db")
		start := make(chan struct{})
		results := make(chan error, openers)
		for range openers {
			go func() {
				<-start
				db, err := Open(path)
				if err == nil {
					err = db.Close()
				}
				results <- err
			}()
		}
		close(start)
		for range openers {
			if err := <-results; err != nil {
				t.Fatalf("round %d: concurrent Open: %v", round, err)
			}
		}
		if n := countMigrations(t, path); n != len(migrations) {
			t.Fatalf("round %d: %d migrations recorded, want %d", round, n, len(migrations))
		}
	}
}

// TestMigrateQueueToSharedPayloads opens a schema version 2 database with
// stored messages and checks that migration 3 keeps every message, its
// queue ID and the queue ID sequence, and moves each payload into
// queue_payloads.
func TestMigrateQueueToSharedPayloads(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "qchat.db")
	alice, bob, carol := testID(1), testID(2), testID(3)
	expires := time.Unix(1_700_003_600, 0).Unix()

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		"CREATE TABLE schema_migrations (version INTEGER NOT NULL PRIMARY KEY) STRICT",
		migrations[0],
		migrations[1],
		"INSERT INTO schema_migrations (version) VALUES (1), (2)",
	}
	for _, stmt := range statements {
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatalf("build version 2 schema: %v", err)
		}
	}
	for _, id := range [][32]byte{bob, carol} {
		if _, err := conn.Exec("INSERT INTO identities (id, bundle, serial) VALUES (?, ?, 1)", id[:], []byte("bundle")); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		recipient [32]byte
		payload   string
	}{{bob, "first"}, {carol, "second"}, {bob, "third"}, {carol, "acked"}} {
		if _, err := conn.Exec("INSERT INTO queue (recipient, sender, payload, size, expires) VALUES (?, ?, ?, ?, ?)",
			row.recipient[:], alice[:], []byte(row.payload), len(row.payload), expires); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec("DELETE FROM queue WHERE qid = 4"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open version 2 database: %v", err)
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
	if len(msgs) != 2 || msgs[0].QID != 1 || msgs[1].QID != 3 || string(msgs[0].Payload) != "first" ||
		string(msgs[1].Payload) != "third" || msgs[0].Sender != alice {
		t.Fatalf("bob's messages after migration: %+v", msgs)
	}
	if msgs, _ := db.QueuedFor(ctx, carol, 0, 10, now); len(msgs) != 1 || msgs[0].QID != 2 || string(msgs[0].Payload) != "second" {
		t.Fatalf("carol's messages after migration: %+v", msgs)
	}
	if rows, size, refs := payloadStats(t, db); rows != 3 || size != int64(len("first")+len("second")+len("third")) || refs != 3 {
		t.Fatalf("payloads after migration: %d rows, %d bytes, %d references", rows, size, refs)
	}
	var legacy int
	if err := db.sql.QueryRow("SELECT count(*) FROM sqlite_master WHERE name IN ('queue_v3') OR sql LIKE '%queue_v3%'").Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	if legacy != 0 {
		t.Fatalf("%d schema objects still mention the temporary table", legacy)
	}

	if err := db.Ack(ctx, bob, 1); err != nil {
		t.Fatal(err)
	}
	if rows, _, _ := payloadStats(t, db); rows != 2 {
		t.Fatalf("%d payloads after acknowledging a migrated message, want 2", rows)
	}
	next, err := db.Enqueue(ctx, bob, alice, []byte("new"), now, now.Add(time.Hour), QueueLimits{MaxMessages: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if next != 5 {
		t.Fatalf("first queue ID after migration %d, want 5 (IDs are never reused)", next)
	}
	outcomes, err := db.EnqueueMulti(ctx, [][32]byte{bob, carol}, alice, []byte("group"), now, now.Add(time.Hour), QueueLimits{MaxMessages: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if qids := qidsOf(t, outcomes); qids[0] != 6 || qids[1] != 7 {
		t.Fatalf("queue IDs %v, want [6 7]", qids)
	}
}

// TestMigrateEmptyQueueKeepsSequence checks that migration 3 keeps the
// queue ID sequence even when every message was already deleted.
func TestMigrateEmptyQueueKeepsSequence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "qchat.db")
	alice, bob := testID(1), testID(2)
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		"CREATE TABLE schema_migrations (version INTEGER NOT NULL PRIMARY KEY) STRICT",
		migrations[0],
		migrations[1],
		"INSERT INTO schema_migrations (version) VALUES (1), (2)",
		"INSERT INTO identities (id, bundle, serial) VALUES (x'" + strings.Repeat("02", 32) + "', x'01', 1)",
		"INSERT INTO queue (recipient, sender, payload, size, expires) VALUES (x'" + strings.Repeat("02", 32) + "', x'" + strings.Repeat("01", 32) + "', x'01', 1, 0)",
		"UPDATE sqlite_sequence SET seq = 41 WHERE name = 'queue'",
		"DELETE FROM queue",
	}
	for _, stmt := range statements {
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatalf("build version 2 database: %v", err)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Unix(1_700_000_000, 0)
	qid, err := db.Enqueue(ctx, bob, alice, []byte("x"), now, now.Add(time.Hour), QueueLimits{MaxMessages: 1, MaxBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if qid != 42 {
		t.Fatalf("queue ID %d after migrating an emptied queue, want 42", qid)
	}
}
