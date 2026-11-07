package serverdb

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
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
