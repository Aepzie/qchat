//go:build unix

package serverdb

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestDatabaseFilesAreOwnerOnly(t *testing.T) {
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })

	db, path := openTestDB(t)
	if _, err := db.CreateInvite(context.Background(), time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(name), err)
		}
		if perm := info.Mode().Perm(); perm != dbFileMode {
			t.Errorf("%s has mode %04o, want %04o", filepath.Base(name), perm, dbFileMode)
		}
	}
}

func TestOpenTightensExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qchat.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != dbFileMode {
		t.Fatalf("existing file has mode %04o after Open, want %04o", perm, dbFileMode)
	}
}
