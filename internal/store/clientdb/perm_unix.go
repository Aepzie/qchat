//go:build !windows

package clientdb

import (
	"fmt"
	"os"
)

// prepareFile creates the database file with mode 0600 if it does not exist
// and tightens the mode of an existing file and its WAL companions, so that
// SQLite never creates them with a wider mode.
func prepareFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("clientdb: create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("clientdb: create database file: %w", err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clientdb: restrict database file mode: %w", err)
		}
	}
	return nil
}
