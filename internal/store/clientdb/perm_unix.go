//go:build !windows

package clientdb

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// prepareFile creates the database file with mode 0600 if it does not exist
// and create is set, and tightens the mode of an existing file and its WAL
// companions, so that SQLite never creates them with a wider mode. Without
// create, a missing file is reported as ErrMissing.
func prepareFile(path string, create bool) error {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if !create && errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrMissing, path)
	}
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
