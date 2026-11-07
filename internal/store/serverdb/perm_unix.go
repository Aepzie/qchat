//go:build !windows

package serverdb

import (
	"errors"
	"io/fs"
	"os"
)

// dbFileMode is the mode of the database file. SQLite creates the -wal and
// -shm files with the mode of the main file.
const dbFileMode fs.FileMode = 0o600

// restrictFile creates path with mode 0600 if it does not exist, and removes
// any group or other permission bits from an existing file, before SQLite
// opens it. An empty file is a valid empty SQLite database.
func restrictFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, dbFileMode)
	if err == nil {
		return f.Close()
	}
	if !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&^dbFileMode == 0 {
		return nil
	}
	return os.Chmod(path, dbFileMode)
}
