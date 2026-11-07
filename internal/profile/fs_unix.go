//go:build unix

package profile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// makePrivateDir creates dir with mode 0700. An existing directory is
// accepted only if it is a real directory (not a symbolic link, whose
// target its creator controls) owned by the current user; its mode is then
// tightened to 0700. A directory owned by somebody else is refused because
// its owner could change its permissions or swap the files inside at any
// time.
func makePrivateDir(dir string) error {
	if parent := filepath.Dir(dir); parent != dir {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return fmt.Errorf("profile: creating parent directory: %w", err)
		}
	}
	err := os.Mkdir(dir, 0o700)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("profile: creating directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("profile: %s is not a directory (symbolic links are refused)", dir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("profile: %s is owned by another user", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("profile: restricting permissions of %s: %w", dir, err)
	}
	return nil
}

// syncDir flushes the directory entry of a just-renamed file to disk, so a
// crash right after an atomic replace cannot bring back the old file.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
