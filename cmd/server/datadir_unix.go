//go:build unix

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// fileProtection describes how init protects the files it writes. On
// Unix-like systems the permission bits suffice: every file is created
// with mode 0600 inside a directory with mode 0700.
type fileProtection struct{}

// prepareDataDir creates dir with mode 0700, or verifies that an existing
// dir is safe to hold the key: it must be owned by the current user and
// not writable by group or others. Group or other read access produces a
// warning on stderr only, since the files themselves are created with mode
// 0600.
func prepareDataDir(dir, serviceAccount string, stderr io.Writer) (*fileProtection, error) {
	if serviceAccount != "" {
		return nil, errors.New("--service-account is only supported on Windows; run init as the account that runs the server instead")
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := os.MkdirAll(parent, dataDirMode); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
	}
	err := os.Mkdir(dir, dataDirMode)
	if err == nil {
		return &fileProtection{}, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	if err := checkExistingDataDir(dir, stderr); err != nil {
		return nil, err
	}
	return &fileProtection{}, nil
}

// checkExistingDataDir refuses a directory that init did not just create
// unless it is owned by the current user and not writable by group or
// others; anyone who can write to the directory can replace the key. A
// symbolic link is refused as well, because its owner can retarget it.
func checkExistingDataDir(dir string, stderr io.Writer) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("data directory %s is a symbolic link; pass the real directory instead", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("data directory %s exists and is not a directory", dir)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("data directory %s: cannot determine its owner", dir)
	}
	if uid := os.Geteuid(); int(stat.Uid) != uid {
		return fmt.Errorf("data directory %s is owned by uid %d, not by the current user (uid %d); run init as the owner, or choose a directory that does not exist yet", dir, stat.Uid, uid)
	}
	perm := info.Mode().Perm()
	if perm&0o022 != 0 {
		return fmt.Errorf("data directory %s is writable by other users (mode %04o), who could replace the key; run chmod 700 %s first", dir, perm, dir)
	}
	if perm&0o077 != 0 {
		fmt.Fprintf(stderr, "%s: warning: %s is accessible to other users (mode %04o); consider chmod 700\n", programName, dir, perm)
	}
	return nil
}

// createTemp creates a new file in dir whose name starts with prefix and
// that only the current user can read and write.
func (*fileProtection) createTemp(dir, prefix string) (*os.File, error) {
	tmp, err := os.CreateTemp(dir, prefix+"*")
	if err != nil {
		return nil, err
	}
	if err := tmp.Chmod(dataFileMode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, err
	}
	return tmp, nil
}

// keyFileExposure describes how the private key at path is accessible to
// other users, or returns "" if it is not.
func keyFileExposure(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Sprintf("mode %04o allows group or other access", perm), nil
	}
	return "", nil
}

// createIfMissing creates an empty file at path that only the current user
// can read and write, and leaves an existing file unchanged.
func (*fileProtection) createIfMissing(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, dataFileMode)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return f.Close()
}
