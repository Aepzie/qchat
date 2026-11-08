//go:build unix

package main

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkOutDir refuses a build-client output directory that other users
// could use to swap binaries between building, hashing and publishing them:
// a symbolic link, a directory owned by another user, or one writable by
// group or others.
func checkOutDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("output directory %s is a symbolic link; pass the real directory instead", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("output directory %s exists and is not a directory", dir)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("output directory %s: cannot determine its owner", dir)
	}
	if uid := os.Geteuid(); int(stat.Uid) != uid {
		return fmt.Errorf("output directory %s is owned by uid %d, not by the current user (uid %d); choose a directory you own", dir, stat.Uid, uid)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("output directory %s is writable by other users (mode %04o), who could replace the binaries; run chmod go-w %s first", dir, perm, dir)
	}
	return nil
}
