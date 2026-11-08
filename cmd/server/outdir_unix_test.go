//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckOutDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o700, 0o755} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkOutDir(dir); err != nil {
			t.Errorf("mode %04o: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkOutDir(dir); err == nil || !strings.Contains(err.Error(), "writable by other users") {
			t.Errorf("mode %04o: err = %v, want a writable-by-others error", mode, err)
		}
	}
}
