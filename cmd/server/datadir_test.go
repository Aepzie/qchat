package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitRefusesSymlinkedDataDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symbolic link: %v", err)
	}
	if code, _, stderr := runCLI(t, "init", "--data-dir", link); code != 1 {
		t.Fatalf("init into symbolic link: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(target, keyFileName)); err == nil {
		t.Fatal("key written through a symbolic link")
	}
}
