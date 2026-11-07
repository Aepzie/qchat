//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitRefusesWritableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "init", "--data-dir", dir)
	if code != 1 || !strings.Contains(stderr, "writable by other users") {
		t.Fatalf("init into mode 0777 directory: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, keyFileName)); err == nil {
		t.Fatal("key written into a writable directory")
	}
}

func TestInitWarnsAboutReadableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "init", "--data-dir", dir)
	if code != 0 || !strings.Contains(stderr, "warning") {
		t.Fatalf("init into mode 0755 directory: exit %d, stderr %q", code, stderr)
	}
	info, err := os.Stat(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key has mode %04o, want 0600", info.Mode().Perm())
	}
}

func TestInitRejectsServiceAccountFlag(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	code, _, stderr := runCLI(t, "init", "--data-dir", dir, "--service-account", "qchat")
	if code != 1 || !strings.Contains(stderr, "only supported on Windows") {
		t.Fatalf("init --service-account: exit %d, stderr %q", code, stderr)
	}
}

func TestKeyFileExposureChecksMode(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), keyFileName)
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if exposure, err := keyFileExposure(keyPath); err != nil || exposure != "" {
		t.Fatalf("mode 0600: exposure %q, err %v", exposure, err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if exposure, err := keyFileExposure(keyPath); err != nil || !strings.Contains(exposure, "0644") {
		t.Fatalf("mode 0644: exposure %q, err %v", exposure, err)
	}
}
