//go:build unix

package profile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/craguS/qchat/internal/crypto/vault"
)

func TestPrivatePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profile")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := create(t, dir)
	p.Close()
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, KeyFileName): 0o600, filepath.Join(dir, DBFileName): 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", path, got, want)
		}
	}

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(link, testPassphrase, "Alice", vault.TestParams()); err == nil {
		t.Error("Create accepted a symbolic link as profile directory")
	}
}
