package profile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/crypto/vault"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/store/clientdb"
)

var (
	testPassphrase  = []byte("correct horse battery")
	otherPassphrase = []byte("staple cloud river lamp")
)

func create(t *testing.T, dir string) *Profile {
	t.Helper()
	p, err := Create(dir, testPassphrase, "Alice", vault.TestParams())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func unlock(t *testing.T, dir string, passphrase []byte) *Profile {
	t.Helper()
	p, err := Unlock(dir, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestCreateUnlockPersistence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "profile")
	if Exists(dir) {
		t.Fatal("Exists before Create")
	}
	p := create(t, dir)
	if !Exists(dir) {
		t.Fatal("Exists after Create is false")
	}
	if p.DisplayName() != "Alice" || p.BundleSerial != 1 {
		t.Errorf("display name %q, serial %d", p.DisplayName(), p.BundleSerial)
	}
	first, err := p.Bundle(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if bundle, err := identity.ParseBundleForID(first, p.Identity.ID()); err != nil || bundle.Serial != 1 {
		t.Fatalf("bundle: %v", err)
	}
	id := p.Identity.ID()
	if err := p.SetDisplayName("Alice B."); err != nil {
		t.Fatal(err)
	}
	msg := clientdb.Message{Peer: [32]byte{1}, MsgID: [16]byte{2}, Dir: clientdb.Incoming, Sent: time.Now(), Received: time.Now(), Body: "hi", Status: clientdb.StatusReceived}
	if err := p.DB.AppendMessage(t.Context(), msg); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := p.Bundle(time.Now()); !errors.Is(err, ErrClosed) {
		t.Errorf("Bundle after Close: %v", err)
	}
	if _, err := p.Identity.MarshalSecret(); !errors.Is(err, identity.ErrDestroyed) {
		t.Errorf("identity not destroyed by Close: %v", err)
	}

	reopened := unlock(t, dir, testPassphrase)
	if reopened.Identity.ID() != id || reopened.DisplayName() != "Alice B." || reopened.BundleSerial != 1 {
		t.Errorf("reopened profile differs: %v %q %d", reopened.Identity.ID(), reopened.DisplayName(), reopened.BundleSerial)
	}
	again, err := reopened.Bundle(time.Now().Add(time.Hour))
	if err != nil || !bytes.Equal(again, first) {
		t.Errorf("stored bundle not returned unchanged: %v", err)
	}
	if ok, err := reopened.DB.HasMessage(t.Context(), msg.Peer, msg.MsgID); err != nil || !ok {
		t.Errorf("message not persisted: %v %v", ok, err)
	}
}

func TestUnlockErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Unlock(dir, testPassphrase); !errors.Is(err, ErrNoProfile) {
		t.Errorf("empty dir: %v", err)
	}
	p := create(t, dir)
	p.Close()
	if _, err := Unlock(dir, otherPassphrase); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
	if _, err := Unlock(dir, nil); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("empty passphrase: %v", err)
	}

	keyPath := filepath.Join(dir, KeyFileName)
	blob, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 1
	if err := os.WriteFile(keyPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(dir, testPassphrase); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("tampered key file: %v", err)
	}

	other := t.TempDir()
	q := create(t, other)
	q.Close()
	otherBlob, err := os.ReadFile(filepath.Join(other, KeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, otherBlob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(dir, testPassphrase); !errors.Is(err, clientdb.ErrWrongKey) {
		t.Errorf("key file of another profile: %v", err)
	}
}

func TestCreateRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	p := create(t, dir)
	id := p.Identity.ID()
	p.Close()
	if _, err := Create(dir, testPassphrase, "Mallory", vault.TestParams()); !errors.Is(err, ErrExists) {
		t.Fatalf("second Create: %v", err)
	}
	if unlock(t, dir, testPassphrase).Identity.ID() != id {
		t.Fatal("existing profile was modified")
	}

	orphan := t.TempDir()
	if err := os.WriteFile(filepath.Join(orphan, DBFileName), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(orphan, testPassphrase, "Alice", vault.TestParams()); !errors.Is(err, ErrExists) {
		t.Errorf("Create over orphaned database: %v", err)
	}
	if Exists(orphan) {
		t.Error("key file written next to orphaned database")
	}
}

func TestCreateRejectsArguments(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p")
	cases := []struct {
		name       string
		passphrase []byte
		display    string
		params     vault.Params
		want       error
	}{
		{"short passphrase", []byte("eleven char"), "Alice", vault.TestParams(), ErrWeakPassphrase},
		{"empty passphrase", nil, "Alice", vault.TestParams(), ErrWeakPassphrase},
		{"multibyte runes count once", []byte("ääääääääääá"), "Alice", vault.TestParams(), ErrWeakPassphrase},
		{"empty display name", testPassphrase, "", vault.TestParams(), clientdb.ErrInvalid},
		{"control character in name", testPassphrase, "A\x1b[2J", vault.TestParams(), clientdb.ErrInvalid},
		{"unsafe KDF params", testPassphrase, "Alice", vault.Params{Time: 1, MemoryKiB: 8, Threads: 1}, vault.ErrUnsafeParams},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Create(dir, tc.passphrase, tc.display, tc.params); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if Exists(dir) {
				t.Error("failed Create left a key file")
			}
			if _, err := os.Stat(filepath.Join(dir, DBFileName)); err == nil {
				t.Error("failed Create left a database")
			}
		})
	}
	if err := CheckPassphrase([]byte("twelve chars")); err != nil {
		t.Errorf("12-character passphrase rejected: %v", err)
	}
}

func TestChangePassphrase(t *testing.T) {
	dir := t.TempDir()
	p := create(t, dir)
	id := p.Identity.ID()
	if err := p.ChangePassphrase(otherPassphrase, []byte("a brand new passphrase")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong old passphrase: %v", err)
	}
	if err := p.ChangePassphrase(testPassphrase, []byte("too short")); !errors.Is(err, ErrWeakPassphrase) {
		t.Errorf("weak new passphrase: %v", err)
	}
	if err := p.ChangePassphrase(testPassphrase, otherPassphrase); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if name := e.Name(); name != KeyFileName && name != DBFileName && name != DBFileName+"-wal" && name != DBFileName+"-shm" {
			t.Errorf("unexpected file %s left in profile directory", name)
		}
	}
	p.Close()
	if err := p.ChangePassphrase(otherPassphrase, testPassphrase); !errors.Is(err, ErrClosed) {
		t.Errorf("after Close: %v", err)
	}

	if _, err := Unlock(dir, testPassphrase); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("old passphrase still works: %v", err)
	}
	if q := unlock(t, dir, otherPassphrase); q.Identity.ID() != id {
		t.Error("identity changed with the passphrase")
	}
}

func TestDefaultDir(t *testing.T) {
	home := func() (string, error) { return filepath.FromSlash("/home/u"), nil }
	config := func() (string, error) { return filepath.FromSlash("/cfg"), nil }
	xdg := t.TempDir()
	env := func(values map[string]string) func(string) string {
		return func(k string) string { return values[k] }
	}
	cases := []struct {
		goos string
		env  map[string]string
		want string
	}{
		{"windows", nil, "/cfg/qchat"},
		{"darwin", nil, "/cfg/qchat"},
		{"linux", nil, "/home/u/.local/share/qchat"},
		{"linux", map[string]string{"XDG_DATA_HOME": xdg}, filepath.Join(xdg, "qchat")},
		{"freebsd", map[string]string{"XDG_DATA_HOME": "relative/path"}, "/home/u/.local/share/qchat"},
	}
	for _, tc := range cases {
		got, err := defaultDir(tc.goos, env(tc.env), home, config)
		if err != nil || got != filepath.FromSlash(tc.want) {
			t.Errorf("%s %v: %q, %v; want %q", tc.goos, tc.env, got, err, tc.want)
		}
	}
	if _, err := defaultDir("linux", env(nil), func() (string, error) { return "", errors.New("no home") }, config); err == nil {
		t.Error("missing home accepted")
	}
	if dir, err := DefaultDir(); err != nil || filepath.Base(dir) != "qchat" {
		t.Errorf("DefaultDir() = %q, %v", dir, err)
	}
}

func removeDatabase(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{DBFileName, DBFileName + "-wal", DBFileName + "-shm"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

func TestUnlockMissingDatabase(t *testing.T) {
	dir := t.TempDir()
	p := create(t, dir)
	p.Close()
	removeDatabase(t, dir)
	if _, err := Unlock(dir, testPassphrase); !errors.Is(err, ErrDatabaseMissing) || !errors.Is(err, clientdb.ErrMissing) {
		t.Fatalf("missing database: %v, want ErrDatabaseMissing", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, DBFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Unlock created a database: %v", err)
	}
	if _, err := Unlock(dir, otherPassphrase); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase with missing database: %v", err)
	}
}

func TestRecoverAdoptsRelayBundle(t *testing.T) {
	dir := t.TempDir()
	p := create(t, dir)
	id := p.Identity.ID()
	relayBundle, err := p.Bundle(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	removeDatabase(t, dir)

	recovered, err := Recover(dir, testPassphrase, relayBundle)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Identity.ID() != id || recovered.BundleSerial != 1 || recovered.DisplayName() != "" {
		t.Errorf("recovered profile: %v serial %d name %q", recovered.Identity.ID(), recovered.BundleSerial, recovered.DisplayName())
	}
	again, err := recovered.Bundle(time.Now().Add(time.Hour))
	if err != nil || !bytes.Equal(again, relayBundle) {
		t.Fatalf("recovered profile does not return the relay bundle: %v", err)
	}
	if err := recovered.SetDisplayName("Alice"); err != nil {
		t.Fatal(err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := unlock(t, dir, testPassphrase)
	if reopened.BundleSerial != 1 || reopened.DisplayName() != "Alice" {
		t.Errorf("reopened after recovery: serial %d name %q", reopened.BundleSerial, reopened.DisplayName())
	}
	if raw, err := reopened.Bundle(time.Now()); err != nil || !bytes.Equal(raw, relayBundle) {
		t.Errorf("reopened bundle differs: %v", err)
	}
	reopened.Close()
	if _, err := Recover(dir, testPassphrase, relayBundle); !errors.Is(err, ErrExists) {
		t.Errorf("Recover over an existing database: %v, want ErrExists", err)
	}
}

func TestRecoverRejects(t *testing.T) {
	dir := t.TempDir()
	p := create(t, dir)
	p.Close()
	removeDatabase(t, dir)

	other := create(t, t.TempDir())
	foreign, err := other.Bundle(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(dir, testPassphrase, foreign); !errors.Is(err, ErrBundleMismatch) || !errors.Is(err, identity.ErrIDMismatch) {
		t.Errorf("bundle of another identity: %v, want ErrBundleMismatch", err)
	}
	if _, err := Recover(dir, testPassphrase, []byte{0xa0}); !errors.Is(err, ErrBundleMismatch) {
		t.Errorf("malformed bundle: %v, want ErrBundleMismatch", err)
	}
	if _, err := Recover(dir, otherPassphrase, nil); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
	if _, err := Recover(t.TempDir(), testPassphrase, nil); !errors.Is(err, ErrNoProfile) {
		t.Errorf("no profile: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, DBFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed Recover left a database: %v", err)
	}

	fresh, err := Recover(dir, testPassphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.BundleSerial != 0 {
		t.Errorf("serial without relay bundle = %d, want 0", fresh.BundleSerial)
	}
	raw, err := fresh.Bundle(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if bundle, err := identity.ParseBundleForID(raw, fresh.Identity.ID()); err != nil || bundle.Serial != 1 {
		t.Errorf("new bundle after recovery without relay bundle: %v", err)
	}
}
