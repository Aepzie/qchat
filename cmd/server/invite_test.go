package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Aepzie/qchat/internal/server"
	"github.com/Aepzie/qchat/internal/store/serverdb"
)

var inviteCodePattern = regexp.MustCompile(`(?m)^  ([A-Z2-7]{4}(?:-[A-Z2-7]{4}){5}-[A-Z2-7]{2})$`)

func TestInitCreatesDatabase(t *testing.T) {
	dir, _ := initDataDir(t)
	cfg, err := server.LoadConfig(filepath.Join(dir, configFileName))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, server.DefaultDatabase); cfg.Database != want {
		t.Fatalf("configured database %q, want %q", cfg.Database, want)
	}
	if cfg.Registration != server.RegistrationInvite || cfg.Limits.MaxMessageSize != server.DefaultMaxMessageSize {
		t.Fatalf("generated config: registration %q, max_message_size %d", cfg.Registration, cfg.Limits.MaxMessageSize)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(cfg.Database + suffix); err == nil {
			t.Errorf("%s left behind after init", filepath.Base(cfg.Database+suffix))
		}
	}
	db, err := serverdb.Open(cfg.Database)
	if err != nil {
		t.Fatalf("database created by init does not open: %v", err)
	}
	defer db.Close()
	if invites, err := db.ListInvites(context.Background()); err != nil || len(invites) != 0 {
		t.Fatalf("new database: %v invites, %v", invites, err)
	}
}

func TestInitDatabaseFlag(t *testing.T) {
	elsewhere := filepath.Join(t.TempDir(), "state", "qchat.db")
	cases := []struct {
		name, flag string
		want       func(dir string) string
	}{
		{"absolute", elsewhere, func(string) string { return elsewhere }},
		{"relative", "store/relay.db", func(dir string) string { return filepath.Join(dir, "store", "relay.db") }},
		{"data directory", "qchat.db", func(dir string) string { return filepath.Join(dir, "qchat.db") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := initDataDir(t, "--database", tc.flag)
			cfg, err := server.LoadConfig(filepath.Join(dir, configFileName))
			if err != nil {
				t.Fatal(err)
			}
			if want := tc.want(dir); cfg.Database != want {
				t.Fatalf("configured database %q, want %q", cfg.Database, want)
			}
			db, err := serverdb.Open(cfg.Database)
			if err != nil {
				t.Fatalf("database created by init does not open: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, server.DefaultDatabase)); err == nil {
				t.Error("default database created although --database was given")
			}
		})
	}
	code, _, stderr := runCLI(t, "init", "--data-dir", filepath.Join(t.TempDir(), "d"), "--database", "bad?.db")
	if code != 1 || !strings.Contains(stderr, "database") {
		t.Fatalf("invalid --database: exit %d, stderr %q", code, stderr)
	}
}

func TestInitForceKeepsDatabase(t *testing.T) {
	dir, _ := initDataDir(t)
	dbPath := filepath.Join(dir, server.DefaultDatabase)
	db, err := serverdb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var id [32]byte
	id[0] = 1
	if _, err := db.PutIdentity(context.Background(), id, []byte("bundle"), 1); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, "init", "--data-dir", dir, "--force"); code != 0 {
		t.Fatalf("init --force exit %d: %s", code, stderr)
	}
	db, err = serverdb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if bundle, _, err := db.GetBundle(context.Background(), id); err != nil || string(bundle) != "bundle" {
		t.Fatalf("identity lost by init --force: %q, %v", bundle, err)
	}
}

func TestInviteCommands(t *testing.T) {
	dir, _ := initDataDir(t)
	configPath := filepath.Join(dir, configFileName)

	if code, stdout, _ := runCLI(t, "invite", "list", "--config", configPath); code != 0 || !strings.Contains(stdout, "No invites") {
		t.Fatalf("list of empty database: exit %d, stdout %q", code, stdout)
	}

	code, stdout, stderr := runCLI(t, "invite", "create", "--config", configPath, "--uses", "2", "--ttl", "2h")
	if code != 0 {
		t.Fatalf("invite create: exit %d, stderr %q", code, stderr)
	}
	m := inviteCodePattern.FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("invite create printed no code:\n%s", stdout)
	}
	for _, want := range []string{"shown only this once", "up to 2 new identities", " UTC."} {
		if !strings.Contains(stdout, want) {
			t.Errorf("invite create output lacks %q:\n%s", want, stdout)
		}
	}
	code2, stdout, _ := runCLI(t, "invite", "create", "--config", configPath)
	if code2 != 0 || !strings.Contains(stdout, "up to 1 new identity until") {
		t.Fatalf("invite create with defaults: exit %d, stdout %q", code2, stdout)
	}

	code, stdout, _ = runCLI(t, "invite", "list", "--config", configPath)
	if code != 0 || !strings.Contains(stdout, "2 invites, 0 expired:") || strings.Count(stdout, "valid") != 2 {
		t.Fatalf("invite list: exit %d, stdout %q", code, stdout)
	}
	if strings.Contains(stdout, m[1]) || strings.Contains(stdout, strings.ReplaceAll(m[1], "-", "")) {
		t.Fatalf("invite list reveals the code:\n%s", stdout)
	}

	dbPath := filepath.Join(dir, server.DefaultDatabase)
	db, err := serverdb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RedeemInvite(context.Background(), strings.ToLower(m[1]), time.Now()); err != nil {
		t.Fatalf("printed code does not redeem: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("INSERT INTO invites (code_hash, expires_at, uses_left) VALUES (zeroblob(32), ?, 1)", time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ = runCLI(t, "invite", "list", "--config", configPath)
	if code != 0 || !strings.Contains(stdout, "3 invites, 1 expired") || !strings.Contains(stdout, "invite prune") || !strings.Contains(stdout, "expired\n") {
		t.Fatalf("invite list with expired invite: exit %d, stdout %q", code, stdout)
	}
	if code, stdout, _ := runCLI(t, "invite", "prune", "--config", configPath); code != 0 || !strings.Contains(stdout, "Removed 1 expired invite.") {
		t.Fatalf("invite prune: exit %d, stdout %q", code, stdout)
	}
	if code, stdout, _ := runCLI(t, "invite", "list", "--config", configPath); code != 0 || !strings.Contains(stdout, "2 invites, 0 expired") {
		t.Fatalf("invite list after prune: exit %d, stdout %q", code, stdout)
	}
}

func TestInviteCommandErrors(t *testing.T) {
	dir, _ := initDataDir(t)
	configPath := filepath.Join(dir, configFileName)

	usageCases := [][]string{
		{"invite"},
		{"invite", "help"},
		{"invite", "frobnicate"},
		{"invite", "create", "--config", configPath, "--uses", "0"},
		{"invite", "create", "--config", configPath, "--uses", "1001"},
		{"invite", "create", "--config", configPath, "--ttl", "31d"},
		{"invite", "create", "--config", configPath, "--ttl", "30s"},
		{"invite", "create", "--config", configPath, "--ttl", "soon"},
		{"invite", "create", "--config", configPath, "extra"},
		{"invite", "list", "--config", configPath, "extra"},
		{"invite", "prune", "--bogus"},
	}
	for _, args := range usageCases {
		if code, stdout, stderr := runCLI(t, args...); code != 2 || stdout != "" || !strings.Contains(stderr, "Usage: qchat-server invite") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}

	if code, _, stderr := runCLI(t, "invite", "list", "--config", filepath.Join(t.TempDir(), "absent.toml")); code != 1 || !strings.Contains(stderr, "read config") {
		t.Errorf("missing config: exit %d, stderr %q", code, stderr)
	}

	elsewhere := t.TempDir()
	otherConfig := filepath.Join(elsewhere, configFileName)
	if err := os.WriteFile(otherConfig, []byte("database = 'missing.db'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"create", "list", "prune"} {
		code, _, stderr := runCLI(t, "invite", sub, "--config", otherConfig)
		if code != 1 || !strings.Contains(stderr, "does not exist") {
			t.Errorf("invite %s with missing database: exit %d, stderr %q", sub, code, stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "missing.db")); err == nil {
		t.Error("invite command created a database outside the data directory")
	}
}

func TestParseInviteTTL(t *testing.T) {
	for text, want := range map[string]time.Duration{
		"72h":  72 * time.Hour,
		"90m":  90 * time.Minute,
		"1m":   time.Minute,
		"1d":   24 * time.Hour,
		"30d":  30 * 24 * time.Hour,
		"720h": 720 * time.Hour,
	} {
		if got, err := parseInviteTTL(text); err != nil || got != want {
			t.Errorf("parseInviteTTL(%q) = %s, %v; want %s", text, got, err, want)
		}
	}
	for _, text := range []string{"", "d", "0d", "-1d", "31d", "1.5d", "59s", "-1h", "720h1s", "10", "1w"} {
		if got, err := parseInviteTTL(text); err == nil {
			t.Errorf("parseInviteTTL(%q) = %s, want an error", text, got)
		}
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path := defaultConfigPath()
	if !filepath.IsAbs(path) || filepath.Base(path) != configFileName {
		t.Fatalf("defaultConfigPath() = %q", path)
	}
}
