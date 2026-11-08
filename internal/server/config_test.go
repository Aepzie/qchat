package server

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeConfigFile(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "server.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	want := Config{
		Listen:         "0.0.0.0:7443",
		TLSCert:        "server.crt",
		TLSKey:         "server.key",
		Database:       "db/qchat.db",
		Registration:   "invite",
		UndeliveredTTL: DurationOf(168 * time.Hour),
		Limits: Limits{
			MaxConnections:                 1000,
			MaxConnectionsPerIP:            16,
			MaxPendingHandshakes:           64,
			MaxFrameSize:                   1048576,
			MaxMessageSize:                 270336,
			MaxQueueBytes:                  2 << 20,
			MaxTotalQueueBytes:             256 << 20,
			MaxSessionsPerIdentity:         4,
			FramesPerSecond:                20,
			Burst:                          40,
			HandshakeTimeout:               DurationOf(10 * time.Second),
			PingInterval:                   DurationOf(30 * time.Second),
			MaxQueuedMessages:              1000,
			MaxQueuedBytes:                 64 << 20,
			PrekeyRequestsPerHour:          120,
			MultiRecipientsPerMinute:       3000,
			SealedRecipientsPerMinute:      3000,
			SealedRecipientsPerMinutePerIP: 6000,
			MaxQueuedSealedMessages:        500,
			AnonymousLookupsPerHourPerIP:   1200,
		},
		Log: LogConfig{Level: "info"},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("DefaultConfig() = %+v, want %+v", cfg, want)
	}
	if got := cfg.Limits.idleTimeout(); got != 70*time.Second {
		t.Fatalf("idle timeout %v, want 70s", got)
	}
}

func TestLoadConfigFull(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, `
listen = "127.0.0.1:9000"
tls_cert = "a.crt"
tls_key  = "b.key"
database = "state/q.db"
registration = "open"
undelivered_ttl = "48h"
[limits]
max_queued_messages = 50
max_queued_bytes = 2097152
prekey_requests_per_hour = 5
multi_recipients_per_minute = 600
sealed_recipients_per_minute = 100
sealed_recipients_per_minute_per_ip = 200
max_queued_sealed_messages = 7
anonymous_lookups_per_hour_per_ip = 9
max_connections = 50
max_connections_per_ip = 4
max_pending_handshakes = 8
max_frame_size = 65536
max_message_size = 4096
max_queue_bytes = 1048576
max_total_queue_bytes = 8388608
max_sessions_per_identity = 2
frames_per_second = 2.5
burst = 7
handshake_timeout = "1500ms"
ping_interval = "1m"
[log]
level = "debug"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Listen:         "127.0.0.1:9000",
		TLSCert:        filepath.Join(dir, "a.crt"),
		TLSKey:         filepath.Join(dir, "b.key"),
		Database:       filepath.Join(dir, "state", "q.db"),
		Registration:   "open",
		UndeliveredTTL: DurationOf(48 * time.Hour),
		Limits: Limits{
			MaxQueuedMessages:              50,
			MaxQueuedBytes:                 2 << 20,
			PrekeyRequestsPerHour:          5,
			MultiRecipientsPerMinute:       600,
			SealedRecipientsPerMinute:      100,
			SealedRecipientsPerMinutePerIP: 200,
			MaxQueuedSealedMessages:        7,
			AnonymousLookupsPerHourPerIP:   9,
			MaxConnections:                 50,
			MaxConnectionsPerIP:            4,
			MaxPendingHandshakes:           8,
			MaxFrameSize:                   65536,
			MaxMessageSize:                 4096,
			MaxQueueBytes:                  1 << 20,
			MaxTotalQueueBytes:             8 << 20,
			MaxSessionsPerIdentity:         2,
			FramesPerSecond:                2.5,
			Burst:                          7,
			HandshakeTimeout:               DurationOf(1500 * time.Millisecond),
			PingInterval:                   DurationOf(time.Minute),
		},
		Log: LogConfig{Level: "debug"},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("LoadConfig = %+v, want %+v", cfg, want)
	}
}

func TestLoadConfigPartialKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadConfig(writeConfigFile(t, dir, "[limits]\nburst = 5\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultConfig()
	want.Limits.Burst = 5
	want.TLSCert = filepath.Join(dir, DefaultTLSCert)
	want.TLSKey = filepath.Join(dir, DefaultTLSKey)
	want.Database = filepath.Join(dir, DefaultDatabase)
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("LoadConfig = %+v, want %+v", cfg, want)
	}
}

func TestLoadConfigEmptyFile(t *testing.T) {
	if _, err := LoadConfig(writeConfigFile(t, t.TempDir(), "")); err != nil {
		t.Fatalf("empty config rejected: %v", err)
	}
}

func TestLoadConfigRelativePaths(t *testing.T) {
	dir := t.TempDir()
	absKey := filepath.Join(t.TempDir(), "elsewhere.key")
	path := writeConfigFile(t, dir, "tls_cert = 'certs/server.crt'\ntls_key = '"+absKey+"'\ndatabase = 'db/qchat.db'\n")

	t.Chdir(t.TempDir())

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "certs", "server.crt"); cfg.TLSCert != want {
		t.Errorf("TLSCert = %q, want %q", cfg.TLSCert, want)
	}
	if cfg.TLSKey != absKey {
		t.Errorf("TLSKey = %q, want unchanged %q", cfg.TLSKey, absKey)
	}
	if want := filepath.Join(dir, "db", "qchat.db"); cfg.Database != want {
		t.Errorf("Database = %q, want %q", cfg.Database, want)
	}
}

func TestLoadConfigRelativeConfigPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeConfigFile(t, filepath.Join(dir, "data"), "")
	t.Chdir(dir)
	cfg, err := LoadConfig(filepath.Join("data", "server.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "data", DefaultTLSCert); !sameFile(cfg.TLSCert, want) {
		t.Fatalf("TLSCert = %q, want %q", cfg.TLSCert, want)
	}
	if !filepath.IsAbs(cfg.TLSCert) {
		t.Fatalf("TLSCert %q is not absolute", cfg.TLSCert)
	}
}

// sameFile compares paths that may differ only in symlinked or short-name
// prefixes of temporary directories.
func sameFile(a, b string) bool {
	if a == b {
		return true
	}
	ea, errA := filepath.EvalSymlinks(filepath.Dir(a))
	eb, errB := filepath.EvalSymlinks(filepath.Dir(b))
	return errA == nil && errB == nil && ea == eb && filepath.Base(a) == filepath.Base(b)
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	for _, content := range []string{
		"listne = \"0.0.0.0:1\"\n",
		"[limits]\nmax_conns = 3\n",
		"[logging]\nlevel = \"info\"\n",
		"[log]\nlevel = \"info\"\nformat = \"json\"\n",
	} {
		_, err := LoadConfig(writeConfigFile(t, t.TempDir(), content))
		if err == nil {
			t.Errorf("config %q accepted", content)
			continue
		}
		if !strings.Contains(err.Error(), "unknown keys") {
			t.Errorf("config %q: error %q does not mention unknown keys", content, err)
		}
	}
}

func TestLoadConfigSyntaxAndTypeErrors(t *testing.T) {
	for _, content := range []string{
		"listen = ",
		"[limits]\nburst = \"many\"\n",
		"[limits]\nhandshake_timeout = 10\n",
		"[limits]\nhandshake_timeout = \"10\"\n",
		"[limits]\nping_interval = \"soon\"\n",
		"[limits]\nmax_frame_size = 99999999999999999999\n",
	} {
		if _, err := LoadConfig(writeConfigFile(t, t.TempDir(), content)); err == nil {
			t.Errorf("config %q accepted", content)
		}
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Config){
		"empty listen":            func(c *Config) { c.Listen = "" },
		"listen without port":     func(c *Config) { c.Listen = "0.0.0.0" },
		"listen bad port":         func(c *Config) { c.Listen = "0.0.0.0:http" },
		"listen port too large":   func(c *Config) { c.Listen = "0.0.0.0:70000" },
		"empty cert":              func(c *Config) { c.TLSCert = "" },
		"empty key":               func(c *Config) { c.TLSKey = "" },
		"zero connections":        func(c *Config) { c.Limits.MaxConnections = 0 },
		"huge connections":        func(c *Config) { c.Limits.MaxConnections = 2_000_000 },
		"zero per ip":             func(c *Config) { c.Limits.MaxConnectionsPerIP = 0 },
		"per ip above total":      func(c *Config) { c.Limits.MaxConnectionsPerIP = 1001 },
		"tiny frames":             func(c *Config) { c.Limits.MaxFrameSize = 10 },
		"frames above protocol":   func(c *Config) { c.Limits.MaxFrameSize = 1<<20 + 1 },
		"zero rate":               func(c *Config) { c.Limits.FramesPerSecond = 0 },
		"negative rate":           func(c *Config) { c.Limits.FramesPerSecond = -1 },
		"NaN rate":                func(c *Config) { c.Limits.FramesPerSecond = math.NaN() },
		"infinite rate":           func(c *Config) { c.Limits.FramesPerSecond = math.Inf(1) },
		"zero burst":              func(c *Config) { c.Limits.Burst = 0 },
		"zero handshake":          func(c *Config) { c.Limits.HandshakeTimeout = Duration{} },
		"negative handshake":      func(c *Config) { c.Limits.HandshakeTimeout = DurationOf(-time.Second) },
		"long handshake":          func(c *Config) { c.Limits.HandshakeTimeout = DurationOf(time.Hour) },
		"ping too short":          func(c *Config) { c.Limits.PingInterval = DurationOf(500 * time.Millisecond) },
		"ping too long":           func(c *Config) { c.Limits.PingInterval = DurationOf(3601 * time.Second) },
		"ping fractional":         func(c *Config) { c.Limits.PingInterval = DurationOf(1500 * time.Millisecond) },
		"unknown log level":       func(c *Config) { c.Log.Level = "verbose" },
		"log level wrong case":    func(c *Config) { c.Log.Level = "INFO" },
		"empty log level":         func(c *Config) { c.Log.Level = "" },
		"negative frame size":     func(c *Config) { c.Limits.MaxFrameSize = -1 },
		"negative max per ip":     func(c *Config) { c.Limits.MaxConnectionsPerIP = -5 },
		"negative max conns":      func(c *Config) { c.Limits.MaxConnections = -5 },
		"zero pending":            func(c *Config) { c.Limits.MaxPendingHandshakes = 0 },
		"negative pending":        func(c *Config) { c.Limits.MaxPendingHandshakes = -1 },
		"huge pending":            func(c *Config) { c.Limits.MaxPendingHandshakes = maxConnectionsLimit + 1 },
		"burst above the limit":   func(c *Config) { c.Limits.Burst = maxBurst + 1 },
		"rate above the maximum":  func(c *Config) { c.Limits.FramesPerSecond = maxFramesPerSecond + 1 },
		"empty database":          func(c *Config) { c.Database = "" },
		"database with query":     func(c *Config) { c.Database = "q.db?mode=ro" },
		"database with fragment":  func(c *Config) { c.Database = "q.db#x" },
		"empty registration":      func(c *Config) { c.Registration = "" },
		"unknown registration":    func(c *Config) { c.Registration = "closed" },
		"registration wrong case": func(c *Config) { c.Registration = "Invite" },
		"tiny messages":           func(c *Config) { c.Limits.MaxMessageSize = MinMessageSize - 1 },
		"zero message size":       func(c *Config) { c.Limits.MaxMessageSize = 0 },
		"messages fill the frame": func(c *Config) { c.Limits.MaxMessageSize = MaxMessageSize + 1 },
		"tiny queue":              func(c *Config) { c.Limits.MaxQueueBytes = MinQueueBytes - 1 },
		"huge queue":              func(c *Config) { c.Limits.MaxQueueBytes = MaxQueueBytes + 1 },
		"total below queue":       func(c *Config) { c.Limits.MaxTotalQueueBytes = c.Limits.MaxQueueBytes - 1 },
		"huge total queue":        func(c *Config) { c.Limits.MaxTotalQueueBytes = MaxTotalQueueBytes + 1 },
		"zero sessions per id":    func(c *Config) { c.Limits.MaxSessionsPerIdentity = 0 },
		"many sessions per id":    func(c *Config) { c.Limits.MaxSessionsPerIdentity = maxSessionsPerID + 1 },
		"zero undelivered ttl":    func(c *Config) { c.UndeliveredTTL = Duration{} },
		"short undelivered ttl":   func(c *Config) { c.UndeliveredTTL = DurationOf(MinUndeliveredTTL - time.Second) },
		"long undelivered ttl":    func(c *Config) { c.UndeliveredTTL = DurationOf(MaxUndeliveredTTL + time.Second) },
		"zero queued messages":    func(c *Config) { c.Limits.MaxQueuedMessages = 0 },
		"many queued messages":    func(c *Config) { c.Limits.MaxQueuedMessages = MaxQueuedMessages + 1 },
		"tiny queued bytes":       func(c *Config) { c.Limits.MaxQueuedBytes = MinQueuedBytes - 1 },
		"huge queued bytes":       func(c *Config) { c.Limits.MaxQueuedBytes = MaxQueuedBytes + 1 },
		"zero prekey requests":    func(c *Config) { c.Limits.PrekeyRequestsPerHour = 0 },
		"many prekey requests":    func(c *Config) { c.Limits.PrekeyRequestsPerHour = MaxPrekeyRequestsPerHour + 1 },
		"zero multi recipients":   func(c *Config) { c.Limits.MultiRecipientsPerMinute = 0 },
		"many multi recipients":   func(c *Config) { c.Limits.MultiRecipientsPerMinute = MaxMultiRecipientsPerMinute + 1 },
		"zero sealed recipients":  func(c *Config) { c.Limits.SealedRecipientsPerMinute = 0 },
		"many sealed recipients":  func(c *Config) { c.Limits.SealedRecipientsPerMinute = MaxSealedRecipientsPerMinute + 1 },
		"zero sealed per ip":      func(c *Config) { c.Limits.SealedRecipientsPerMinutePerIP = 0 },
		"many sealed per ip":      func(c *Config) { c.Limits.SealedRecipientsPerMinutePerIP = MaxSealedRecipientsPerMinute + 1 },
		"zero sealed queue":       func(c *Config) { c.Limits.MaxQueuedSealedMessages = 0 },
		"many sealed queued":      func(c *Config) { c.Limits.MaxQueuedSealedMessages = MaxQueuedMessages + 1 },
		"zero anonymous lookups":  func(c *Config) { c.Limits.AnonymousLookupsPerHourPerIP = 0 },
		"many anonymous lookups":  func(c *Config) { c.Limits.AnonymousLookupsPerHourPerIP = MaxAnonymousLookupsPerHourIP + 1 },
	}
	for name, mutate := range cases {
		cfg := DefaultConfig()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", name, cfg)
		}
	}
}

func TestValidateAccepts(t *testing.T) {
	cases := map[string]func(*Config){
		"empty host":            func(c *Config) { c.Listen = ":7443" },
		"ipv6 host":             func(c *Config) { c.Listen = "[::]:7443" },
		"port zero":             func(c *Config) { c.Listen = "127.0.0.1:0" },
		"minimum ping":          func(c *Config) { c.Limits.PingInterval = DurationOf(time.Second) },
		"maximum ping":          func(c *Config) { c.Limits.PingInterval = DurationOf(time.Hour) },
		"per ip equals total":   func(c *Config) { c.Limits.MaxConnectionsPerIP = c.Limits.MaxConnections },
		"fractional rate":       func(c *Config) { c.Limits.FramesPerSecond = 0.1 },
		"each log level":        func(c *Config) { c.Log.Level = "warn" },
		"pending above total":   func(c *Config) { c.Limits.MaxPendingHandshakes = c.Limits.MaxConnections + 1 },
		"open registration":     func(c *Config) { c.Registration = RegistrationOpen },
		"minimum message size":  func(c *Config) { c.Limits.MaxMessageSize = MinMessageSize },
		"maximum message size":  func(c *Config) { c.Limits.MaxMessageSize = MaxMessageSize },
		"absolute database":     func(c *Config) { c.Database = filepath.Join(os.TempDir(), "q.db") },
		"minimum queue":         func(c *Config) { c.Limits.MaxQueueBytes, c.Limits.MaxTotalQueueBytes = MinQueueBytes, MinQueueBytes },
		"maximum total queue":   func(c *Config) { c.Limits.MaxTotalQueueBytes = MaxTotalQueueBytes },
		"one session per id":    func(c *Config) { c.Limits.MaxSessionsPerIdentity = 1 },
		"minimum ttl":           func(c *Config) { c.UndeliveredTTL = DurationOf(MinUndeliveredTTL) },
		"maximum ttl":           func(c *Config) { c.UndeliveredTTL = DurationOf(MaxUndeliveredTTL) },
		"one queued message":    func(c *Config) { c.Limits.MaxQueuedMessages = 1 },
		"most queued messages":  func(c *Config) { c.Limits.MaxQueuedMessages = MaxQueuedMessages },
		"minimum queued bytes":  func(c *Config) { c.Limits.MaxQueuedBytes = MinQueuedBytes },
		"maximum queued bytes":  func(c *Config) { c.Limits.MaxQueuedBytes = MaxQueuedBytes },
		"one prekey request":    func(c *Config) { c.Limits.PrekeyRequestsPerHour = 1 },
		"most prekey requests":  func(c *Config) { c.Limits.PrekeyRequestsPerHour = MaxPrekeyRequestsPerHour },
		"one multi recipient":   func(c *Config) { c.Limits.MultiRecipientsPerMinute = 1 },
		"most multi recipients": func(c *Config) { c.Limits.MultiRecipientsPerMinute = MaxMultiRecipientsPerMinute },
		"one sealed recipient":  func(c *Config) { c.Limits.SealedRecipientsPerMinute, c.Limits.SealedRecipientsPerMinutePerIP = 1, 1 },
		"most sealed recipients": func(c *Config) {
			c.Limits.SealedRecipientsPerMinute, c.Limits.SealedRecipientsPerMinutePerIP = MaxSealedRecipientsPerMinute, MaxSealedRecipientsPerMinute
		},
	}
	for name, mutate := range cases {
		cfg := DefaultConfig()
		mutate(&cfg)
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s: Validate rejected: %v", name, err)
		}
	}
}

func TestDurationText(t *testing.T) {
	var d Duration
	if err := d.UnmarshalText([]byte("1m30s")); err != nil || d.Std() != 90*time.Second {
		t.Fatalf("UnmarshalText(1m30s) = %v, %v", d.Std(), err)
	}
	for _, bad := range []string{"", "10", "ten seconds", "1y"} {
		if err := d.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("UnmarshalText(%q) succeeded", bad)
		}
	}
	text, err := DurationOf(10 * time.Second).MarshalText()
	if err != nil || string(text) != "10s" {
		t.Fatalf("MarshalText = %q, %v", text, err)
	}
}

func TestWriteTOMLRoundTrip(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = "[::]:8443"
	cfg.Limits.FramesPerSecond = 12.5
	var buf bytes.Buffer
	if err := cfg.WriteTOML(&buf); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	for _, want := range []string{`listen = '[::]:8443'`, "[limits]", "[log]", `handshake_timeout = '10s'`, "never logged or stored", "max_pending_handshakes = 64", "before TLS", "database = 'db/qchat.db'", "registration = 'invite'", "max_message_size = 270336", "max_queued_sealed_messages = 500", "anonymous_lookups_per_hour_per_ip = 1200", "max_queue_bytes = 2097152", "max_total_queue_bytes = 268435456", "max_sessions_per_identity = 4", "invite create",
		"undelivered_ttl = '168h0m0s'", "max_queued_messages = 1000", "max_queued_bytes = 67108864",
		"prekey_requests_per_hour = 120", "multi_recipients_per_minute = 3000", "burst of 512", "waiting for delivery",
		"sealed_recipients_per_minute = 3000", "sealed_recipients_per_minute_per_ip = 6000", "burst of 1024", "Tor onion service"} {
		if !strings.Contains(text, want) {
			t.Errorf("WriteTOML output lacks %q:\n%s", want, text)
		}
	}
	parsed, err := ParseConfig(buf.Bytes())
	if err != nil {
		t.Fatalf("re-parse: %v\n%s", err, text)
	}
	if !reflect.DeepEqual(parsed, cfg) {
		t.Fatalf("round trip = %+v, want %+v", parsed, cfg)
	}
}

func TestLogLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		if _, err := (LogConfig{Level: level}).SlogLevel(); err != nil {
			t.Errorf("level %q rejected: %v", level, err)
		}
	}
}
