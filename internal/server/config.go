package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/craguS/qchat/internal/protocol"
)

// Default configuration values. They are also written by "qchat-server init".
const (
	DefaultListen              = "0.0.0.0:7443"
	DefaultTLSCert             = "server.crt"
	DefaultTLSKey              = "server.key"
	DefaultMaxConnections      = 1000
	DefaultMaxConnectionsPerIP = 16
	DefaultMaxFrameSize        = protocol.MaxFrameSize
	DefaultFramesPerSecond     = 20.0
	DefaultBurst               = 40
	DefaultHandshakeTimeout    = 10 * time.Second
	DefaultPingInterval        = 30 * time.Second
	DefaultLogLevel            = "info"
)

// Bounds enforced by Config.Validate.
const (
	maxConnectionsLimit   = 1_000_000
	minFrameSize          = 256
	maxFramesPerSecond    = 100_000
	maxBurst              = 1_000_000
	maxHandshakeTimeout   = 5 * time.Minute
	minPingInterval       = time.Second
	maxConfigFileSize     = 1 << 20
	configFieldListen     = "listen"
	configFieldPingPeriod = "limits.ping_interval"
)

// Duration is a time.Duration that is written in TOML as a Go duration
// string such as "10s" or "1m30s".
//
// It is a struct rather than a named integer type on purpose: the TOML
// decoder would otherwise accept a bare integer such as
// handshake_timeout = 10 and silently read it as 10 nanoseconds.
type Duration struct {
	d time.Duration
}

// DurationOf wraps d.
func DurationOf(d time.Duration) Duration { return Duration{d: d} }

// UnmarshalText implements encoding.TextUnmarshaler using time.ParseDuration.
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q", text)
	}
	d.d = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.d.String()), nil
}

// Std returns d as a time.Duration.
func (d Duration) Std() time.Duration { return d.d }

// Config is the complete server configuration, normally loaded from a TOML
// file with LoadConfig.
type Config struct {
	// Listen is the TCP address to listen on, as "host:port". An empty host
	// listens on all interfaces.
	Listen string `toml:"listen" comment:"TCP address to listen on (host:port)."`
	// TLSCert is the path of the PEM certificate. LoadConfig resolves
	// relative paths against the directory of the configuration file.
	TLSCert string `toml:"tls_cert" comment:"PEM certificate; relative paths resolve against this file's directory."`
	// TLSKey is the path of the PEM private key, resolved like TLSCert.
	TLSKey string `toml:"tls_key" comment:"PEM private key (keep it secret, mode 0600)."`
	// Limits bounds the resources a client can consume.
	Limits Limits `toml:"limits"`
	// Log configures logging.
	Log LogConfig `toml:"log"`
}

// Limits bounds the resources clients can consume.
type Limits struct {
	// MaxConnections is the maximum number of simultaneous connections.
	MaxConnections int `toml:"max_connections" comment:"Maximum simultaneous connections."`
	// MaxConnectionsPerIP is the maximum number of simultaneous connections
	// from one IPv4 address or one IPv6 /64 prefix. Addresses are held in
	// memory only for this counter, and never logged or stored.
	MaxConnectionsPerIP int `toml:"max_connections_per_ip" comment:"Maximum simultaneous connections per IPv4 address or IPv6 /64.\nAddresses are held in memory only for this counter, never logged or stored."`
	// MaxFrameSize is the largest accepted WebSocket message in bytes. It
	// must not exceed protocol.MaxFrameSize.
	MaxFrameSize int `toml:"max_frame_size" comment:"Largest accepted frame in bytes (at most 1048576)."`
	// FramesPerSecond is the sustained per-session frame rate.
	FramesPerSecond float64 `toml:"frames_per_second" comment:"Sustained frames per second per session."`
	// Burst is the per-session token bucket size.
	Burst int `toml:"burst" comment:"Frames a session may send in a burst above the sustained rate."`
	// HandshakeTimeout bounds the wait for the client's Hello.
	HandshakeTimeout Duration `toml:"handshake_timeout" comment:"Time a client has to send its Hello."`
	// PingInterval is the keepalive interval announced to clients, in whole
	// seconds between 1s and protocol.MaxPingInterval seconds. A session
	// that sends nothing for 2*PingInterval+10s is closed.
	PingInterval Duration `toml:"ping_interval" comment:"Keepalive interval announced to clients (whole seconds, 1s to 1h).\nSessions silent for twice this plus 10s are closed."`
}

// LogConfig configures logging.
type LogConfig struct {
	// Level is one of "debug", "info", "warn" or "error".
	Level string `toml:"level" comment:"One of debug, info, warn, error."`
}

// DefaultConfig returns the configuration used for every field that a
// configuration file leaves out.
func DefaultConfig() Config {
	return Config{
		Listen:  DefaultListen,
		TLSCert: DefaultTLSCert,
		TLSKey:  DefaultTLSKey,
		Limits: Limits{
			MaxConnections:      DefaultMaxConnections,
			MaxConnectionsPerIP: DefaultMaxConnectionsPerIP,
			MaxFrameSize:        DefaultMaxFrameSize,
			FramesPerSecond:     DefaultFramesPerSecond,
			Burst:               DefaultBurst,
			HandshakeTimeout:    DurationOf(DefaultHandshakeTimeout),
			PingInterval:        DurationOf(DefaultPingInterval),
		},
		Log: LogConfig{Level: DefaultLogLevel},
	}
}

// LoadConfig reads the TOML file at path on top of DefaultConfig, resolves
// relative TLS paths against the file's directory and validates the result.
// Unknown keys are rejected so that typos do not silently fall back to
// defaults.
func LoadConfig(path string) (Config, error) {
	content, err := readBoundedFile(path, maxConfigFileSize)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	cfg, err := ParseConfig(content)
	if err != nil {
		return Config{}, err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("resolve config path: %w", err)
	}
	cfg.resolvePaths(filepath.Dir(absPath))
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ParseConfig decodes TOML on top of DefaultConfig without resolving paths
// or validating. Most callers want LoadConfig.
func ParseConfig(content []byte) (Config, error) {
	cfg := DefaultConfig()
	dec := toml.NewDecoder(bytes.NewReader(content)).DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, describeTOMLError(err)
	}
	return cfg, nil
}

// describeTOMLError adds position and key details that go-toml keeps out of
// its short Error() strings.
func describeTOMLError(err error) error {
	var strict *toml.StrictMissingError
	if errors.As(err, &strict) {
		keys := make([]string, 0, len(strict.Errors))
		for _, e := range strict.Errors {
			keys = append(keys, strings.Join(e.Key(), "."))
		}
		return fmt.Errorf("parse config: unknown keys: %s", strings.Join(keys, ", "))
	}
	var decodeErr *toml.DecodeError
	if errors.As(err, &decodeErr) {
		row, col := decodeErr.Position()
		return fmt.Errorf("parse config: line %d, column %d: %s", row, col, decodeErr.Error())
	}
	return fmt.Errorf("parse config: %w", err)
}

// resolvePaths makes relative TLS file paths relative to baseDir. This keeps
// a data directory self-contained regardless of the working directory the
// server is started from (a Windows service starts in System32).
func (c *Config) resolvePaths(baseDir string) {
	c.TLSCert = resolveAgainst(baseDir, c.TLSCert)
	c.TLSKey = resolveAgainst(baseDir, c.TLSKey)
}

func resolveAgainst(baseDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

// Validate reports the first invalid field, if any.
func (c Config) Validate() error {
	if err := validateListen(c.Listen); err != nil {
		return err
	}
	if c.TLSCert == "" {
		return errors.New("config: tls_cert must not be empty")
	}
	if c.TLSKey == "" {
		return errors.New("config: tls_key must not be empty")
	}
	if err := c.Limits.validate(); err != nil {
		return err
	}
	if _, err := c.Log.SlogLevel(); err != nil {
		return err
	}
	return nil
}

func validateListen(listen string) error {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("config: %s must be host:port: %w", configFieldListen, err)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("config: %s has an invalid port", configFieldListen)
	}
	return nil
}

func (l Limits) validate() error {
	switch {
	case l.MaxConnections < 1 || l.MaxConnections > maxConnectionsLimit:
		return fmt.Errorf("config: limits.max_connections must be between 1 and %d", maxConnectionsLimit)
	case l.MaxConnectionsPerIP < 1 || l.MaxConnectionsPerIP > l.MaxConnections:
		return errors.New("config: limits.max_connections_per_ip must be between 1 and limits.max_connections")
	case l.MaxFrameSize < minFrameSize || l.MaxFrameSize > protocol.MaxFrameSize:
		return fmt.Errorf("config: limits.max_frame_size must be between %d and %d", minFrameSize, protocol.MaxFrameSize)
	case math.IsNaN(l.FramesPerSecond) || l.FramesPerSecond <= 0 || l.FramesPerSecond > maxFramesPerSecond:
		return fmt.Errorf("config: limits.frames_per_second must be greater than 0 and at most %d", maxFramesPerSecond)
	case l.Burst < 1 || l.Burst > maxBurst:
		return fmt.Errorf("config: limits.burst must be between 1 and %d", maxBurst)
	case l.HandshakeTimeout.Std() <= 0 || l.HandshakeTimeout.Std() > maxHandshakeTimeout:
		return fmt.Errorf("config: limits.handshake_timeout must be greater than 0 and at most %s", maxHandshakeTimeout)
	}
	return validatePingInterval(l.PingInterval.Std())
}

func validatePingInterval(d time.Duration) error {
	maxInterval := protocol.MaxPingInterval * time.Second
	if d < minPingInterval || d > maxInterval {
		return fmt.Errorf("config: %s must be between %s and %s", configFieldPingPeriod, minPingInterval, maxInterval)
	}
	if d%time.Second != 0 {
		return fmt.Errorf("config: %s must be a whole number of seconds", configFieldPingPeriod)
	}
	return nil
}

// SlogLevel returns the slog level named by Level.
func (l LogConfig) SlogLevel() (slog.Level, error) {
	switch l.Level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, errors.New("config: log.level must be one of debug, info, warn, error")
	}
}

// idleTimeout is how long a session may stay silent before it is closed:
// two missed keepalives plus slack for network delay.
func (l Limits) idleTimeout() time.Duration {
	return 2*l.PingInterval.Std() + 10*time.Second
}

// WriteTOML writes c as a commented TOML document, suitable for a new
// configuration file.
func (c Config) WriteTOML(w io.Writer) error {
	enc := toml.NewEncoder(w).SetIndentTables(false)
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return nil
}

// readBoundedFile reads at most limit bytes and fails if the file is
// larger, so a wrong path (a device, a huge file) cannot exhaust memory.
func readBoundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("file larger than %d bytes", limit)
	}
	return content, nil
}
