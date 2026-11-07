// Command qchat is the qchat terminal client.
//
// Usage:
//
//	qchat --server host:port --pin sha256:<64 hex digits> [--tor | --socks5 HOST:PORT] [--profile DIR] [--invite CODE] [--recover]
//	qchat --version
//
// --tor connects through the Tor SOCKS port at 127.0.0.1:9050; --socks5
// names another SOCKS5 proxy, for example Tor Browser's at 127.0.0.1:9150,
// and takes precedence over --tor's default address. With either flag every
// connection goes through the proxy, the server name is resolved by the
// proxy and never locally, and qchat never falls back to a direct
// connection: if the proxy is unreachable, qchat does not connect. Each run
// uses a fresh random SOCKS user name, so Tor keeps qchat's traffic on
// circuits of its own. .onion servers are reachable only this way.
//
// On first start qchat creates a profile (identity keys and an encrypted
// local database) in DIR, by default the per-user directory reported by
// profile.DefaultDir, and asks for a display name and a passphrase. Later
// starts ask for the passphrase. Relays that restrict registration need an
// invite code from their operator once, passed with --invite.
//
// If the profile's key file is intact but its database is gone, qchat
// explains what was lost and exits. Restoring the database from a backup
// keeps everything; otherwise --recover creates a new, empty database for
// the same identity, after looking up the bundle the relay holds for it so
// that the relay keeps accepting the identity. Contacts, verifications, the
// display name and message history are not recovered. --recover has no
// effect while the database exists.
//
// The pin is the SHA-256 fingerprint of the server's public key, obtained
// from the server operator over a channel you trust. The client refuses to
// talk to a server presenting any other key.
//
// Builds made with an embedded server (see package buildcfg) connect only to
// that server; --server and --pin may then be omitted, and values that differ
// from the embedded ones are rejected.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/craguS/qchat/internal/app"
	"github.com/craguS/qchat/internal/buildcfg"
	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/crypto/vault"
	"github.com/craguS/qchat/internal/profile"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/transport"
	"github.com/craguS/qchat/internal/tui"
)

// version is the client version. Release builds override it with
// -ldflags "-X main.version=...".
var version = "0.1.0-dev"

// shutdownGrace bounds how long the client waits for the session to close
// its connection after the interface exits.
const shutdownGrace = 3 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// options are the parsed command line flags.
type options struct {
	server, pin       string
	serverSet, pinSet bool
	showVersion       bool
	profileDir        string
	invite            string
	recoverDB         bool
	tor               bool
	socks5            string
	// proxy is the canonical address of the SOCKS5 proxy all connections
	// go through, empty for direct connections. It is derived from --tor
	// and --socks5.
	proxy string
}

// defaultTorProxy is the address of Tor's SOCKS port in the default
// configuration of the tor daemon.
const defaultTorProxy = "127.0.0.1:9050"

// parseFlags parses the command line. Flags may be written with one or two
// dashes.
func parseFlags(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("qchat", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.server, "server", "", "server address, host:port")
	fs.StringVar(&o.pin, "pin", "", "server public key fingerprint, sha256:<hex>")
	fs.BoolVar(&o.showVersion, "version", false, "print the version and exit")
	fs.StringVar(&o.profileDir, "profile", "", "profile directory (default: the per-user qchat directory)")
	fs.StringVar(&o.invite, "invite", "", "invite code for registering with the server")
	fs.BoolVar(&o.recoverDB, "recover", false, "if the local database is missing, create a new, empty one (contacts and history are lost)")
	fs.BoolVar(&o.tor, "tor", false, "connect through Tor at "+defaultTorProxy+"; never connect directly")
	fs.StringVar(&o.socks5, "socks5", "", "connect through the SOCKS5 proxy at HOST:PORT, e.g. Tor; never connect directly")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: qchat --server host:port --pin sha256:<fingerprint> [--tor | --socks5 HOST:PORT] [--profile DIR] [--invite CODE] [--recover]")
		fmt.Fprintln(stderr, "       qchat --version")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if err := validateInvite(o.invite); err != nil {
		return o, err
	}
	socks5Set := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "server":
			o.serverSet = true
		case "pin":
			o.pinSet = true
		case "socks5":
			socks5Set = true
		}
	})
	proxy, err := proxyAddress(o.tor, socks5Set, o.socks5)
	if err != nil {
		return o, err
	}
	o.proxy = proxy
	return o, nil
}

// proxyAddress returns the canonical address of the SOCKS5 proxy selected
// by --tor and --socks5, or "" for direct connections. An explicitly given
// --socks5 must be a valid host:port, even an empty one: silently falling
// back to a direct connection would defeat its purpose.
func proxyAddress(tor, socks5Set bool, socks5 string) (string, error) {
	if socks5Set {
		addr, err := transport.ValidateHostPort(socks5)
		if err != nil {
			return "", fmt.Errorf("--socks5: %w", err)
		}
		return addr, nil
	}
	if tor {
		return defaultTorProxy, nil
	}
	return "", nil
}

// validateInvite applies the protocol's limits for invite codes, so that a
// mistyped code is reported at once instead of by the relay.
func validateInvite(code string) error {
	if len(code) > protocol.MaxInviteLen {
		return fmt.Errorf("--invite: code is longer than %d characters", protocol.MaxInviteLen)
	}
	for i := 0; i < len(code); i++ {
		if code[i] < 0x21 || code[i] > 0x7e {
			return errors.New("--invite: code may contain printable ASCII characters only")
		}
	}
	return nil
}

// target is the server the client will connect to.
type target struct {
	addr   string
	pin    transport.Fingerprint
	locked bool
	// proxy is the SOCKS5 proxy every connection goes through, empty for
	// direct connections.
	proxy string
	// isolation is the SOCKS user name that keeps this run's connections
	// on Tor circuits of their own. It is set together with proxy.
	isolation string
}

// dialer returns the dial function for the client's sessions: nil for
// direct connections, otherwise one that only ever connects through the
// proxy.
func (t target) dialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if t.proxy == "" {
		return nil
	}
	return transport.SOCKS5Dialer(t.proxy, t.isolation)
}

// newIsolationToken returns a random SOCKS user name for one run of the
// client, so that Tor does not share circuits between runs or with other
// applications (IsolateSOCKSAuth).
func newIsolationToken() string {
	var token [16]byte
	rand.Read(token[:])
	return hex.EncodeToString(token[:])
}

// embedded is the result of buildcfg.Embedded.
type embedded struct {
	addr string
	pin  transport.Fingerprint
	ok   bool
	err  error
}

// resolveTarget combines the embedded configuration with the flags. An
// embedded server always wins: flags that name a different server or pin
// are an error, never an override. The proxy flags apply to every server,
// embedded or not.
func resolveTarget(emb embedded, o options) (target, error) {
	t, err := resolveServer(emb, o)
	if err != nil {
		return target{}, err
	}
	if o.proxy != "" {
		t.proxy = o.proxy
		t.isolation = newIsolationToken()
	}
	return t, nil
}

// resolveServer determines the server address and pin for resolveTarget.
func resolveServer(emb embedded, o options) (target, error) {
	if emb.err != nil {
		return target{}, fmt.Errorf("this build is misconfigured: %w", emb.err)
	}
	if emb.ok {
		if o.serverSet && !sameServer(o.server, emb.addr) {
			return target{}, fmt.Errorf("this client is locked to %s", emb.addr)
		}
		if o.pinSet {
			pin, err := transport.ParseFingerprint(o.pin)
			if err != nil || !pin.Equal(emb.pin) {
				return target{}, fmt.Errorf("this client is locked to %s", emb.addr)
			}
		}
		return target{addr: emb.addr, pin: emb.pin, locked: true}, nil
	}

	switch {
	case !o.serverSet && !o.pinSet:
		return target{}, errors.New("missing --server and --pin: both are required, e.g. qchat --server chat.example.org:443 --pin sha256:<fingerprint>")
	case !o.serverSet || o.server == "":
		return target{}, errors.New("missing --server host:port")
	case !o.pinSet || o.pin == "":
		return target{}, errors.New("missing --pin sha256:<fingerprint>; get it from the server operator over a channel you trust")
	}
	addr, err := transport.ValidateHostPort(o.server)
	if err != nil {
		return target{}, fmt.Errorf("--server: %w", err)
	}
	pin, err := transport.ParseFingerprint(o.pin)
	if err != nil {
		return target{}, fmt.Errorf("--pin: %w", err)
	}
	return target{addr: addr, pin: pin}, nil
}

// sameServer reports whether the user-supplied address flag names the
// embedded server, which is already in canonical form. Equivalent spellings
// such as a port with leading zeros match; anything invalid does not.
func sameServer(flagAddr, embeddedAddr string) bool {
	addr, err := transport.ValidateHostPort(flagAddr)
	return err == nil && addr == embeddedAddr
}

// run is main without the process exit, for testing. It returns the exit
// code: 0 on success, 1 on runtime failure, 2 on usage errors, 3 after a
// security alert.
func run(args []string, stdout, stderr io.Writer) int {
	o, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "qchat:", err)
		return 2
	}
	addr, pin, ok, embErr := buildcfg.Embedded()
	emb := embedded{addr: addr, pin: pin, ok: ok, err: embErr}
	if o.showVersion {
		fmt.Fprintln(stdout, versionLine(emb))
		return 0
	}
	t, err := resolveTarget(emb, o)
	if err != nil {
		fmt.Fprintln(stderr, "qchat:", err)
		return 2
	}
	dir := o.profileDir
	if dir == "" {
		if dir, err = profile.DefaultDir(); err != nil {
			fmt.Fprintln(stderr, "qchat: no profile directory; pass --profile DIR:", err)
			return 2
		}
	}
	opened, err := openProfile(dir, o.recoverDB)
	defer clear(opened.passphrase)
	if err != nil {
		fmt.Fprintln(stderr, "qchat:", err)
		return 1
	}
	p := opened.profile
	if opened.dbMissing {
		if !o.recoverDB {
			fmt.Fprintln(stderr, databaseMissingHint(dir))
			return 1
		}
		if p, err = recoverProfile(t, dir, opened.passphrase); err != nil {
			var mismatch *transport.PinMismatchError
			if errors.As(err, &mismatch) {
				printPinMismatch(stderr, mismatch)
				return 3
			}
			fmt.Fprintln(stderr, "qchat: recovery failed:", err)
			return 1
		}
		fmt.Fprintln(stderr, recoveredNotice)
	}
	if p == nil {
		return 0
	}
	defer p.Close()
	return runInterface(t, p, o.invite, stderr)
}

// openedProfile is the result of openProfile.
type openedProfile struct {
	// profile is the created or unlocked profile, nil if the user
	// cancelled or the database is missing.
	profile *profile.Profile
	// dbMissing reports that the passphrase opened the key file but the
	// database does not exist (profile.ErrDatabaseMissing).
	dbMissing bool
	// passphrase is a copy of the verified passphrase, kept only when
	// dbMissing is set and recovery was requested. The caller zeroes it.
	passphrase []byte
}

// openProfile creates the profile in dir on first start and unlocks it
// otherwise, each with its own full-screen form. The profile is nil and the
// error nil when the user cancels. A missing database ends the unlock form
// with dbMissing set; keepPassphrase keeps a copy of the passphrase for
// recovery then.
func openProfile(dir string, keepPassphrase bool) (openedProfile, error) {
	if !profile.Exists(dir) {
		p, err := createProfile(dir)
		return openedProfile{profile: p}, err
	}
	var opened openedProfile
	model := tui.NewUnlock(tui.UnlockConfig{
		Hint:         dir,
		QuitWhenDone: true,
		Unlock: func(passphrase []byte) error {
			p, err := profile.Unlock(dir, passphrase)
			if errors.Is(err, profile.ErrWrongPassphrase) {
				return tui.ErrWrongPassphrase
			}
			if errors.Is(err, profile.ErrDatabaseMissing) {
				opened.dbMissing = true
				if keepPassphrase {
					opened.passphrase = bytes.Clone(passphrase)
				}
				return nil
			}
			if err != nil {
				return err
			}
			opened.profile = p
			return nil
		},
	})
	if _, err := tea.NewProgram(model).Run(); err != nil {
		if opened.profile != nil {
			opened.profile.Close()
		}
		clear(opened.passphrase)
		return openedProfile{}, err
	}
	return opened, nil
}

// createProfile asks for a display name and passphrase and creates the
// profile in dir. The passphrase buffer is zeroed afterwards.
func createProfile(dir string) (*profile.Profile, error) {
	final, err := tea.NewProgram(tui.NewCreateProfile(tui.CreateProfileConfig{QuitWhenDone: true})).Run()
	if err != nil {
		return nil, err
	}
	m, ok := final.(tui.CreateProfileModel)
	if !ok {
		return nil, errors.New("profile form ended unexpectedly")
	}
	submitted, done := m.Result()
	defer clear(submitted.Passphrase)
	if !done || m.Cancelled() {
		return nil, nil
	}
	return profile.Create(dir, submitted.Passphrase, submitted.DisplayName, vault.DefaultParams())
}

// registrationHint explains a refused registration and what to do next.
func registrationHint(denied client.RegistrationDenied, hadInvite bool) string {
	line := "qchat: the server refused to register your identity"
	if msg := client.SanitizeASCII(denied.Message, 200); msg != "" {
		line += " (" + msg + ")"
	}
	switch {
	case denied.Code == protocol.ErrCodeConflict:
		return line + ".\n  The server already knows this ID with a different key. Ask the server operator."
	case hadInvite:
		return line + ".\n  The invite code was not accepted; it may be mistyped, used up or expired. Ask the server operator for a new one."
	default:
		return line + ".\n  This server requires an invite code: ask its operator for one and start qchat with --invite CODE."
	}
}

// printPinMismatch reports a server whose key does not match the pin.
func printPinMismatch(stderr io.Writer, mismatch *transport.PinMismatchError) {
	fmt.Fprintln(stderr, "qchat: SECURITY ALERT: the server's public key does not match the pinned fingerprint.")
	fmt.Fprintln(stderr, "  expected: ", mismatch.Expected.Grouped())
	fmt.Fprintln(stderr, "  presented:", mismatch.Presented.Grouped())
	fmt.Fprintln(stderr, "  qchat did not connect. Verify the fingerprint with the server operator over a channel you trust.")
}

func versionLine(emb embedded) string {
	line := "qchat " + version
	if emb.ok {
		line += " (locked to " + emb.addr + ")"
	}
	return line
}

// runInterface starts the session and the terminal interface, and tears
// both down when the user quits.
func runInterface(t target, p *profile.Profile, invite string, stderr io.Writer) int {
	backend, err := app.New(p, invite)
	if err != nil {
		fmt.Fprintln(stderr, "qchat:", err)
		return 1
	}
	sess, err := client.New(client.Options{Addr: t.addr, Pin: t.pin, Dialer: t.dialer(), Auth: backend.Authenticator()})
	if err != nil {
		fmt.Fprintln(stderr, "qchat:", err)
		return 2
	}
	backend.UseSession(sess)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sessionDone := make(chan error, 1)
	go func() { sessionDone <- sess.Run(ctx) }()
	appDone := make(chan struct{})
	go func() {
		defer close(appDone)
		backend.Run(ctx, sess.Events())
	}()

	model := tui.New(tui.Config{
		Addr:       t.addr,
		Pin:        t.pin,
		Events:     backend.TUIEvents(),
		Backend:    backend,
		ChatEvents: backend.ChatEvents(),
		Tor:        t.proxy != "",
		Version:    version,
	})
	_, uiErr := tea.NewProgram(model).Run()
	cancel()

	var sessionErr error
	grace := time.After(shutdownGrace)
	select {
	case sessionErr = <-sessionDone:
	case <-grace:
	}
	select {
	case <-appDone:
	case <-grace:
	}

	var mismatch *transport.PinMismatchError
	if errors.As(sessionErr, &mismatch) {
		printPinMismatch(stderr, mismatch)
		return 3
	}
	if denied, ok := backend.RegistrationDenied(); ok {
		fmt.Fprintln(stderr, registrationHint(denied, invite != ""))
		return 1
	}
	if uiErr != nil && !errors.Is(uiErr, tea.ErrInterrupted) {
		fmt.Fprintln(stderr, "qchat:", uiErr)
		return 1
	}
	return 0
}
