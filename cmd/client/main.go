// Command qchat is the qchat terminal client.
//
// Usage:
//
//	qchat --server host:port --pin sha256:<64 hex digits> [--profile DIR] [--invite CODE]
//	qchat --version
//
// On first start qchat creates a profile (identity keys and an encrypted
// local database) in DIR, by default the per-user directory reported by
// profile.DefaultDir, and asks for a display name and a passphrase. Later
// starts ask for the passphrase. Relays that restrict registration need an
// invite code from their operator once, passed with --invite.
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
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
}

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
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: qchat --server host:port --pin sha256:<fingerprint> [--profile DIR] [--invite CODE]")
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
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "server":
			o.serverSet = true
		case "pin":
			o.pinSet = true
		}
	})
	return o, nil
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
// are an error, never an override.
func resolveTarget(emb embedded, o options) (target, error) {
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
	p, err := openProfile(dir)
	if err != nil {
		fmt.Fprintln(stderr, "qchat:", err)
		return 1
	}
	if p == nil {
		return 0
	}
	defer p.Close()
	return runInterface(t, p, o.invite, stderr)
}

// openProfile creates the profile in dir on first start and unlocks it
// otherwise, each with its own full-screen form. It returns nil and no
// error when the user cancels.
func openProfile(dir string) (*profile.Profile, error) {
	if !profile.Exists(dir) {
		return createProfile(dir)
	}
	var unlocked *profile.Profile
	model := tui.NewUnlock(tui.UnlockConfig{
		Hint:         dir,
		QuitWhenDone: true,
		Unlock: func(passphrase []byte) error {
			p, err := profile.Unlock(dir, passphrase)
			if errors.Is(err, profile.ErrWrongPassphrase) {
				return tui.ErrWrongPassphrase
			}
			if err != nil {
				return err
			}
			unlocked = p
			return nil
		},
	})
	if _, err := tea.NewProgram(model).Run(); err != nil {
		if unlocked != nil {
			unlocked.Close()
		}
		return nil, err
	}
	return unlocked, nil
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
	sess, err := client.New(client.Options{Addr: t.addr, Pin: t.pin, Auth: backend.Authenticator()})
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
		fmt.Fprintln(stderr, "qchat: SECURITY ALERT: the server's public key does not match the pinned fingerprint.")
		fmt.Fprintln(stderr, "  expected: ", mismatch.Expected.Grouped())
		fmt.Fprintln(stderr, "  presented:", mismatch.Presented.Grouped())
		fmt.Fprintln(stderr, "  qchat did not connect. Verify the fingerprint with the server operator over a channel you trust.")
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
