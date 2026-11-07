// Command qchat is the qchat terminal client.
//
// Usage:
//
//	qchat --server host:port --pin sha256:<64 hex digits>
//	qchat --version
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

	"github.com/craguS/qchat/internal/buildcfg"
	"github.com/craguS/qchat/internal/client"
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
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: qchat --server host:port --pin sha256:<fingerprint>")
		fmt.Fprintln(stderr, "       qchat --version")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
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
		if o.serverSet && o.server != emb.addr {
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
	if err := buildcfg.ValidateAddr(o.server); err != nil {
		return target{}, fmt.Errorf("--server: %w", err)
	}
	pin, err := transport.ParseFingerprint(o.pin)
	if err != nil {
		return target{}, fmt.Errorf("--pin: %w", err)
	}
	return target{addr: o.server, pin: pin}, nil
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
	return runInterface(t, stderr)
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
func runInterface(t target, stderr io.Writer) int {
	sess, err := client.New(client.Options{Addr: t.addr, Pin: t.pin})
	if err != nil {
		fmt.Fprintln(stderr, "qchat:", err)
		return 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sessionDone := make(chan error, 1)
	go func() { sessionDone <- sess.Run(ctx) }()

	model := tui.New(tui.Config{
		Addr:    t.addr,
		Pin:     t.pin,
		Events:  sess.Events(),
		Version: version,
	})
	_, uiErr := tea.NewProgram(model).Run()
	cancel()

	var sessionErr error
	select {
	case sessionErr = <-sessionDone:
	case <-time.After(shutdownGrace):
	}

	var mismatch *transport.PinMismatchError
	if errors.As(sessionErr, &mismatch) {
		fmt.Fprintln(stderr, "qchat: SECURITY ALERT: the server's public key does not match the pinned fingerprint.")
		fmt.Fprintln(stderr, "  expected: ", mismatch.Expected.Grouped())
		fmt.Fprintln(stderr, "  presented:", mismatch.Presented.Grouped())
		fmt.Fprintln(stderr, "  qchat did not connect. Verify the fingerprint with the server operator over a channel you trust.")
		return 3
	}
	if uiErr != nil && !errors.Is(uiErr, tea.ErrInterrupted) {
		fmt.Fprintln(stderr, "qchat:", uiErr)
		return 1
	}
	return 0
}
