// Command qchat-server runs the qchat relay server.
//
// Usage:
//
//	qchat-server init --data-dir DIR [--host NAME]... [--listen ADDR] [--service-account NAME] [--force]
//	qchat-server run --config FILE
//	qchat-server fingerprint (--config FILE | --data-dir DIR)
//	qchat-server version
//
// "init" creates a data directory holding a fresh server identity
// (server.key, server.crt) and a configuration file (server.toml). "run"
// starts the server; on Windows it also runs as a service (see
// deploy/windows/README.md). "fingerprint" prints the public key
// fingerprint that clients pin.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// version is the release version, set at build time with
// -ldflags "-X main.version=v0.1.0".
var version = "dev"

// programName is used in messages and as the Windows service name.
const programName = "qchat-server"

// errUsage marks a command-line mistake whose explanation has already been
// printed; it maps to exit status 2.
var errUsage = errors.New("usage error")

const usageText = `Usage: qchat-server <command> [flags]

Commands:
  init          create a data directory with a new server identity and config
  run           run the server
  fingerprint   print the server public key fingerprint that clients pin
  version       print the version
  help          show this help

Planned (not available yet):
  invite        create invitations for new users
  build-client  build a client with this server's address and fingerprint embedded

Run "qchat-server <command> -h" for the flags of a command.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command line args and returns the process exit status:
// 0 on success, 1 on failure, 2 on a usage error.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	var err error
	switch cmd, rest := args[0], args[1:]; cmd {
	case "init":
		err = cmdInit(rest, stdout, stderr)
	case "run":
		err = cmdRun(rest, stderr)
	case "fingerprint":
		err = cmdFingerprint(rest, stdout, stderr)
	case "version":
		err = cmdVersion(rest, stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stderr, usageText)
		return 2
	default:
		fmt.Fprintf(stderr, "%s: unknown command %q\n\n%s", programName, cmd, usageText)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		return 2
	default:
		fmt.Fprintf(stderr, "%s: %v\n", programName, err)
		return 1
	}
}

// newFlagSet returns a FlagSet whose errors and usage go to stderr.
func newFlagSet(name, synopsis string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(programName+" "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s %s %s\n\nFlags:\n", programName, name, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags parses args and rejects positional arguments. Any error has
// already been reported to the user.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() > 0 {
		return usagef(fs, "unexpected argument %q", fs.Arg(0))
	}
	return nil
}

// usagef prints a message and the command usage, and returns errUsage.
func usagef(fs *flag.FlagSet, format string, args ...any) error {
	fmt.Fprintf(fs.Output(), "%s: %s\n", fs.Name(), fmt.Sprintf(format, args...))
	fs.Usage()
	return errUsage
}

func cmdVersion(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("version", "", stderr)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s %s\n", programName, version)
	return nil
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}
