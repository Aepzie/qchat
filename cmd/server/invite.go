package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/craguS/qchat/internal/server"
	"github.com/craguS/qchat/internal/store/serverdb"
)

// Defaults of "invite create".
const (
	defaultInviteUses   = 1
	defaultInviteTTLArg = "72h"
)

// inviteTimeLayout formats invite expiry times, always in UTC.
const inviteTimeLayout = "2006-01-02 15:04:05 UTC"

const inviteUsageText = `Usage: qchat-server invite <subcommand> [flags]

Subcommands:
  create   create an invite code for registering new identities
  list     list the stored invites (expiry and uses left; codes are never stored)
  prune    delete expired and used-up invites

Run "qchat-server invite <subcommand> -h" for the flags of a subcommand.
`

// cmdInvite dispatches the invite subcommands.
func cmdInvite(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, inviteUsageText)
		return errUsage
	}
	switch sub, rest := args[0], args[1:]; sub {
	case "create":
		return cmdInviteCreate(rest, stdout, stderr)
	case "list":
		return cmdInviteList(rest, stdout, stderr)
	case "prune":
		return cmdInvitePrune(rest, stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stderr, inviteUsageText)
		return errUsage
	default:
		fmt.Fprintf(stderr, "%s invite: unknown subcommand %q\n\n%s", programName, sub, inviteUsageText)
		return errUsage
	}
}

// cmdInviteCreate creates an invite and prints its code. The code is shown
// only here: the database keeps its hash only.
func cmdInviteCreate(args []string, stdout, stderr io.Writer) error {
	fset := newFlagSet("invite create", "[--config FILE] [--uses N] [--ttl DURATION]", stderr)
	configPath := fset.String("config", defaultConfigPath(), "path of server.toml")
	uses := fset.Int("uses", defaultInviteUses, fmt.Sprintf("number of identities the invite can register (1 to %d)", serverdb.MaxInviteUses))
	ttlText := fset.String("ttl", defaultInviteTTLArg, "validity, as a Go duration such as 90m or 72h, or whole days such as 7d (at most 30d)")
	if err := parseFlags(fset, args); err != nil {
		return err
	}
	ttl, err := parseInviteTTL(*ttlText)
	if err != nil {
		return usagef(fset, "--ttl: %v", err)
	}
	if *uses < 1 || *uses > serverdb.MaxInviteUses {
		return usagef(fset, "--uses must be between 1 and %d", serverdb.MaxInviteUses)
	}

	db, err := openConfiguredDatabase(*configPath)
	if err != nil {
		return err
	}
	defer db.Close()
	code, err := db.CreateInvite(context.Background(), ttl, *uses)
	if err != nil {
		return err
	}
	expires := time.Now().Add(ttl).UTC()

	fmt.Fprintf(stdout, "Invite code (shown only this once; only its hash is stored, so it cannot be displayed again):\n\n  %s\n\n", code)
	fmt.Fprintf(stdout, "Registers up to %d new %s until %s.\n", *uses, plural(*uses, "identity", "identities"), expires.Format(inviteTimeLayout))
	fmt.Fprintln(stdout, "Give it to the new user over a channel you trust; anyone holding it can register.")
	return nil
}

// cmdInviteList prints the expiry and remaining uses of every stored
// invite.
func cmdInviteList(args []string, stdout, stderr io.Writer) error {
	fset := newFlagSet("invite list", "[--config FILE]", stderr)
	configPath := fset.String("config", defaultConfigPath(), "path of server.toml")
	if err := parseFlags(fset, args); err != nil {
		return err
	}
	db, err := openConfiguredDatabase(*configPath)
	if err != nil {
		return err
	}
	defer db.Close()
	invites, err := db.ListInvites(context.Background())
	if err != nil {
		return err
	}
	if len(invites) == 0 {
		fmt.Fprintln(stdout, "No invites.")
		return nil
	}

	now := time.Now()
	expired := 0
	for _, invite := range invites {
		if invite.Expired(now) {
			expired++
		}
	}
	fmt.Fprintf(stdout, "%d %s, %d expired", len(invites), plural(len(invites), "invite", "invites"), expired)
	if expired > 0 {
		fmt.Fprintf(stdout, " (remove with \"%s invite prune\")", programName)
	}
	fmt.Fprint(stdout, ":\n\n")

	table := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "  EXPIRES\tUSES LEFT\tSTATUS")
	for _, invite := range invites {
		status := "valid"
		if invite.Expired(now) {
			status = "expired"
		}
		fmt.Fprintf(table, "  %s\t%d\t%s\n", invite.ExpiresAt.UTC().Format(inviteTimeLayout), invite.UsesLeft, status)
	}
	return table.Flush()
}

// cmdInvitePrune deletes expired and used-up invites.
func cmdInvitePrune(args []string, stdout, stderr io.Writer) error {
	fset := newFlagSet("invite prune", "[--config FILE]", stderr)
	configPath := fset.String("config", defaultConfigPath(), "path of server.toml")
	if err := parseFlags(fset, args); err != nil {
		return err
	}
	db, err := openConfiguredDatabase(*configPath)
	if err != nil {
		return err
	}
	defer db.Close()
	deleted, err := db.PruneExpiredInvites(context.Background(), time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Removed %d expired %s.\n", deleted, plural(int(deleted), "invite", "invites"))
	return nil
}

// openConfiguredDatabase opens the database named by the configuration
// file. It refuses to create a missing database: a new file outside the
// data directory would lack its protection, and invites stored in a
// database the server does not read would never work.
func openConfiguredDatabase(configPath string) (*serverdb.DB, error) {
	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(cfg.Database); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("database %s does not exist; check the database setting in %s, or run \"%s init\" to create a data directory", cfg.Database, configPath, programName)
	} else if err != nil {
		return nil, err
	}
	return serverdb.Open(cfg.Database)
}

// parseInviteTTL parses a Go duration or a whole number of days such as
// "7d", and checks the bounds of serverdb.CreateInvite.
func parseInviteTTL(text string) (time.Duration, error) {
	var ttl time.Duration
	if days, ok := strings.CutSuffix(text, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 1 || n > int(serverdb.MaxInviteTTL/(24*time.Hour)) {
			return 0, fmt.Errorf("invalid number of days %q", text)
		}
		ttl = time.Duration(n) * 24 * time.Hour
	} else {
		parsed, err := time.ParseDuration(text)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", text)
		}
		ttl = parsed
	}
	if ttl < time.Minute || ttl > serverdb.MaxInviteTTL {
		return 0, fmt.Errorf("must be between 1m and 30d, got %s", text)
	}
	return ttl, nil
}

// defaultConfigPath is the configuration file of the deployments described
// in deploy/: C:\ProgramData\qchat\server.toml on Windows and
// /etc/qchat/server.toml elsewhere.
func defaultConfigPath() string {
	if runtime.GOOS != "windows" {
		return "/etc/qchat/server.toml"
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "qchat", configFileName)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
