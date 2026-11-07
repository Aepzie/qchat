package serverdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Errors returned by DB methods. Callers compare them with errors.Is.
var (
	// ErrNotFound reports that no identity with the requested ID exists.
	ErrNotFound = errors.New("serverdb: not found")
	// ErrConflict reports that an identity with the same ID but a different
	// bundle and a serial that is not higher is already stored.
	ErrConflict = errors.New("serverdb: conflicting identity")
	// ErrInviteInvalid reports an unknown, malformed, expired or used-up
	// invite code. The cases are deliberately indistinguishable.
	ErrInviteInvalid = errors.New("serverdb: invalid invite code")
	// ErrInvalidArgument reports a parameter outside its documented range.
	ErrInvalidArgument = errors.New("serverdb: invalid argument")
	// ErrSchemaTooNew reports a database written by a newer version of the
	// server, whose schema this version does not know.
	ErrSchemaTooNew = errors.New("serverdb: database schema is newer than this server supports")
)

// busyTimeout is how long a statement waits for a lock held by another
// connection before failing with SQLITE_BUSY.
const busyTimeout = 5 * time.Second

// Retry policy for switching a new database to WAL mode. SQLite reports
// SQLITE_BUSY at once, without consulting the busy timeout, when another
// connection holds a lock it cannot wait for, which happens when several
// processes open a brand-new database at the same time. The first attempt
// waits journalRetryBase, every further one twice as long up to
// journalRetryMax, for at most journalAttempts attempts (about 3 seconds).
const (
	journalAttempts  = 12
	journalRetryBase = 5 * time.Millisecond
	journalRetryMax  = 500 * time.Millisecond
)

// sqliteCodeBusy and sqliteCodeLocked are the primary SQLite result codes
// SQLITE_BUSY and SQLITE_LOCKED.
const (
	sqliteCodeBusy   = 5
	sqliteCodeLocked = 6
)

// DB is an open relay database. It is safe for concurrent use.
type DB struct {
	sql *sql.DB
	now func() time.Time
}

// Open opens the database at path, creating it if it does not exist, and
// applies any missing schema migrations. The directory must exist.
func Open(path string) (*DB, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("%w: database path %q", ErrInvalidArgument, path)
	}
	if err := prepareFile(path); err != nil {
		return nil, fmt.Errorf("serverdb: prepare %s: %w", path, err)
	}
	conn, err := sql.Open("sqlite", path+"?"+dsnOptions())
	if err != nil {
		return nil, fmt.Errorf("serverdb: open %s: %w", path, err)
	}
	db := &DB{sql: conn, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 2*busyTimeout)
	defer cancel()
	if err := db.checkJournalModeWithRetry(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := migrate(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return db, nil
}

// dsnOptions returns the driver options applied to every connection of the
// pool. The path is passed without the "file:" prefix, so it is not parsed
// as a URI and needs no escaping.
func dsnOptions() string {
	pragmas := []string{
		fmt.Sprintf("busy_timeout(%d)", busyTimeout.Milliseconds()),
		"foreign_keys(1)",
		"journal_mode(WAL)",
		"secure_delete(1)",
		"synchronous(FULL)",
	}
	options := make([]string, 0, len(pragmas)+1)
	for _, pragma := range pragmas {
		options = append(options, "_pragma="+pragma)
	}
	options = append(options, "_txlock=immediate")
	return strings.Join(options, "&")
}

// prepareFile refuses a path that exists but is not a regular file, and
// applies the platform's file protection (see restrictFile).
func prepareFile(path string) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case !info.Mode().IsRegular():
		return errors.New("not a regular file")
	}
	return restrictFile(path)
}

// checkJournalModeWithRetry runs checkJournalMode, retrying with
// exponential backoff while the database is busy or locked. A connection
// whose setup failed is discarded by the pool, so each attempt opens a
// fresh one and applies every pragma again.
func (db *DB) checkJournalModeWithRetry(ctx context.Context) error {
	delay := journalRetryBase
	for attempt := 1; ; attempt++ {
		err := db.checkJournalMode(ctx)
		if err == nil || attempt == journalAttempts || !isBusy(err) {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
		delay = min(2*delay, journalRetryMax)
	}
}

// isBusy reports whether err is an SQLITE_BUSY or SQLITE_LOCKED error,
// including their extended codes.
func isBusy(err error) bool {
	var coded interface{ Code() int }
	if !errors.As(err, &coded) {
		return false
	}
	primary := coded.Code() & 0xff
	return primary == sqliteCodeBusy || primary == sqliteCodeLocked
}

// checkJournalMode verifies that the database really is in WAL mode, which
// SQLite silently refuses on some file systems.
func (db *DB) checkJournalMode(ctx context.Context) error {
	var mode string
	if err := db.sql.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return fmt.Errorf("serverdb: read journal mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("serverdb: journal mode is %q, want wal", mode)
	}
	return nil
}

// Close checkpoints the write-ahead log into the main file, truncating the
// -wal file, and closes the database.
func (db *DB) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*busyTimeout)
	defer cancel()
	_, checkpointErr := db.sql.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	closeErr := db.sql.Close()
	if closeErr != nil {
		return fmt.Errorf("serverdb: close: %w", closeErr)
	}
	if checkpointErr != nil {
		return fmt.Errorf("serverdb: checkpoint: %w", checkpointErr)
	}
	return nil
}

// withTx runs fn in a write transaction (BEGIN IMMEDIATE) and commits it if
// fn returns nil. Any error rolls the transaction back.
func (db *DB) withTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit: %w", err)
	}
	return nil
}
