package clientdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Errors returned by the package. Callers compare with errors.Is.
var (
	// ErrWrongKey means the database key does not match the one the file was
	// created with.
	ErrWrongKey = errors.New("clientdb: wrong database key")
	// ErrCorrupt means a stored value failed authentication or decoding,
	// typically because the file was modified outside this package.
	ErrCorrupt = errors.New("clientdb: stored record is corrupt or was tampered with")
	// ErrNotFound means the requested row does not exist.
	ErrNotFound = errors.New("clientdb: not found")
	// ErrDuplicate means a message with the same (Peer, MsgID) already exists.
	ErrDuplicate = errors.New("clientdb: duplicate message")
	// ErrInvalid means an argument failed validation.
	ErrInvalid = errors.New("clientdb: invalid argument")
	// ErrClosed means the database has been closed.
	ErrClosed = errors.New("clientdb: database is closed")
	// ErrMissing means OpenExisting found no database file, or a file that
	// holds no qchat database (for example an empty file).
	ErrMissing = errors.New("clientdb: database does not exist")
)

const (
	tableMeta     = "meta"
	tableContacts = "contacts"
	tableMessages = "messages"
	tableSettings = "settings"
	tableSeen     = "seen"
	tableSessions = "sessions"
	tablePrekeys  = "prekeys"

	metaCanary = "canary"

	busyTimeoutMillis = 5000
)

// migrations are applied in order; migration i brings the schema to version
// i+1. Existing entries must never be edited.
var migrations = []string{
	`CREATE TABLE meta (
		name  TEXT PRIMARY KEY,
		value BLOB NOT NULL
	) STRICT;
	CREATE TABLE contacts (
		lookup BLOB PRIMARY KEY,
		value  BLOB NOT NULL
	) STRICT, WITHOUT ROWID;
	CREATE TABLE messages (
		seq    INTEGER PRIMARY KEY AUTOINCREMENT,
		peer   BLOB NOT NULL,
		lookup BLOB NOT NULL UNIQUE,
		value  BLOB NOT NULL
	) STRICT;
	CREATE INDEX messages_peer_seq ON messages (peer, seq);
	CREATE TABLE settings (
		lookup BLOB PRIMARY KEY,
		value  BLOB NOT NULL
	) STRICT, WITHOUT ROWID;`,
	`CREATE TABLE seen (
		lookup BLOB PRIMARY KEY
	) STRICT, WITHOUT ROWID;
	INSERT INTO seen (lookup) SELECT lookup FROM messages;`,
	`CREATE TABLE sessions (
		lookup BLOB PRIMARY KEY,
		value  BLOB NOT NULL
	) STRICT;
	CREATE TABLE prekeys (
		lookup BLOB PRIMARY KEY,
		value  BLOB NOT NULL
	) STRICT;`,
}

// DB is an open client database. It is safe for concurrent use.
type DB struct {
	mu     sync.RWMutex
	closed bool
	conn   *sql.DB
	keys   *keys
}

// Open opens or creates the database at path, protected by key. A new file is
// initialized with the current schema and a canary row; an existing file is
// migrated and its canary checked, returning ErrWrongKey on mismatch.
//
// Open silently creates an empty database when the file is missing. Callers
// that expect an existing database, such as unlocking a profile, must use
// [OpenExisting] instead, so that a lost or moved file is reported rather
// than replaced by an empty one.
func Open(path string, key [32]byte) (*DB, error) {
	return open(path, key, false)
}

// OpenExisting is like [Open] but never creates a database. It returns
// ErrMissing if path does not exist or holds no qchat database (an empty or
// uninitialized SQLite file), and leaves the file system unchanged in that
// case, apart from an empty file SQLite may already have found there.
func OpenExisting(path string, key [32]byte) (*DB, error) {
	return open(path, key, true)
}

func open(path string, key [32]byte, mustExist bool) (*DB, error) {
	if path == "" || strings.ContainsRune(path, '?') || strings.HasPrefix(path, "file:") || path == ":memory:" {
		return nil, fmt.Errorf("%w: unsupported database path %q", ErrInvalid, path)
	}
	if mustExist {
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrMissing, path)
		}
	}
	if err := prepareFile(path, !mustExist); err != nil {
		return nil, err
	}
	k, err := deriveKeys(key)
	if err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=secure_delete(ON)&_pragma=foreign_keys(ON)&_pragma=synchronous(FULL)&_txlock=immediate",
		path, busyTimeoutMillis)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		k.wipe()
		return nil, fmt.Errorf("clientdb: open: %w", err)
	}
	conn.SetMaxOpenConns(1)
	d := &DB{conn: conn, keys: k}
	if err := d.init(context.Background(), mustExist); err != nil {
		conn.Close()
		k.wipe()
		return nil, err
	}
	return d, nil
}

// init applies pending migrations, writes the canary into a new database and
// verifies it. With mustExist, an uninitialized database is not initialized
// but reported as ErrMissing.
func (d *DB) init(ctx context.Context, mustExist bool) error {
	if err := d.conn.PingContext(ctx); err != nil {
		return fmt.Errorf("clientdb: open: %w", err)
	}
	err := d.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY) STRICT`); err != nil {
			return err
		}
		var version int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
			return err
		}
		if version == 0 && mustExist {
			return ErrMissing
		}
		if version > len(migrations) {
			return fmt.Errorf("clientdb: database schema version %d is newer than supported version %d", version, len(migrations))
		}
		for v := version; v < len(migrations); v++ {
			if _, err := tx.ExecContext(ctx, migrations[v]); err != nil {
				return fmt.Errorf("clientdb: migration %d: %w", v+1, err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (?)`, v+1); err != nil {
				return err
			}
		}
		if version == 0 {
			return d.writeCanary(ctx, tx)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return d.checkCanary(ctx)
}

func (d *DB) writeCanary(ctx context.Context, tx *sql.Tx) error {
	plain, err := encode(canaryRecord{Magic: canaryMagic})
	if err != nil {
		return err
	}
	sealed, err := d.keys.seal(plain, rowAAD(tableMeta, []byte(metaCanary), -1))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO meta (name, value) VALUES (?, ?)`, metaCanary, sealed)
	return err
}

func (d *DB) checkCanary(ctx context.Context) error {
	var sealed []byte
	err := d.conn.QueryRowContext(ctx, `SELECT value FROM meta WHERE name = ?`, metaCanary).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: canary row missing", ErrCorrupt)
	}
	if err != nil {
		return fmt.Errorf("clientdb: read canary: %w", err)
	}
	plain, err := d.keys.open(sealed, rowAAD(tableMeta, []byte(metaCanary), -1))
	if err != nil {
		return ErrWrongKey
	}
	var rec canaryRecord
	if err := decode(plain, &rec); err != nil {
		return err
	}
	if rec.Magic != canaryMagic {
		return fmt.Errorf("%w: unexpected canary", ErrCorrupt)
	}
	return nil
}

// Close checkpoints the WAL, closes the database and clears the derived keys.
// It is safe to call more than once.
func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	_, ckErr := d.conn.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	err := d.conn.Close()
	d.keys.wipe()
	if err != nil {
		return fmt.Errorf("clientdb: close: %w", err)
	}
	if ckErr != nil {
		return fmt.Errorf("clientdb: checkpoint: %w", ckErr)
	}
	return nil
}

// acquire takes the read side of the close lock. On success the caller must
// call d.mu.RUnlock.
func (d *DB) acquire() error {
	d.mu.RLock()
	if d.closed {
		d.mu.RUnlock()
		return ErrClosed
	}
	return nil
}

// withTx runs fn in a write transaction, committing on success. The caller
// holds the close lock.
func (d *DB) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("clientdb: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("clientdb: commit: %w", err)
	}
	return nil
}

// isUniqueViolation reports whether err is a SQLite uniqueness constraint
// failure.
func isUniqueViolation(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	return se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}
