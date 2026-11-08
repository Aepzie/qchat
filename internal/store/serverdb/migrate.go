package serverdb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
)

// migrations holds the schema changes in order; migrations[i] brings the
// schema to version i+1. Released entries must never change: add a new
// entry instead.
var migrations = []string{
	`CREATE TABLE identities (
		id     BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 32),
		bundle BLOB    NOT NULL CHECK (length(bundle) > 0),
		serial INTEGER NOT NULL
	) STRICT, WITHOUT ROWID;
	CREATE TABLE invites (
		code_hash  BLOB    NOT NULL PRIMARY KEY CHECK (length(code_hash) = 32),
		expires_at INTEGER NOT NULL,
		uses_left  INTEGER NOT NULL CHECK (uses_left >= 0)
	) STRICT, WITHOUT ROWID;
	CREATE INDEX invites_expires_at ON invites (expires_at);`,
	`CREATE TABLE signed_prekeys (
		id      BLOB    NOT NULL PRIMARY KEY REFERENCES identities (id) ON DELETE CASCADE,
		prekey  BLOB    NOT NULL CHECK (length(prekey) > 0),
		key_id  INTEGER NOT NULL,
		expires INTEGER NOT NULL
	) STRICT, WITHOUT ROWID;
	CREATE TABLE one_time_prekeys (
		id     BLOB    NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
		key_id INTEGER NOT NULL,
		prekey BLOB    NOT NULL CHECK (length(prekey) > 0),
		PRIMARY KEY (id, key_id)
	) STRICT;
	CREATE TABLE queue (
		qid       INTEGER PRIMARY KEY AUTOINCREMENT,
		recipient BLOB    NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
		sender    BLOB    NOT NULL CHECK (length(sender) = 32),
		payload   BLOB    NOT NULL CHECK (length(payload) > 0),
		size      INTEGER NOT NULL CHECK (size = length(payload)),
		expires   INTEGER NOT NULL
	) STRICT;
	CREATE INDEX queue_recipient_qid ON queue (recipient, qid);
	CREATE INDEX queue_expires ON queue (expires);`,
	`CREATE TABLE queue_payloads (
		pid     INTEGER PRIMARY KEY,
		payload BLOB    NOT NULL CHECK (length(payload) > 0),
		size    INTEGER NOT NULL CHECK (size = length(payload)),
		refs    INTEGER NOT NULL CHECK (refs > 0)
	) STRICT;
	CREATE TABLE queue_v3 (
		qid       INTEGER PRIMARY KEY AUTOINCREMENT,
		recipient BLOB    NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
		sender    BLOB    NOT NULL CHECK (length(sender) = 32),
		pid       INTEGER NOT NULL REFERENCES queue_payloads (pid),
		size      INTEGER NOT NULL CHECK (size > 0),
		expires   INTEGER NOT NULL
	) STRICT;
	INSERT INTO queue_payloads (pid, payload, size, refs)
		SELECT qid, payload, size, 1 FROM queue;
	INSERT INTO queue_v3 (qid, recipient, sender, pid, size, expires)
		SELECT qid, recipient, sender, qid, size, expires FROM queue;
	DELETE FROM sqlite_sequence WHERE name = 'queue_v3';
	INSERT INTO sqlite_sequence (name, seq)
		SELECT 'queue_v3', seq FROM sqlite_sequence WHERE name = 'queue';
	DROP TABLE queue;
	ALTER TABLE queue_v3 RENAME TO queue;
	CREATE INDEX queue_recipient_qid ON queue (recipient, qid);
	CREATE INDEX queue_expires ON queue (expires);
	CREATE INDEX queue_pid ON queue (pid);
	CREATE TRIGGER queue_release_payload AFTER DELETE ON queue BEGIN
		DELETE FROM queue_payloads WHERE pid = OLD.pid AND refs = 1;
		UPDATE queue_payloads SET refs = refs - 1 WHERE pid = OLD.pid;
	END;`,
	`DROP TRIGGER queue_release_payload;
	CREATE TABLE queue_v4 (
		qid       INTEGER PRIMARY KEY AUTOINCREMENT,
		recipient BLOB    NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
		sender    BLOB    CHECK (sender IS NULL OR length(sender) = 32),
		pid       INTEGER NOT NULL REFERENCES queue_payloads (pid),
		size      INTEGER NOT NULL CHECK (size > 0),
		expires   INTEGER NOT NULL
	) STRICT;
	INSERT INTO queue_v4 (qid, recipient, sender, pid, size, expires)
		SELECT qid, recipient, sender, pid, size, expires FROM queue;
	DELETE FROM sqlite_sequence WHERE name = 'queue_v4';
	INSERT INTO sqlite_sequence (name, seq)
		SELECT 'queue_v4', seq FROM sqlite_sequence WHERE name = 'queue';
	DROP TABLE queue;
	ALTER TABLE queue_v4 RENAME TO queue;
	CREATE INDEX queue_recipient_qid ON queue (recipient, qid);
	CREATE INDEX queue_expires ON queue (expires);
	CREATE INDEX queue_pid ON queue (pid);
	CREATE TRIGGER queue_release_payload AFTER DELETE ON queue BEGIN
		DELETE FROM queue_payloads WHERE pid = OLD.pid AND refs = 1;
		UPDATE queue_payloads SET refs = refs - 1 WHERE pid = OLD.pid;
	END;
	CREATE TABLE access_keys (
		id                 BLOB    NOT NULL PRIMARY KEY REFERENCES identities (id) ON DELETE CASCADE,
		verifier           BLOB    NOT NULL CHECK (length(verifier) = 32),
		allow_unidentified INTEGER NOT NULL CHECK (allow_unidentified IN (0, 1))
	) STRICT, WITHOUT ROWID;`,
	`DELETE FROM access_keys WHERE verifier = zeroblob(32);
	ALTER TABLE access_keys RENAME COLUMN verifier TO verifier_hash;`,
}

// migrationSteps holds the parts of migrations that SQL alone cannot
// express, keyed by schema version. A step runs in the migration
// transaction right after the SQL of its version.
var migrationSteps = map[int]func(context.Context, *sql.Tx) error{
	5: hashAccessVerifiers,
}

// hashAccessVerifiers replaces every stored access verifier by its SHA-256
// hash, so that the database no longer holds the bearer proofs.
func hashAccessVerifiers(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "SELECT id, verifier_hash FROM access_keys")
	if err != nil {
		return fmt.Errorf("read access keys: %w", err)
	}
	type storedRow struct{ id, verifier []byte }
	var stored []storedRow
	for rows.Next() {
		var r storedRow
		if err := rows.Scan(&r.id, &r.verifier); err != nil {
			rows.Close()
			return fmt.Errorf("read access keys: %w", err)
		}
		stored = append(stored, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read access keys: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("read access keys: %w", err)
	}
	for _, r := range stored {
		hash := sha256.Sum256(r.verifier)
		if _, err := tx.ExecContext(ctx, "UPDATE access_keys SET verifier_hash = ? WHERE id = ?", hash[:], r.id); err != nil {
			return fmt.Errorf("hash access key: %w", err)
		}
	}
	return nil
}

// migrate applies the missing migrations in one write transaction, so
// concurrent Opens of the same file cannot apply a migration twice.
func migrate(ctx context.Context, conn *sql.DB) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER NOT NULL PRIMARY KEY
	) STRICT`); err != nil {
		return fmt.Errorf("serverdb: create schema_migrations: %w", err)
	}
	var current int
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(version), 0) FROM schema_migrations").Scan(&current); err != nil {
		return fmt.Errorf("serverdb: read schema version: %w", err)
	}
	if current > len(migrations) {
		return fmt.Errorf("%w (database version %d, supported %d)", ErrSchemaTooNew, current, len(migrations))
	}
	for version := current + 1; version <= len(migrations); version++ {
		if _, err := tx.ExecContext(ctx, migrations[version-1]); err != nil {
			return fmt.Errorf("serverdb: migration %d: %w", version, err)
		}
		if step, ok := migrationSteps[version]; ok {
			if err := step(ctx, tx); err != nil {
				return fmt.Errorf("serverdb: migration %d: %w", version, err)
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES (?)", version); err != nil {
			return fmt.Errorf("serverdb: record migration %d: %w", version, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit migration: %w", err)
	}
	return nil
}
