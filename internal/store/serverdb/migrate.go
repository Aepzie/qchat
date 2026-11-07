package serverdb

import (
	"context"
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
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES (?)", version); err != nil {
			return fmt.Errorf("serverdb: record migration %d: %w", version, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit migration: %w", err)
	}
	return nil
}
