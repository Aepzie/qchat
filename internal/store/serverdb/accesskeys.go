package serverdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// AccessKey is the sealed sender access setting of an identity.
type AccessKey struct {
	// Verifier is the verifier of the identity's access key, which sealed
	// senders present as their access proof.
	Verifier [32]byte
	// AllowUnidentified lets anyone send sealed messages to the identity.
	AllowUnidentified bool
}

// SetAccessKey stores key as the access setting of id, replacing any
// earlier one. It fails with ErrNotFound if id is not a stored identity.
// The setting is deleted together with the identity.
func (db *DB) SetAccessKey(ctx context.Context, id [32]byte, key AccessKey) error {
	allow := 0
	if key.AllowUnidentified {
		allow = 1
	}
	return db.withTx(ctx, func(tx *sql.Tx) error {
		if err := requireIdentity(ctx, tx, id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO access_keys (id, verifier, allow_unidentified) VALUES (?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET verifier = excluded.verifier, allow_unidentified = excluded.allow_unidentified`,
			id[:], key.Verifier[:], allow)
		if err != nil {
			return fmt.Errorf("serverdb: store access key: %w", err)
		}
		return nil
	})
}

// GetAccessKey returns the access setting of id. It fails with ErrNotFound
// if id is not a stored identity or has never set one; the two cases are
// deliberately not distinguished.
func (db *DB) GetAccessKey(ctx context.Context, id [32]byte) (AccessKey, error) {
	var verifier []byte
	var allow int64
	err := db.sql.QueryRowContext(ctx, "SELECT verifier, allow_unidentified FROM access_keys WHERE id = ?", id[:]).Scan(&verifier, &allow)
	if errors.Is(err, sql.ErrNoRows) {
		return AccessKey{}, ErrNotFound
	}
	if err != nil {
		return AccessKey{}, fmt.Errorf("serverdb: read access key: %w", err)
	}
	if len(verifier) != 32 {
		return AccessKey{}, errors.New("serverdb: damaged access key row")
	}
	return AccessKey{Verifier: [32]byte(verifier), AllowUnidentified: allow == 1}, nil
}
