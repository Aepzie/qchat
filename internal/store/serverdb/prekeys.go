package serverdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Bounds for stored prekeys.
const (
	// MaxPrekeySize bounds the size of a stored prekey. Prekeys are about
	// 4.7 KB; the bound only keeps a buggy caller from filling the disk.
	MaxPrekeySize = 16 << 10
	// MaxOneTimePrekeys is the largest number of one-time prekeys stored
	// per identity. Further prekeys are ignored until some are handed out.
	MaxOneTimePrekeys = 200
)

// OneTimePrekey is an encoded one-time prekey together with its key ID.
type OneTimePrekey struct {
	// KeyID is the owner-chosen ID of the prekey, unique per identity.
	KeyID uint32
	// Prekey is the encoded, signed prekey exactly as the owner uploaded it.
	Prekey []byte
}

// PrekeyStatus describes the prekeys stored for an identity.
type PrekeyStatus struct {
	// OneTimeRemaining is the number of one-time prekeys not yet handed out.
	OneTimeRemaining int
	// SignedPrekeyExpires is the expiry of the stored signed prekey, or the
	// zero Time if none is stored.
	SignedPrekeyExpires time.Time
}

// PutSignedPrekey stores the signed prekey of id unless the stored one
// expires later: the newest prekey wins, and uploading the stored prekey
// again changes nothing. The identity must exist, otherwise ErrNotFound is
// returned. The caller must have verified the prekey's signature against
// the identity's bundle and taken keyID and expires from it.
func (db *DB) PutSignedPrekey(ctx context.Context, id [32]byte, keyID uint32, prekey []byte, expires time.Time) error {
	if err := checkPrekey(prekey); err != nil {
		return err
	}
	return db.withTx(ctx, func(tx *sql.Tx) error {
		if err := requireIdentity(ctx, tx, id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO signed_prekeys (id, prekey, key_id, expires) VALUES (?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET prekey = excluded.prekey, key_id = excluded.key_id, expires = excluded.expires
			WHERE excluded.expires >= signed_prekeys.expires`, id[:], prekey, int64(keyID), expires.Unix())
		if err != nil {
			return fmt.Errorf("serverdb: store signed prekey: %w", err)
		}
		return nil
	})
}

// AddOneTimePrekeys stores one-time prekeys of id and returns the number
// stored afterwards. Prekeys whose key ID is already stored are ignored, as
// are prekeys beyond MaxOneTimePrekeys. A key ID that was handed out before
// may be stored again; the owner is expected not to reuse key IDs. The
// identity must exist, otherwise ErrNotFound is returned. The caller must
// have verified every prekey against the identity's bundle.
func (db *DB) AddOneTimePrekeys(ctx context.Context, id [32]byte, prekeys []OneTimePrekey) (int, error) {
	for _, p := range prekeys {
		if err := checkPrekey(p.Prekey); err != nil {
			return 0, err
		}
	}
	var remaining int
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		if err := requireIdentity(ctx, tx, id); err != nil {
			return err
		}
		count, err := countOneTimePrekeys(ctx, tx, id)
		if err != nil {
			return err
		}
		for _, p := range prekeys {
			if count >= MaxOneTimePrekeys {
				break
			}
			result, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO one_time_prekeys (id, key_id, prekey) VALUES (?, ?, ?)",
				id[:], int64(p.KeyID), p.Prekey)
			if err != nil {
				return fmt.Errorf("serverdb: store one-time prekey: %w", err)
			}
			added, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("serverdb: store one-time prekey: %w", err)
			}
			count += int(added)
		}
		remaining = count
		return nil
	})
	if err != nil {
		return 0, err
	}
	return remaining, nil
}

// CountOneTimePrekeys returns the number of one-time prekeys stored for id.
func (db *DB) CountOneTimePrekeys(ctx context.Context, id [32]byte) (int, error) {
	var n int
	if err := db.sql.QueryRowContext(ctx, "SELECT count(*) FROM one_time_prekeys WHERE id = ?", id[:]).Scan(&n); err != nil {
		return 0, fmt.Errorf("serverdb: count one-time prekeys: %w", err)
	}
	return n, nil
}

// GetPrekeyStatus returns the number of one-time prekeys and the expiry of
// the signed prekey stored for id. An identity without prekeys, or an
// unknown one, has the zero status.
func (db *DB) GetPrekeyStatus(ctx context.Context, id [32]byte) (PrekeyStatus, error) {
	count, err := db.CountOneTimePrekeys(ctx, id)
	if err != nil {
		return PrekeyStatus{}, err
	}
	status := PrekeyStatus{OneTimeRemaining: count}
	var expires int64
	err = db.sql.QueryRowContext(ctx, "SELECT expires FROM signed_prekeys WHERE id = ?", id[:]).Scan(&expires)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return status, nil
	case err != nil:
		return PrekeyStatus{}, fmt.Errorf("serverdb: read signed prekey: %w", err)
	}
	status.SignedPrekeyExpires = time.Unix(expires, 0)
	return status, nil
}

// TakePrekeys returns the prekey bundle of id: its identity bundle, its
// signed prekey and, if one is left, its oldest one-time prekey, which is
// deleted in the same transaction so that it is handed out exactly once.
// oneTime is nil when none is left. ErrNotFound is returned, and nothing is
// deleted, if the identity is unknown or has no signed prekey that is still
// valid at now.
func (db *DB) TakePrekeys(ctx context.Context, id [32]byte, now time.Time) (bundle, signed, oneTime []byte, err error) {
	err = db.withTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT i.bundle, s.prekey FROM identities i
			JOIN signed_prekeys s ON s.id = i.id WHERE i.id = ? AND s.expires > ?`, id[:], now.Unix())
		if err := row.Scan(&bundle, &signed); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("serverdb: read prekey bundle: %w", err)
		}
		err := tx.QueryRowContext(ctx, `DELETE FROM one_time_prekeys WHERE rowid =
			(SELECT rowid FROM one_time_prekeys WHERE id = ? ORDER BY rowid LIMIT 1) RETURNING prekey`, id[:]).Scan(&oneTime)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("serverdb: take one-time prekey: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return bundle, signed, oneTime, nil
}

func checkPrekey(prekey []byte) error {
	if len(prekey) == 0 || len(prekey) > MaxPrekeySize {
		return fmt.Errorf("%w: prekey size %d not between 1 and %d", ErrInvalidArgument, len(prekey), MaxPrekeySize)
	}
	return nil
}

// requireIdentity returns ErrNotFound unless id is a stored identity.
func requireIdentity(ctx context.Context, tx *sql.Tx, id [32]byte) error {
	known, err := identityExists(ctx, tx, id)
	if err != nil {
		return err
	}
	if !known {
		return ErrNotFound
	}
	return nil
}

func countOneTimePrekeys(ctx context.Context, tx *sql.Tx, id [32]byte) (int, error) {
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM one_time_prekeys WHERE id = ?", id[:]).Scan(&n); err != nil {
		return 0, fmt.Errorf("serverdb: count one-time prekeys: %w", err)
	}
	return n, nil
}
