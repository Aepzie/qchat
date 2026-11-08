package serverdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MaxBundleSize bounds the size of a stored bundle. Phase 2 bundles are
// about 6.6 KB; the bound only keeps a buggy caller from filling the disk.
const MaxBundleSize = 64 << 10

// PutResult reports what PutIdentity did.
type PutResult int

// Outcomes of PutIdentity and RedeemInviteAndPut.
const (
	// Created means the ID was not known and has been stored.
	Created PutResult = iota + 1
	// Unchanged means the identical bundle was already stored.
	Unchanged
	// Replaced means the stored bundle had a lower serial and was replaced.
	Replaced
)

// String returns the name of r.
func (r PutResult) String() string {
	switch r {
	case Created:
		return "created"
	case Unchanged:
		return "unchanged"
	case Replaced:
		return "replaced"
	default:
		return fmt.Sprintf("PutResult(%d)", int(r))
	}
}

// GetBundle returns the bundle stored for id and its serial, or ErrNotFound.
func (db *DB) GetBundle(ctx context.Context, id [32]byte) (bundle []byte, serial uint64, err error) {
	var stored int64
	err = db.sql.QueryRowContext(ctx, "SELECT bundle, serial FROM identities WHERE id = ?", id[:]).Scan(&bundle, &stored)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, fmt.Errorf("serverdb: read identity: %w", err)
	}
	return bundle, serialFromColumn(stored), nil
}

// PutIdentity stores bundle under id, in one transaction:
//
//   - an unknown id is stored (Created);
//   - the identical bundle and serial is accepted without change (Unchanged);
//   - a bundle with a higher serial replaces the stored one (Replaced);
//   - anything else fails with ErrConflict and changes nothing.
//
// PutIdentity does not verify the bundle: the caller must have checked its
// signature, derived id from its signing key and taken serial from it.
func (db *DB) PutIdentity(ctx context.Context, id [32]byte, bundle []byte, serial uint64) (PutResult, error) {
	if err := checkBundle(bundle); err != nil {
		return 0, err
	}
	var result PutResult
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		result, err = putIdentity(ctx, tx, id, bundle, serial)
		return err
	})
	if err != nil {
		return 0, err
	}
	return result, nil
}

// RedeemInviteAndPut stores bundle under id like PutIdentity and, if id is
// not known yet, redeems the invite code in the same transaction. If either
// step fails nothing changes, so a rejected bundle does not use up the
// invite.
//
// A known id is updated by the PutIdentity rules without touching the
// invite, and code may then be empty: the relay demands an invite only for
// new identities. A new id with an invalid code fails with ErrInviteInvalid.
func (db *DB) RedeemInviteAndPut(ctx context.Context, code string, id [32]byte, bundle []byte, serial uint64, now time.Time) (PutResult, error) {
	if err := checkBundle(bundle); err != nil {
		return 0, err
	}
	var result PutResult
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		known, err := identityExists(ctx, tx, id)
		if err != nil {
			return err
		}
		if !known {
			if err := redeemInvite(ctx, tx, code, now); err != nil {
				return err
			}
		}
		result, err = putIdentity(ctx, tx, id, bundle, serial)
		return err
	})
	if err != nil {
		return 0, err
	}
	return result, nil
}

func checkBundle(bundle []byte) error {
	if len(bundle) == 0 || len(bundle) > MaxBundleSize {
		return fmt.Errorf("%w: bundle size %d not between 1 and %d", ErrInvalidArgument, len(bundle), MaxBundleSize)
	}
	return nil
}

func identityExists(ctx context.Context, tx *sql.Tx, id [32]byte) (bool, error) {
	var one int
	err := tx.QueryRowContext(ctx, "SELECT 1 FROM identities WHERE id = ?", id[:]).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("serverdb: read identity: %w", err)
	}
	return true, nil
}

// putIdentity applies the PutIdentity rules inside tx.
func putIdentity(ctx context.Context, tx *sql.Tx, id [32]byte, bundle []byte, serial uint64) (PutResult, error) {
	var storedBundle []byte
	var storedColumn int64
	err := tx.QueryRowContext(ctx, "SELECT bundle, serial FROM identities WHERE id = ?", id[:]).Scan(&storedBundle, &storedColumn)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, "INSERT INTO identities (id, bundle, serial) VALUES (?, ?, ?)", id[:], bundle, serialToColumn(serial)); err != nil {
			return 0, fmt.Errorf("serverdb: insert identity: %w", err)
		}
		return Created, nil
	}
	if err != nil {
		return 0, fmt.Errorf("serverdb: read identity: %w", err)
	}
	storedSerial := serialFromColumn(storedColumn)
	switch {
	case serial == storedSerial && bytes.Equal(bundle, storedBundle):
		return Unchanged, nil
	case serial > storedSerial:
		if _, err := tx.ExecContext(ctx, "UPDATE identities SET bundle = ?, serial = ? WHERE id = ?", bundle, serialToColumn(serial), id[:]); err != nil {
			return 0, fmt.Errorf("serverdb: update identity: %w", err)
		}
		return Replaced, nil
	default:
		return 0, ErrConflict
	}
}

// serialToColumn stores a uint64 serial in SQLite's signed 64-bit INTEGER
// by reinterpreting its bits; serials are only compared in Go, after
// serialFromColumn has reversed the conversion.
func serialToColumn(serial uint64) int64 { return int64(serial) } // #nosec G115 -- deliberate bit reinterpretation, reversed by serialFromColumn

func serialFromColumn(column int64) uint64 { return uint64(column) } // #nosec G115 -- deliberate bit reinterpretation, reverses serialToColumn
