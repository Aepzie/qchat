package serverdb

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
)

// AccessKey is the sealed sender access setting an identity uploads.
type AccessKey struct {
	// Verifier is the verifier of the identity's access key, which sealed
	// senders present as their access proof. It must not be all zero. Only
	// its SHA-256 hash is stored.
	Verifier [32]byte
	// AllowUnidentified lets anyone send sealed messages to the identity.
	AllowUnidentified bool
}

// StoredAccessKey is the access setting of an identity as stored.
type StoredAccessKey struct {
	// VerifierHash is the SHA-256 hash of the identity's verifier, so a
	// copy of the database does not hand out working access proofs.
	VerifierHash [32]byte
	// AllowUnidentified lets anyone send sealed messages to the identity.
	AllowUnidentified bool
}

// Matches reports whether proof is the verifier whose hash k holds. It
// hashes proof and compares in constant time, so it costs the same for
// every proof of the same length.
func (k StoredAccessKey) Matches(proof []byte) bool {
	hash := sha256.Sum256(proof)
	return subtle.ConstantTimeCompare(hash[:], k.VerifierHash[:]) == 1
}

// zeroVerifier is the verifier SetAccessKey refuses.
var zeroVerifier [32]byte

// SetAccessKey stores key as the access setting of id, replacing any
// earlier one; only the hash of the verifier is written. It fails with
// ErrInvalidArgument for an all-zero verifier and with ErrNotFound if id
// is not a stored identity. The setting is deleted together with the
// identity.
func (db *DB) SetAccessKey(ctx context.Context, id [32]byte, key AccessKey) error {
	if subtle.ConstantTimeCompare(key.Verifier[:], zeroVerifier[:]) == 1 {
		return fmt.Errorf("%w: zero access verifier", ErrInvalidArgument)
	}
	allow := 0
	if key.AllowUnidentified {
		allow = 1
	}
	hash := sha256.Sum256(key.Verifier[:])
	return db.withTx(ctx, func(tx *sql.Tx) error {
		if err := requireIdentity(ctx, tx, id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO access_keys (id, verifier_hash, allow_unidentified) VALUES (?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET verifier_hash = excluded.verifier_hash, allow_unidentified = excluded.allow_unidentified`,
			id[:], hash[:], allow)
		if err != nil {
			return fmt.Errorf("serverdb: store access key: %w", err)
		}
		return nil
	})
}

// GetAccessKey returns the stored access setting of id. It fails with
// ErrNotFound if id is not a stored identity or has never set one; the two
// cases are deliberately not distinguished.
func (db *DB) GetAccessKey(ctx context.Context, id [32]byte) (StoredAccessKey, error) {
	var hash []byte
	var allow int64
	err := db.sql.QueryRowContext(ctx, "SELECT verifier_hash, allow_unidentified FROM access_keys WHERE id = ?", id[:]).Scan(&hash, &allow)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredAccessKey{}, ErrNotFound
	}
	if err != nil {
		return StoredAccessKey{}, fmt.Errorf("serverdb: read access key: %w", err)
	}
	if len(hash) != 32 {
		return StoredAccessKey{}, errors.New("serverdb: damaged access key row")
	}
	return StoredAccessKey{VerifierHash: [32]byte(hash), AllowUnidentified: allow == 1}, nil
}
