package clientdb

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Limits for prekey secrets.
const (
	// MaxPrekeyPrivateSize is the maximum size of a stored prekey private key.
	MaxPrekeyPrivateSize = 8 << 10
	// MaxPrekeyPublicSize is the maximum size of a stored signed prekey
	// encoding.
	MaxPrekeyPublicSize = 16 << 10
)

// PrekeyKind distinguishes signed from one-time prekeys.
type PrekeyKind uint8

// Prekey kinds.
const (
	PrekeySigned  PrekeyKind = 1
	PrekeyOneTime PrekeyKind = 2
)

func (k PrekeyKind) valid() bool { return k == PrekeySigned || k == PrekeyOneTime }

// PrekeySecret is one of the user's own prekeys together with its private
// key. A secret is identified by (Kind, KeyID).
type PrekeySecret struct {
	Kind PrekeyKind
	// KeyID is the non-zero key ID chosen by the owner.
	KeyID uint32
	// Private is the private key. It must not be empty.
	Private []byte
	// Public is the signed prekey encoding that is uploaded to the relay.
	Public  []byte
	Created time.Time
	// RetireAt is the time after which the secret is deleted by
	// PruneRetiredPrekeys; zero means never. It is used for signed prekeys,
	// whose private key is kept for a while after rotation.
	RetireAt time.Time
	// Uploaded is true once the relay has accepted Public.
	Uploaded bool
}

// prekeyRecord is the encrypted form of PrekeySecret.
type prekeyRecord struct {
	Kind     uint8  `cbor:"1,keyasint"`
	KeyID    uint32 `cbor:"2,keyasint"`
	Private  []byte `cbor:"3,keyasint"`
	Public   []byte `cbor:"4,keyasint"`
	Created  int64  `cbor:"5,keyasint"`
	RetireAt int64  `cbor:"6,keyasint"`
	Uploaded bool   `cbor:"7,keyasint"`
}

func validatePrekeyID(kind PrekeyKind, keyID uint32) error {
	if !kind.valid() {
		return fmt.Errorf("%w: unknown prekey kind %d", ErrInvalid, kind)
	}
	if keyID == 0 {
		return fmt.Errorf("%w: prekey ID must be non-zero", ErrInvalid)
	}
	return nil
}

func (p *PrekeySecret) validate() error {
	if err := validatePrekeyID(p.Kind, p.KeyID); err != nil {
		return err
	}
	if len(p.Private) == 0 || len(p.Private) > MaxPrekeyPrivateSize {
		return fmt.Errorf("%w: prekey private key must be 1 to %d bytes", ErrInvalid, MaxPrekeyPrivateSize)
	}
	if len(p.Public) > MaxPrekeyPublicSize {
		return fmt.Errorf("%w: prekey public encoding larger than %d bytes", ErrInvalid, MaxPrekeyPublicSize)
	}
	if err := checkTime("Created", p.Created); err != nil {
		return err
	}
	return checkTime("RetireAt", p.RetireAt)
}

func (p *PrekeySecret) record() prekeyRecord {
	return prekeyRecord{
		Kind:     uint8(p.Kind),
		KeyID:    p.KeyID,
		Private:  p.Private,
		Public:   p.Public,
		Created:  timeToNanos(p.Created),
		RetireAt: timeToNanos(p.RetireAt),
		Uploaded: p.Uploaded,
	}
}

func (r *prekeyRecord) secret() (PrekeySecret, error) {
	p := PrekeySecret{
		Kind:     PrekeyKind(r.Kind),
		KeyID:    r.KeyID,
		Private:  r.Private,
		Created:  nanosToTime(r.Created),
		RetireAt: nanosToTime(r.RetireAt),
		Uploaded: r.Uploaded,
	}
	if len(r.Public) > 0 {
		p.Public = r.Public
	}
	if validatePrekeyID(p.Kind, p.KeyID) != nil || len(p.Private) == 0 {
		return PrekeySecret{}, fmt.Errorf("%w: invalid prekey record", ErrCorrupt)
	}
	return p, nil
}

// PutPrekeySecret stores p, replacing the secret with the same (Kind, KeyID).
func (d *DB) PutPrekeySecret(ctx context.Context, p PrekeySecret) error {
	if err := p.validate(); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.prekeyLookup(p.Kind, p.KeyID)
	plain, err := encode(p.record())
	if err != nil {
		return err
	}
	defer clear(plain)
	sealed, err := d.keys.seal(plain, rowAAD(tablePrekeys, lookup, -1))
	if err != nil {
		return err
	}
	_, err = d.conn.ExecContext(ctx,
		`INSERT INTO prekeys (lookup, value) VALUES (?, ?)
		 ON CONFLICT (lookup) DO UPDATE SET value = excluded.value`, lookup, sealed)
	if err != nil {
		return fmt.Errorf("clientdb: put prekey secret: %w", err)
	}
	return nil
}

// GetPrekeySecret returns the secret with (kind, keyID), or ErrNotFound.
func (d *DB) GetPrekeySecret(ctx context.Context, kind PrekeyKind, keyID uint32) (PrekeySecret, error) {
	if err := validatePrekeyID(kind, keyID); err != nil {
		return PrekeySecret{}, err
	}
	if err := d.acquire(); err != nil {
		return PrekeySecret{}, err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.prekeyLookup(kind, keyID)
	var sealed []byte
	err := d.conn.QueryRowContext(ctx, `SELECT value FROM prekeys WHERE lookup = ?`, lookup).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return PrekeySecret{}, ErrNotFound
	}
	if err != nil {
		return PrekeySecret{}, fmt.Errorf("clientdb: get prekey secret: %w", err)
	}
	return d.openPrekey(lookup, sealed)
}

// DeletePrekeySecret deletes the secret with (kind, keyID), or returns
// ErrNotFound.
//
// The row is really removed: secure_delete overwrites the freed space with
// zeros, and a truncating WAL checkpoint then removes the old page images
// from the -wal file, so after a successful return the encrypted private key
// is no longer present in the database files. Forward secrecy relies on
// this. The checkpoint costs a few extra writes and syncs; see the package
// documentation.
func (d *DB) DeletePrekeySecret(ctx context.Context, kind PrekeyKind, keyID uint32) error {
	if err := validatePrekeyID(kind, keyID); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	err := d.withTx(ctx, func(tx *sql.Tx) error {
		return d.deletePrekeyTx(ctx, tx, kind, keyID)
	})
	if err != nil {
		return err
	}
	d.checkpoint(ctx)
	return nil
}

// ListPrekeySecrets returns all secrets of the given kind, ordered by Created
// and then KeyID.
func (d *DB) ListPrekeySecrets(ctx context.Context, kind PrekeyKind) ([]PrekeySecret, error) {
	if !kind.valid() {
		return nil, fmt.Errorf("%w: unknown prekey kind %d", ErrInvalid, kind)
	}
	if err := d.acquire(); err != nil {
		return nil, err
	}
	defer d.mu.RUnlock()

	all, err := d.allPrekeys(ctx, d.conn)
	if err != nil {
		return nil, err
	}
	var secrets []PrekeySecret
	for _, row := range all {
		if row.secret.Kind == kind {
			secrets = append(secrets, row.secret)
		}
	}
	slices.SortFunc(secrets, func(a, b PrekeySecret) int {
		return cmp.Or(a.Created.Compare(b.Created), cmp.Compare(a.KeyID, b.KeyID))
	})
	return secrets, nil
}

// PruneRetiredPrekeys deletes every secret, of either kind, whose RetireAt is
// set and not after now, and returns how many were deleted. If any were, the
// WAL is checkpointed as in [DB.DeletePrekeySecret].
func (d *DB) PruneRetiredPrekeys(ctx context.Context, now time.Time) (int, error) {
	if err := d.acquire(); err != nil {
		return 0, err
	}
	defer d.mu.RUnlock()

	var pruned int
	err := d.withTx(ctx, func(tx *sql.Tx) error {
		all, err := d.allPrekeys(ctx, tx)
		if err != nil {
			return err
		}
		for _, row := range all {
			if row.secret.RetireAt.IsZero() || row.secret.RetireAt.After(now) {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM prekeys WHERE lookup = ?`, row.lookup); err != nil {
				return fmt.Errorf("clientdb: prune prekeys: %w", err)
			}
			pruned++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if pruned > 0 {
		d.checkpoint(ctx)
	}
	return pruned, nil
}

// deletePrekeyTx deletes one prekey row inside tx, returning ErrNotFound if
// it does not exist.
func (d *DB) deletePrekeyTx(ctx context.Context, tx *sql.Tx, kind PrekeyKind, keyID uint32) error {
	lookup := d.keys.prekeyLookup(kind, keyID)
	res, err := tx.ExecContext(ctx, `DELETE FROM prekeys WHERE lookup = ?`, lookup)
	if err != nil {
		return fmt.Errorf("clientdb: delete prekey secret: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("clientdb: delete prekey secret: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

type prekeyRow struct {
	lookup []byte
	secret PrekeySecret
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// allPrekeys decrypts every prekey row. The table holds a few dozen rows, so
// filtering after decryption is cheap and keeps the kind out of the file.
func (d *DB) allPrekeys(ctx context.Context, q querier) ([]prekeyRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT lookup, value FROM prekeys`)
	if err != nil {
		return nil, fmt.Errorf("clientdb: list prekey secrets: %w", err)
	}
	defer rows.Close()
	var all []prekeyRow
	for rows.Next() {
		var lookup, sealed []byte
		if err := rows.Scan(&lookup, &sealed); err != nil {
			return nil, fmt.Errorf("clientdb: list prekey secrets: %w", err)
		}
		p, err := d.openPrekey(lookup, sealed)
		if err != nil {
			return nil, err
		}
		all = append(all, prekeyRow{lookup: lookup, secret: p})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("clientdb: list prekey secrets: %w", err)
	}
	return all, nil
}

// openPrekey decrypts a prekey row and checks that it belongs to lookup.
func (d *DB) openPrekey(lookup, sealed []byte) (PrekeySecret, error) {
	plain, err := d.keys.open(sealed, rowAAD(tablePrekeys, lookup, -1))
	if err != nil {
		return PrekeySecret{}, err
	}
	defer clear(plain)
	var rec prekeyRecord
	if err := decode(plain, &rec); err != nil {
		return PrekeySecret{}, err
	}
	p, err := rec.secret()
	if err != nil {
		return PrekeySecret{}, err
	}
	if !bytes.Equal(d.keys.prekeyLookup(p.Kind, p.KeyID), lookup) {
		return PrekeySecret{}, fmt.Errorf("%w: prekey ID does not match its row", ErrCorrupt)
	}
	return p, nil
}
