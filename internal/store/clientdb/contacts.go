package clientdb

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// PutContact inserts c or replaces the stored contact with the same ID.
func (d *DB) PutContact(ctx context.Context, c Contact) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.contactLookup(c.ID)
	plain, err := encode(c.record())
	if err != nil {
		return err
	}
	sealed, err := d.keys.seal(plain, rowAAD(tableContacts, lookup, -1))
	if err != nil {
		return err
	}
	_, err = d.conn.ExecContext(ctx,
		`INSERT INTO contacts (lookup, value) VALUES (?, ?)
		 ON CONFLICT (lookup) DO UPDATE SET value = excluded.value`, lookup, sealed)
	if err != nil {
		return fmt.Errorf("clientdb: put contact: %w", err)
	}
	return nil
}

// GetContact returns the contact with the given ID, or ErrNotFound.
func (d *DB) GetContact(ctx context.Context, id [32]byte) (Contact, error) {
	if err := d.acquire(); err != nil {
		return Contact{}, err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.contactLookup(id)
	var sealed []byte
	err := d.conn.QueryRowContext(ctx, `SELECT value FROM contacts WHERE lookup = ?`, lookup).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return Contact{}, ErrNotFound
	}
	if err != nil {
		return Contact{}, fmt.Errorf("clientdb: get contact: %w", err)
	}
	return d.openContact(lookup, sealed)
}

// ListContacts returns all contacts sorted by display name (case-insensitive,
// ties broken by exact name, then ID).
func (d *DB) ListContacts(ctx context.Context) ([]Contact, error) {
	if err := d.acquire(); err != nil {
		return nil, err
	}
	defer d.mu.RUnlock()

	rows, err := d.conn.QueryContext(ctx, `SELECT lookup, value FROM contacts`)
	if err != nil {
		return nil, fmt.Errorf("clientdb: list contacts: %w", err)
	}
	defer rows.Close()
	var contacts []Contact
	for rows.Next() {
		var lookup, sealed []byte
		if err := rows.Scan(&lookup, &sealed); err != nil {
			return nil, fmt.Errorf("clientdb: list contacts: %w", err)
		}
		c, err := d.openContact(lookup, sealed)
		if err != nil {
			return nil, err
		}
		contacts = append(contacts, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("clientdb: list contacts: %w", err)
	}
	slices.SortFunc(contacts, func(a, b Contact) int {
		return cmp.Or(
			strings.Compare(strings.ToLower(a.DisplayName), strings.ToLower(b.DisplayName)),
			strings.Compare(a.DisplayName, b.DisplayName),
			bytes.Compare(a.ID[:], b.ID[:]),
		)
	})
	return contacts, nil
}

// DeleteContact deletes the contact with the given ID and all of its
// messages. It returns ErrNotFound if no such contact exists; any orphaned
// messages for that ID are deleted regardless.
//
// The replay tombstones of the deleted messages are kept (see
// AppendMessage), so the relay cannot re-deliver them as new messages after
// the contact is added again. They hold no message content.
func (d *DB) DeleteContact(ctx context.Context, id [32]byte) error {
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.contactLookup(id)
	var deleted int64
	err := d.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM messages WHERE peer = ?`, lookup); err != nil {
			return fmt.Errorf("clientdb: delete messages: %w", err)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM contacts WHERE lookup = ?`, lookup)
		if err != nil {
			return fmt.Errorf("clientdb: delete contact: %w", err)
		}
		deleted, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return err
	}
	if deleted == 0 {
		return ErrNotFound
	}
	return nil
}

// openContact decrypts a contact row and checks that it belongs to lookup.
func (d *DB) openContact(lookup, sealed []byte) (Contact, error) {
	plain, err := d.keys.open(sealed, rowAAD(tableContacts, lookup, -1))
	if err != nil {
		return Contact{}, err
	}
	var rec contactRecord
	if err := decode(plain, &rec); err != nil {
		return Contact{}, err
	}
	c, err := rec.contact()
	if err != nil {
		return Contact{}, err
	}
	if !bytes.Equal(d.keys.contactLookup(c.ID), lookup) {
		return Contact{}, fmt.Errorf("%w: contact ID does not match its row", ErrCorrupt)
	}
	return c, nil
}
