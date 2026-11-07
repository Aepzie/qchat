package clientdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
)

// AppendMessage stores m at the end of its conversation and assigns it the
// next local sequence number. A message with the same (Peer, MsgID) that is
// stored, or was stored and later removed by DeleteContact, yields
// ErrDuplicate; replay protection relies on this check. m.Seq is ignored.
//
// Every appended (Peer, MsgID) is also recorded in the seen table as a
// value-less HMAC tombstone that DeleteContact keeps, so deleting and
// re-adding a contact does not let old payloads be delivered again as new
// messages.
func (d *DB) AppendMessage(ctx context.Context, m Message) error {
	if err := m.validate(); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	peer := d.keys.contactLookup(m.Peer)
	lookup := d.keys.messageLookup(m.Peer, m.MsgID)
	plain, err := encode(m.record())
	if err != nil {
		return err
	}
	return d.withTx(ctx, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx,
			`SELECT 1 FROM seen WHERE lookup = ? UNION ALL SELECT 1 FROM messages WHERE lookup = ? LIMIT 1`,
			lookup, lookup).Scan(&exists)
		if err == nil {
			return ErrDuplicate
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("clientdb: append message: %w", err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO seen (lookup) VALUES (?)`, lookup)
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		if err != nil {
			return fmt.Errorf("clientdb: append message: %w", err)
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO messages (peer, lookup, value) VALUES (?, ?, x'')`, peer, lookup)
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		if err != nil {
			return fmt.Errorf("clientdb: append message: %w", err)
		}
		seq, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("clientdb: append message: %w", err)
		}
		sealed, err := d.keys.seal(plain, rowAAD(tableMessages, lookup, seq))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE messages SET value = ? WHERE seq = ?`, sealed, seq); err != nil {
			return fmt.Errorf("clientdb: append message: %w", err)
		}
		return nil
	})
}

// HasMessage reports whether a message with (peer, msgID) was ever appended:
// it is true for a stored message and also for one that DeleteContact has
// removed, matching the duplicate check of AppendMessage. Use it to discard
// replayed payloads before decrypting or displaying them; it does not mean
// the message can still be read.
func (d *DB) HasMessage(ctx context.Context, peer [32]byte, msgID [16]byte) (bool, error) {
	if err := d.acquire(); err != nil {
		return false, err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.messageLookup(peer, msgID)
	var exists int
	err := d.conn.QueryRowContext(ctx,
		`SELECT 1 FROM seen WHERE lookup = ? UNION ALL SELECT 1 FROM messages WHERE lookup = ? LIMIT 1`,
		lookup, lookup).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("clientdb: has message: %w", err)
	}
	return true, nil
}

// UpdateMessageStatus sets the status of a stored message, or returns
// ErrNotFound.
func (d *DB) UpdateMessageStatus(ctx context.Context, peer [32]byte, msgID [16]byte, status uint8) error {
	if !validStatus(status) {
		return fmt.Errorf("%w: unknown status %d", ErrInvalid, status)
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	peerLookup := d.keys.contactLookup(peer)
	lookup := d.keys.messageLookup(peer, msgID)
	return d.withTx(ctx, func(tx *sql.Tx) error {
		var seq int64
		var rowPeer, sealed []byte
		err := tx.QueryRowContext(ctx, `SELECT seq, peer, value FROM messages WHERE lookup = ?`, lookup).Scan(&seq, &rowPeer, &sealed)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("clientdb: update message status: %w", err)
		}
		if !bytes.Equal(rowPeer, peerLookup) {
			return fmt.Errorf("%w: message row has the wrong peer", ErrCorrupt)
		}
		m, err := d.openMessage(peerLookup, lookup, seq, sealed)
		if err != nil {
			return err
		}
		m.Status = status
		plain, err := encode(m.record())
		if err != nil {
			return err
		}
		resealed, err := d.keys.seal(plain, rowAAD(tableMessages, lookup, seq))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE messages SET value = ? WHERE seq = ?`, resealed, seq); err != nil {
			return fmt.Errorf("clientdb: update message status: %w", err)
		}
		return nil
	})
}

// Messages returns up to limit messages of the conversation with peer, in
// chronological (sequence) order. With before == 0 it returns the latest
// messages; otherwise only messages with Seq < before. To page backwards,
// pass the Seq of the first message of the previous result. limit must be
// positive and is capped at MaxPageSize.
func (d *DB) Messages(ctx context.Context, peer [32]byte, limit int, before int64) ([]Message, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: limit must be positive", ErrInvalid)
	}
	if before < 0 {
		return nil, fmt.Errorf("%w: negative cursor", ErrInvalid)
	}
	limit = min(limit, MaxPageSize)
	if err := d.acquire(); err != nil {
		return nil, err
	}
	defer d.mu.RUnlock()

	peerLookup := d.keys.contactLookup(peer)
	rows, err := d.conn.QueryContext(ctx,
		`SELECT seq, lookup, value FROM messages
		 WHERE peer = ? AND (? = 0 OR seq < ?)
		 ORDER BY seq DESC LIMIT ?`, peerLookup, before, before, limit)
	if err != nil {
		return nil, fmt.Errorf("clientdb: messages: %w", err)
	}
	defer rows.Close()
	var msgs []Message
	for rows.Next() {
		var seq int64
		var lookup, sealed []byte
		if err := rows.Scan(&seq, &lookup, &sealed); err != nil {
			return nil, fmt.Errorf("clientdb: messages: %w", err)
		}
		m, err := d.openMessage(peerLookup, lookup, seq, sealed)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("clientdb: messages: %w", err)
	}
	slices.Reverse(msgs)
	return msgs, nil
}

// openMessage decrypts a message row and checks that its identifiers match
// the row's peer and lookup columns.
func (d *DB) openMessage(peerLookup, lookup []byte, seq int64, sealed []byte) (Message, error) {
	plain, err := d.keys.open(sealed, rowAAD(tableMessages, lookup, seq))
	if err != nil {
		return Message{}, err
	}
	var rec messageRecord
	if err := decode(plain, &rec); err != nil {
		return Message{}, err
	}
	m, err := rec.message(seq)
	if err != nil {
		return Message{}, err
	}
	if !bytes.Equal(d.keys.contactLookup(m.Peer), peerLookup) ||
		!bytes.Equal(d.keys.messageLookup(m.Peer, m.MsgID), lookup) {
		return Message{}, fmt.Errorf("%w: message identifiers do not match their row", ErrCorrupt)
	}
	return m, nil
}
