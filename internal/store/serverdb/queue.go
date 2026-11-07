package serverdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MaxQueuedPayloadSize bounds the size of one stored message payload. The
// protocol limits payloads to less than 1 MiB; the bound only keeps a buggy
// caller from filling the disk.
const MaxQueuedPayloadSize = 4 << 20

// QueueLimits bounds the messages stored for one recipient.
type QueueLimits struct {
	// MaxMessages is the largest number of unexpired messages stored for a
	// recipient; at least 1.
	MaxMessages int
	// MaxBytes is the largest total payload size, in bytes, of the unexpired
	// messages stored for a recipient; at least 1.
	MaxBytes int64
}

// Queued is a message stored for a recipient.
type Queued struct {
	// QID is the queue ID of the message, at least 1. Queue IDs increase in
	// the order in which messages were stored and are never reused.
	QID uint64
	// Sender is the authenticated identity that sent the message.
	Sender [32]byte
	// Payload is the end-to-end encrypted ciphertext exactly as sent.
	Payload []byte
}

// Enqueue stores payload from sender for recipient until expires and
// returns its queue ID. Messages that have expired at now do not count
// toward limits and are deleted in the same transaction. If storing the
// message would exceed limits, Enqueue fails with ErrQueueFull and changes
// nothing. The recipient must be a stored identity, otherwise ErrNotFound
// is returned.
func (db *DB) Enqueue(ctx context.Context, recipient, sender [32]byte, payload []byte, now, expires time.Time, limits QueueLimits) (uint64, error) {
	if len(payload) == 0 || len(payload) > MaxQueuedPayloadSize {
		return 0, fmt.Errorf("%w: payload size %d not between 1 and %d", ErrInvalidArgument, len(payload), MaxQueuedPayloadSize)
	}
	if limits.MaxMessages < 1 || limits.MaxBytes < 1 {
		return 0, fmt.Errorf("%w: queue limits must be positive", ErrInvalidArgument)
	}
	if !expires.After(now) {
		return 0, fmt.Errorf("%w: message expires before it is stored", ErrInvalidArgument)
	}
	var qid int64
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		if err := requireIdentity(ctx, tx, recipient); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM queue WHERE recipient = ? AND expires <= ?", recipient[:], now.Unix()); err != nil {
			return fmt.Errorf("serverdb: prune queue: %w", err)
		}
		var count int
		var size int64
		if err := tx.QueryRowContext(ctx, "SELECT count(*), coalesce(sum(size), 0) FROM queue WHERE recipient = ?",
			recipient[:]).Scan(&count, &size); err != nil {
			return fmt.Errorf("serverdb: read queue usage: %w", err)
		}
		if count >= limits.MaxMessages || size+int64(len(payload)) > limits.MaxBytes {
			return ErrQueueFull
		}
		err := tx.QueryRowContext(ctx, `INSERT INTO queue (recipient, sender, payload, size, expires)
			VALUES (?, ?, ?, ?, ?) RETURNING qid`, recipient[:], sender[:], payload, len(payload), expires.Unix()).Scan(&qid)
		if err != nil {
			return fmt.Errorf("serverdb: store message: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return uint64(qid), nil
}

// QueuedFor returns, in queue order, at most limit messages stored for
// recipient whose queue ID is greater than afterQID and that are still
// valid at now.
func (db *DB) QueuedFor(ctx context.Context, recipient [32]byte, afterQID uint64, limit int, now time.Time) ([]Queued, error) {
	if limit < 1 {
		return nil, fmt.Errorf("%w: limit %d", ErrInvalidArgument, limit)
	}
	if afterQID > 1<<63-1 {
		return nil, nil
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT qid, sender, payload FROM queue
		WHERE recipient = ? AND qid > ? AND expires > ? ORDER BY qid LIMIT ?`,
		recipient[:], int64(afterQID), now.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("serverdb: read queue: %w", err)
	}
	defer rows.Close()
	var out []Queued
	for rows.Next() {
		var qid int64
		var sender, payload []byte
		if err := rows.Scan(&qid, &sender, &payload); err != nil {
			return nil, fmt.Errorf("serverdb: read queue: %w", err)
		}
		if len(sender) != 32 || qid < 1 {
			return nil, errors.New("serverdb: damaged queue row")
		}
		out = append(out, Queued{QID: uint64(qid), Sender: [32]byte(sender), Payload: payload})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("serverdb: read queue: %w", err)
	}
	return out, nil
}

// Ack deletes the message qid stored for recipient. It fails with
// ErrNotFound if recipient has no such message, in particular if the
// message belongs to another recipient, which is left untouched.
func (db *DB) Ack(ctx context.Context, recipient [32]byte, qid uint64) error {
	if qid == 0 || qid > 1<<63-1 {
		return ErrNotFound
	}
	result, err := db.sql.ExecContext(ctx, "DELETE FROM queue WHERE qid = ? AND recipient = ?", int64(qid), recipient[:])
	if err != nil {
		return fmt.Errorf("serverdb: delete message: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("serverdb: delete message: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// PruneQueue deletes every message that has expired at now and returns how
// many it deleted.
func (db *DB) PruneQueue(ctx context.Context, now time.Time) (int64, error) {
	result, err := db.sql.ExecContext(ctx, "DELETE FROM queue WHERE expires <= ?", now.Unix())
	if err != nil {
		return 0, fmt.Errorf("serverdb: prune queue: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("serverdb: prune queue: %w", err)
	}
	return n, nil
}
