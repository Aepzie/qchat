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
	if err := checkEnqueueArgs(payload, now, expires, limits); err != nil {
		return 0, err
	}
	var qid uint64
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		qid, err = enqueueTx(ctx, tx, recipient, sender, payload, now, expires, limits)
		return err
	})
	if err != nil {
		return 0, err
	}
	return qid, nil
}

// MaxMultiRecipients is the largest number of recipients EnqueueMulti
// accepts in one call.
const MaxMultiRecipients = 256

// EnqueueMulti stores one copy of payload from sender for every recipient,
// in a single transaction, and returns the queue IDs in the order of
// recipients. Each copy has its own queue ID and counts toward the limits
// of its recipient exactly as if it had been stored by [DB.Enqueue].
//
// Either every copy is stored or none is: if any recipient is not a stored
// identity the call fails with ErrNotFound, and if any recipient's queue
// would exceed limits it fails with ErrQueueFull, in both cases changing
// nothing. The errors deliberately do not say which recipient caused them.
// recipients must hold between 1 and MaxMultiRecipients distinct IDs.
func (db *DB) EnqueueMulti(ctx context.Context, recipients [][32]byte, sender [32]byte, payload []byte, now, expires time.Time, limits QueueLimits) ([]uint64, error) {
	if len(recipients) == 0 || len(recipients) > MaxMultiRecipients {
		return nil, fmt.Errorf("%w: %d recipients, want 1 to %d", ErrInvalidArgument, len(recipients), MaxMultiRecipients)
	}
	seen := make(map[[32]byte]struct{}, len(recipients))
	for _, r := range recipients {
		if _, dup := seen[r]; dup {
			return nil, fmt.Errorf("%w: duplicate recipient", ErrInvalidArgument)
		}
		seen[r] = struct{}{}
	}
	if err := checkEnqueueArgs(payload, now, expires, limits); err != nil {
		return nil, err
	}
	qids := make([]uint64, len(recipients))
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		for _, r := range recipients {
			if err := requireIdentity(ctx, tx, r); err != nil {
				return err
			}
		}
		for i, r := range recipients {
			qid, err := enqueueTx(ctx, tx, r, sender, payload, now, expires, limits)
			if err != nil {
				return err
			}
			qids[i] = qid
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return qids, nil
}

// checkEnqueueArgs validates the arguments shared by Enqueue and
// EnqueueMulti.
func checkEnqueueArgs(payload []byte, now, expires time.Time, limits QueueLimits) error {
	if len(payload) == 0 || len(payload) > MaxQueuedPayloadSize {
		return fmt.Errorf("%w: payload size %d not between 1 and %d", ErrInvalidArgument, len(payload), MaxQueuedPayloadSize)
	}
	if limits.MaxMessages < 1 || limits.MaxBytes < 1 {
		return fmt.Errorf("%w: queue limits must be positive", ErrInvalidArgument)
	}
	if !expires.After(now) {
		return fmt.Errorf("%w: message expires before it is stored", ErrInvalidArgument)
	}
	return nil
}

// enqueueTx stores one message within tx after checking that recipient
// exists and that its queue has room, and returns the new queue ID.
func enqueueTx(ctx context.Context, tx *sql.Tx, recipient, sender [32]byte, payload []byte, now, expires time.Time, limits QueueLimits) (uint64, error) {
	if err := requireIdentity(ctx, tx, recipient); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM queue WHERE recipient = ? AND expires <= ?", recipient[:], now.Unix()); err != nil {
		return 0, fmt.Errorf("serverdb: prune queue: %w", err)
	}
	var count int
	var size int64
	if err := tx.QueryRowContext(ctx, "SELECT count(*), coalesce(sum(size), 0) FROM queue WHERE recipient = ?",
		recipient[:]).Scan(&count, &size); err != nil {
		return 0, fmt.Errorf("serverdb: read queue usage: %w", err)
	}
	if count >= limits.MaxMessages || size+int64(len(payload)) > limits.MaxBytes {
		return 0, ErrQueueFull
	}
	var qid int64
	err := tx.QueryRowContext(ctx, `INSERT INTO queue (recipient, sender, payload, size, expires)
		VALUES (?, ?, ?, ?, ?) RETURNING qid`, recipient[:], sender[:], payload, len(payload), expires.Unix()).Scan(&qid)
	if err != nil {
		return 0, fmt.Errorf("serverdb: store message: %w", err)
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
