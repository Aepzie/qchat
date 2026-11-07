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
	// messages stored for a recipient; at least 1. Every message counts
	// with the full size of its payload, even when the payload is shared
	// with other recipients.
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

// Enqueued is the outcome of [DB.EnqueueMulti] for one recipient.
type Enqueued struct {
	// QID is the queue ID of the message stored for the recipient, or 0 if
	// none was stored.
	QID uint64
	// Err is nil if the message was stored, ErrNotFound if the recipient is
	// not a stored identity and ErrQueueFull if storing the message would
	// exceed the recipient's limits.
	Err error
}

// Enqueue stores payload from sender for recipient until expires and
// returns its queue ID. Messages that have expired at now do not count
// toward limits and are deleted in the same transaction. If storing the
// message would exceed limits, Enqueue fails with ErrQueueFull and stores
// nothing. The recipient must be a stored identity, otherwise ErrNotFound
// is returned.
func (db *DB) Enqueue(ctx context.Context, recipient, sender [32]byte, payload []byte, now, expires time.Time, limits QueueLimits) (uint64, error) {
	if err := checkEnqueueArgs(payload, now, expires, limits); err != nil {
		return 0, err
	}
	var outcomes []Enqueued
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		outcomes, err = enqueueSharedTx(ctx, tx, [][32]byte{recipient}, sender, payload, now, expires, limits)
		return err
	})
	if err != nil {
		return 0, err
	}
	if outcomes[0].Err != nil {
		return 0, outcomes[0].Err
	}
	return outcomes[0].QID, nil
}

// MaxMultiRecipients is the largest number of recipients EnqueueMulti
// accepts in one call.
const MaxMultiRecipients = 256

// EnqueueMulti stores payload from sender for every recipient that can
// take it, in a single transaction, and returns one outcome per recipient
// in the order of recipients. The payload is stored once and shared by all
// copies; each copy has its own queue ID and counts toward the limits of
// its recipient with the full payload size, exactly as if it had been
// stored by [DB.Enqueue].
//
// A recipient that is not a stored identity, or whose queue would exceed
// limits, gets no copy and does not affect the others; its outcome carries
// ErrNotFound or ErrQueueFull. The returned error is reserved for invalid
// arguments and database failures, in which case nothing is stored.
// recipients must hold between 1 and MaxMultiRecipients distinct IDs.
func (db *DB) EnqueueMulti(ctx context.Context, recipients [][32]byte, sender [32]byte, payload []byte, now, expires time.Time, limits QueueLimits) ([]Enqueued, error) {
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
	var outcomes []Enqueued
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		outcomes, err = enqueueSharedTx(ctx, tx, recipients, sender, payload, now, expires, limits)
		return err
	})
	if err != nil {
		return nil, err
	}
	return outcomes, nil
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

// enqueueSharedTx stores payload once within tx, plus one queue row
// referring to it for every recipient that exists and has room, and
// returns the outcome for each recipient. If no recipient can take the
// message, nothing is written apart from deleting expired messages.
func enqueueSharedTx(ctx context.Context, tx *sql.Tx, recipients [][32]byte, sender [32]byte, payload []byte, now, expires time.Time, limits QueueLimits) ([]Enqueued, error) {
	outcomes := make([]Enqueued, len(recipients))
	accepted := make([]int, 0, len(recipients))
	for i, r := range recipients {
		err := checkRoomTx(ctx, tx, r, int64(len(payload)), now, limits)
		switch {
		case err == nil:
			accepted = append(accepted, i)
		case errors.Is(err, ErrNotFound), errors.Is(err, ErrQueueFull):
			outcomes[i].Err = err
		default:
			return nil, err
		}
	}
	if len(accepted) == 0 {
		return outcomes, nil
	}
	var pid int64
	if err := tx.QueryRowContext(ctx, "INSERT INTO queue_payloads (payload, size, refs) VALUES (?, ?, ?) RETURNING pid",
		payload, len(payload), len(accepted)).Scan(&pid); err != nil {
		return nil, fmt.Errorf("serverdb: store payload: %w", err)
	}
	insert, err := tx.PrepareContext(ctx, `INSERT INTO queue (recipient, sender, pid, size, expires)
		VALUES (?, ?, ?, ?, ?) RETURNING qid`)
	if err != nil {
		return nil, fmt.Errorf("serverdb: store message: %w", err)
	}
	defer insert.Close()
	for _, i := range accepted {
		var qid int64
		if err := insert.QueryRowContext(ctx, recipients[i][:], sender[:], pid, len(payload), expires.Unix()).Scan(&qid); err != nil {
			return nil, fmt.Errorf("serverdb: store message: %w", err)
		}
		outcomes[i].QID = uint64(qid)
	}
	return outcomes, nil
}

// checkRoomTx deletes the expired messages of recipient within tx and
// reports ErrNotFound if recipient is not a stored identity, or
// ErrQueueFull if one more message of size bytes would exceed limits.
func checkRoomTx(ctx context.Context, tx *sql.Tx, recipient [32]byte, size int64, now time.Time, limits QueueLimits) error {
	if err := requireIdentity(ctx, tx, recipient); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM queue WHERE recipient = ? AND expires <= ?", recipient[:], now.Unix()); err != nil {
		return fmt.Errorf("serverdb: prune queue: %w", err)
	}
	var count int
	var used int64
	if err := tx.QueryRowContext(ctx, "SELECT count(*), coalesce(sum(size), 0) FROM queue WHERE recipient = ?",
		recipient[:]).Scan(&count, &used); err != nil {
		return fmt.Errorf("serverdb: read queue usage: %w", err)
	}
	if count >= limits.MaxMessages || used+size > limits.MaxBytes {
		return ErrQueueFull
	}
	return nil
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
	rows, err := db.sql.QueryContext(ctx, `SELECT q.qid, q.sender, p.payload FROM queue q
		JOIN queue_payloads p ON p.pid = q.pid
		WHERE q.recipient = ? AND q.qid > ? AND q.expires > ? ORDER BY q.qid LIMIT ?`,
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

// Ack deletes the message qid stored for recipient, and its payload once no
// other recipient's copy refers to it. It fails with ErrNotFound if
// recipient has no such message, in particular if the message belongs to
// another recipient, which is left untouched.
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

// PruneQueue deletes every message that has expired at now, and every
// payload no remaining message refers to, and returns how many messages it
// deleted.
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
