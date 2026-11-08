package clientdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// maxExpiredBatch bounds the messages DeleteExpiredMessages removes at once.
const maxExpiredBatch = 500

// ExpiredMessage identifies a message deleted by DeleteExpiredMessages.
type ExpiredMessage struct {
	// Conv is the contact or group, and Group tells which.
	Conv  [32]byte
	Group bool
	// Sender is the group message sender; for a 1:1 message it is zero.
	Sender [32]byte
	MsgID  [16]byte
	Dir    Direction
	Flags  uint8
}

// expiresColumn returns the expires column of a message: its expiry in
// Unix seconds, rounded up, or 0 for none.
func expiresColumn(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return (t.UnixNano() + int64(time.Second) - 1) / int64(time.Second)
}

// insertMessageRow inserts a message row with an empty value. The expires
// column is only named for a message that expires, so that databases
// migrated in tests from early schemas keep working.
func insertMessageRow(ctx context.Context, tx *sql.Tx, peer, lookup []byte, expires time.Time) (sql.Result, error) {
	if expires.IsZero() {
		return tx.ExecContext(ctx, `INSERT INTO messages (peer, lookup, value) VALUES (?, ?, x'')`, peer, lookup)
	}
	return tx.ExecContext(ctx, `INSERT INTO messages (peer, lookup, value, expires) VALUES (?, ?, x'', ?)`, peer, lookup, expiresColumn(expires))
}

// DeleteExpiredMessages deletes up to 500 1:1 and group messages whose
// Expires is not after now, and returns them so that the caller can remove
// them from the interface and delete their files. The replay tombstones of
// the deleted messages stay, so they cannot be delivered again. After a
// deletion the WAL is checkpointed, so that the deleted bodies leave the
// files (see the package documentation). Call it again while it returns a
// full batch.
//
// The expires column is not authenticated; a row whose column says it has
// expired but whose encrypted record does not is left alone.
func (d *DB) DeleteExpiredMessages(ctx context.Context, now time.Time) ([]ExpiredMessage, error) {
	if err := d.acquire(); err != nil {
		return nil, err
	}
	defer d.mu.RUnlock()
	var out []ExpiredMessage
	err := d.withTx(ctx, func(tx *sql.Tx) error {
		out = nil
		rows, err := tx.QueryContext(ctx,
			`SELECT seq, peer, lookup, value FROM messages WHERE expires > 0 AND expires <= ? ORDER BY expires LIMIT ?`,
			now.Unix(), maxExpiredBatch)
		if err != nil {
			return fmt.Errorf("clientdb: expired messages: %w", err)
		}
		var seqs []int64
		for rows.Next() {
			var seq int64
			var peer, lookup, sealed []byte
			if err := rows.Scan(&seq, &peer, &lookup, &sealed); err != nil {
				rows.Close()
				return fmt.Errorf("clientdb: expired messages: %w", err)
			}
			e, expires, ok := d.openAnyMessage(peer, lookup, seq, sealed)
			if !ok || expires.IsZero() || expires.After(now) {
				continue
			}
			seqs = append(seqs, seq)
			out = append(out, e)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("clientdb: expired messages: %w", err)
		}
		rows.Close()
		for _, seq := range seqs {
			if _, err := tx.ExecContext(ctx, `DELETE FROM messages WHERE seq = ?`, seq); err != nil {
				return fmt.Errorf("clientdb: delete expired message: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) > 0 {
		d.checkpoint(ctx)
	}
	return out, nil
}

// openAnyMessage opens a message row as a 1:1 or as a group message.
func (d *DB) openAnyMessage(peer, lookup []byte, seq int64, sealed []byte) (ExpiredMessage, time.Time, bool) {
	if m, err := d.openMessage(peer, lookup, seq, sealed); err == nil {
		return ExpiredMessage{Conv: m.Peer, MsgID: m.MsgID, Dir: m.Dir, Flags: m.Flags}, m.Expires, true
	}
	m, err := d.openGroupMessage(peer, lookup, seq, sealed)
	if err != nil {
		return ExpiredMessage{}, time.Time{}, false
	}
	return ExpiredMessage{Conv: m.Group, Group: true, Sender: m.Sender, MsgID: m.MsgID, Dir: m.Dir, Flags: m.Flags}, m.Expires, true
}
