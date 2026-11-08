package clientdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Timer is the disappearing message timer of a conversation.
type Timer struct {
	// Conv is the contact or group ID.
	Conv [32]byte
	// Duration is how long a message is kept; zero means off.
	Duration time.Duration
	// SetAt is the sender time of the timer message that set it; a setting
	// with a later SetAt replaces it.
	SetAt time.Time
}

type timerRecord struct {
	Conv     []byte `cbor:"1,keyasint"`
	Duration int64  `cbor:"2,keyasint"`
	SetAt    int64  `cbor:"3,keyasint"`
}

// PutTimer stores the timer of a conversation, replacing the previous one.
func (d *DB) PutTimer(ctx context.Context, t Timer) error {
	if t.Duration < 0 {
		return fmt.Errorf("%w: negative timer", ErrInvalid)
	}
	if err := checkTime("SetAt", t.SetAt); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()
	lookup := d.keys.lookup(labelTimer, t.Conv[:])
	plain, err := encode(timerRecord{Conv: t.Conv[:], Duration: int64(t.Duration), SetAt: timeToNanos(t.SetAt)})
	if err != nil {
		return err
	}
	sealed, err := d.keys.seal(plain, rowAAD(tableTimers, lookup, -1))
	if err != nil {
		return err
	}
	_, err = d.conn.ExecContext(ctx,
		`INSERT INTO timers (lookup, value) VALUES (?, ?)
		 ON CONFLICT (lookup) DO UPDATE SET value = excluded.value`, lookup, sealed)
	if err != nil {
		return fmt.Errorf("clientdb: put timer: %w", err)
	}
	return nil
}

// GetTimer returns the timer of a conversation, or ErrNotFound if it was
// never set.
func (d *DB) GetTimer(ctx context.Context, conv [32]byte) (Timer, error) {
	if err := d.acquire(); err != nil {
		return Timer{}, err
	}
	defer d.mu.RUnlock()
	lookup := d.keys.lookup(labelTimer, conv[:])
	var sealed []byte
	err := d.conn.QueryRowContext(ctx, `SELECT value FROM timers WHERE lookup = ?`, lookup).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return Timer{}, ErrNotFound
	}
	if err != nil {
		return Timer{}, fmt.Errorf("clientdb: get timer: %w", err)
	}
	plain, err := d.keys.open(sealed, rowAAD(tableTimers, lookup, -1))
	if err != nil {
		return Timer{}, err
	}
	var rec timerRecord
	if err := decode(plain, &rec); err != nil {
		return Timer{}, err
	}
	if !bytes.Equal(rec.Conv, conv[:]) || rec.Duration < 0 {
		return Timer{}, fmt.Errorf("%w: timer does not match its row", ErrCorrupt)
	}
	return Timer{Conv: conv, Duration: time.Duration(rec.Duration), SetAt: nanosToTime(rec.SetAt)}, nil
}
