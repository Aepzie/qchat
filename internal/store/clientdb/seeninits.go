package clientdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrInitSeen is returned by [DB.CommitReceiveInit] when the session start
// it records is already in the replay set.
var ErrInitSeen = errors.New("clientdb: session start already seen")

// SeenInit identifies a session start (an Init header) in the replay set.
type SeenInit struct {
	// SPKID is the non-zero ID of the own signed prekey the Init used.
	SPKID uint32
	// Key is the Init's replay key (handshake.ReplayKey).
	Key [32]byte
	// Expires is when the entry may be pruned: no earlier than the time the
	// Init can no longer be accepted, which is when the signed prekey SPKID
	// is deleted (its RetireAt) or the Init is older than
	// handshake.MaxInitAge, whichever comes first. Using the prekey's
	// RetireAt for every entry of that prekey reveals the least in the file.
	Expires time.Time
}

func (s SeenInit) validate() error {
	if s.SPKID == 0 {
		return fmt.Errorf("%w: signed prekey ID must be non-zero", ErrInvalid)
	}
	if s.Expires.Unix() <= 0 {
		return fmt.Errorf("%w: Expires must be after 1970", ErrInvalid)
	}
	return nil
}

// expiresSeconds returns Expires in Unix seconds, rounded up, so that an
// entry is never pruned before its expiry.
func (s SeenInit) expiresSeconds() int64 {
	seconds := s.Expires.Unix()
	if s.Expires.After(time.Unix(seconds, 0)) {
		seconds++
	}
	return seconds
}

// MarkInitSeen adds a session start to the replay set and reports whether it
// was already there; in that case nothing is changed (in particular its
// expiry is not extended). The check and the insertion are one atomic
// statement.
//
// The replay set stores only HMAC-SHA256(lookupKey, label || u32(spkID) ||
// key) and the expiry, no encrypted value. Entries stay until
// [DB.PruneSeenInits] removes them after expires.
//
// Recording a session start and storing the session it created should
// happen in one transaction, which [DB.CommitReceiveInit] provides; with
// MarkInitSeen alone, a crash between the two leaves either the session
// unrecorded (a replay of the Init is then accepted once more) or the Init
// recorded without its session (its later messages are then rejected).
func (d *DB) MarkInitSeen(ctx context.Context, spkID uint32, key [32]byte, expires time.Time) (alreadySeen bool, err error) {
	seen := SeenInit{SPKID: spkID, Key: key, Expires: expires}
	if err := seen.validate(); err != nil {
		return false, err
	}
	if err := d.acquire(); err != nil {
		return false, err
	}
	defer d.mu.RUnlock()

	var inserted bool
	err = d.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		inserted, err = d.insertSeenInitTx(ctx, tx, seen)
		return err
	})
	if err != nil {
		return false, err
	}
	return !inserted, nil
}

// CommitReceiveInit is [DB.CommitReceive] for the first message of a session
// started by the peer: in the same transaction it also adds init to the
// replay set. If init is already there it returns [ErrInitSeen] and writes
// nothing, so a replayed session start can neither replace the session nor
// consume a prekey. Its other errors are those of CommitReceive and
// [DB.MarkInitSeen].
func (d *DB) CommitReceiveInit(ctx context.Context, s Session, m Message, consumedOneTime uint32, init SeenInit) error {
	if m.Dir != Incoming {
		return fmt.Errorf("%w: CommitReceiveInit needs an incoming message", ErrInvalid)
	}
	if err := init.validate(); err != nil {
		return err
	}
	if err := d.validateCommit(s, m); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	err := d.withTx(ctx, func(tx *sql.Tx) error {
		inserted, err := d.insertSeenInitTx(ctx, tx, init)
		if err != nil {
			return err
		}
		if !inserted {
			return ErrInitSeen
		}
		if err := d.appendMessageTx(ctx, tx, m); err != nil {
			return err
		}
		if consumedOneTime != 0 {
			if err := d.deletePrekeyTx(ctx, tx, PrekeyOneTime, consumedOneTime); err != nil {
				return err
			}
		}
		return d.putSessionTx(ctx, tx, s)
	})
	if err != nil {
		return err
	}
	if consumedOneTime != 0 {
		d.checkpoint(ctx)
	}
	return nil
}

// PruneSeenInits deletes every replay set entry whose expiry is not after
// now and returns how many were deleted.
func (d *DB) PruneSeenInits(ctx context.Context, now time.Time) (int, error) {
	if err := d.acquire(); err != nil {
		return 0, err
	}
	defer d.mu.RUnlock()

	res, err := d.conn.ExecContext(ctx, `DELETE FROM seen_inits WHERE expires <= ?`, now.Unix())
	if err != nil {
		return 0, fmt.Errorf("clientdb: prune seen inits: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("clientdb: prune seen inits: %w", err)
	}
	return int(n), nil
}

// insertSeenInitTx inserts seen into the replay set inside tx and reports
// whether it was new.
func (d *DB) insertSeenInitTx(ctx context.Context, tx *sql.Tx, seen SeenInit) (bool, error) {
	res, err := tx.ExecContext(ctx,
		`INSERT INTO seen_inits (lookup, expires) VALUES (?, ?) ON CONFLICT (lookup) DO NOTHING`,
		d.keys.seenInitLookup(seen.SPKID, seen.Key), seen.expiresSeconds())
	if err != nil {
		return false, fmt.Errorf("clientdb: mark init seen: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("clientdb: mark init seen: %w", err)
	}
	return n == 1, nil
}
