package clientdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Limits for ratchet sessions.
const (
	// MaxSessionStateSize is the maximum size of a serialized ratchet state.
	MaxSessionStateSize = 1 << 20
	// MaxPendingInitSize is the maximum size of a stored Init header.
	MaxPendingInitSize = 128 << 10
)

// Session is the ratchet session with one peer. There is at most one session
// per peer. State is the ratchet's own serialization; this package stores it
// encrypted like every other row and does not interpret it.
type Session struct {
	Peer [32]byte
	// State is the serialized ratchet state. It must not be empty.
	State []byte
	// Initiator is true if this side started the session.
	Initiator bool
	// Confirmed is true once any message has been received on the session.
	Confirmed bool
	// PendingInit is the Init header that is sent with every message until
	// the session is confirmed; nil if there is none.
	PendingInit []byte
	Created     time.Time
	Updated     time.Time
}

// sessionRecord is the encrypted form of Session.
type sessionRecord struct {
	Peer        []byte `cbor:"1,keyasint"`
	State       []byte `cbor:"2,keyasint"`
	Initiator   bool   `cbor:"3,keyasint"`
	Confirmed   bool   `cbor:"4,keyasint"`
	PendingInit []byte `cbor:"5,keyasint"`
	Created     int64  `cbor:"6,keyasint"`
	Updated     int64  `cbor:"7,keyasint"`
}

func (s *Session) validate() error {
	if len(s.State) == 0 {
		return fmt.Errorf("%w: empty session state", ErrInvalid)
	}
	if len(s.State) > MaxSessionStateSize {
		return fmt.Errorf("%w: session state larger than %d bytes", ErrInvalid, MaxSessionStateSize)
	}
	if len(s.PendingInit) > MaxPendingInitSize {
		return fmt.Errorf("%w: pending Init larger than %d bytes", ErrInvalid, MaxPendingInitSize)
	}
	if err := checkTime("Created", s.Created); err != nil {
		return err
	}
	return checkTime("Updated", s.Updated)
}

func (s *Session) record() sessionRecord {
	return sessionRecord{
		Peer:        s.Peer[:],
		State:       s.State,
		Initiator:   s.Initiator,
		Confirmed:   s.Confirmed,
		PendingInit: s.PendingInit,
		Created:     timeToNanos(s.Created),
		Updated:     timeToNanos(s.Updated),
	}
}

func (r *sessionRecord) session() (Session, error) {
	var s Session
	if len(r.Peer) != len(s.Peer) {
		return Session{}, fmt.Errorf("%w: bad session peer length", ErrCorrupt)
	}
	if len(r.State) == 0 {
		return Session{}, fmt.Errorf("%w: empty session state", ErrCorrupt)
	}
	copy(s.Peer[:], r.Peer)
	s.State = r.State
	s.Initiator = r.Initiator
	s.Confirmed = r.Confirmed
	if len(r.PendingInit) > 0 {
		s.PendingInit = r.PendingInit
	}
	s.Created = nanosToTime(r.Created)
	s.Updated = nanosToTime(r.Updated)
	return s, nil
}

// PutSession stores s, replacing any session with the same peer.
func (d *DB) PutSession(ctx context.Context, s Session) error {
	if err := s.validate(); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	return d.withTx(ctx, func(tx *sql.Tx) error {
		return d.putSessionTx(ctx, tx, s)
	})
}

// GetSession returns the session with peer, or ErrNotFound.
func (d *DB) GetSession(ctx context.Context, peer [32]byte) (Session, error) {
	if err := d.acquire(); err != nil {
		return Session{}, err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.sessionLookup(peer)
	var sealed []byte
	err := d.conn.QueryRowContext(ctx, `SELECT value FROM sessions WHERE lookup = ?`, lookup).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("clientdb: get session: %w", err)
	}
	return d.openSession(lookup, sealed)
}

// DeleteSession deletes the session with peer, or returns ErrNotFound. Like
// [DB.DeletePrekeySecret] it then checkpoints the WAL, so the deleted ratchet
// state does not linger in the -wal file.
func (d *DB) DeleteSession(ctx context.Context, peer [32]byte) error {
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.sessionLookup(peer)
	res, err := d.conn.ExecContext(ctx, `DELETE FROM sessions WHERE lookup = ?`, lookup)
	if err != nil {
		return fmt.Errorf("clientdb: delete session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("clientdb: delete session: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	d.checkpoint(ctx)
	return nil
}

// CommitReceive atomically records the processing of a received message: it
// appends m, stores s as the new session state for m.Peer and, if
// consumedOneTime is non-zero, deletes the own one-time prekey secret with
// that key ID. Either all three changes are committed or none is, so a crash
// can neither leave a deleted prekey without the session derived from it nor
// a saved session whose prekey can still be used again.
//
// m must be Incoming and s.Peer must equal m.Peer. If the message was already
// appended, CommitReceive returns ErrDuplicate (see [DB.AppendMessage]) and
// writes nothing: the session is not updated and no prekey is deleted. If
// consumedOneTime names a prekey that is not stored, it returns ErrNotFound
// and writes nothing.
//
// When a prekey was deleted, the WAL is checkpointed afterwards; see
// [DB.DeletePrekeySecret].
func (d *DB) CommitReceive(ctx context.Context, s Session, m Message, consumedOneTime uint32) error {
	if m.Dir != Incoming {
		return fmt.Errorf("%w: CommitReceive needs an incoming message", ErrInvalid)
	}
	if err := d.validateCommit(s, m); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	err := d.withTx(ctx, func(tx *sql.Tx) error {
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

// CommitSend atomically appends the outgoing message m and stores s as the
// new session state for m.Peer, so the state that produced a ciphertext is
// saved before the ciphertext is handed to the relay. m must be Outgoing and
// s.Peer must equal m.Peer. On ErrDuplicate nothing is written.
func (d *DB) CommitSend(ctx context.Context, s Session, m Message) error {
	if m.Dir != Outgoing {
		return fmt.Errorf("%w: CommitSend needs an outgoing message", ErrInvalid)
	}
	if err := d.validateCommit(s, m); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	return d.withTx(ctx, func(tx *sql.Tx) error {
		if err := d.appendMessageTx(ctx, tx, m); err != nil {
			return err
		}
		return d.putSessionTx(ctx, tx, s)
	})
}

func (d *DB) validateCommit(s Session, m Message) error {
	if s.Peer != m.Peer {
		return fmt.Errorf("%w: session and message belong to different peers", ErrInvalid)
	}
	if err := s.validate(); err != nil {
		return err
	}
	return m.validate()
}

// putSessionTx encrypts s and upserts it inside tx. s must have been
// validated.
func (d *DB) putSessionTx(ctx context.Context, tx *sql.Tx, s Session) error {
	lookup := d.keys.sessionLookup(s.Peer)
	plain, err := encode(s.record())
	if err != nil {
		return err
	}
	defer clear(plain)
	sealed, err := d.keys.seal(plain, rowAAD(tableSessions, lookup, -1))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO sessions (lookup, value) VALUES (?, ?)
		 ON CONFLICT (lookup) DO UPDATE SET value = excluded.value`, lookup, sealed)
	if err != nil {
		return fmt.Errorf("clientdb: put session: %w", err)
	}
	return nil
}

// openSession decrypts a session row and checks that it belongs to lookup.
func (d *DB) openSession(lookup, sealed []byte) (Session, error) {
	plain, err := d.keys.open(sealed, rowAAD(tableSessions, lookup, -1))
	if err != nil {
		return Session{}, err
	}
	defer clear(plain)
	var rec sessionRecord
	if err := decode(plain, &rec); err != nil {
		return Session{}, err
	}
	s, err := rec.session()
	if err != nil {
		return Session{}, err
	}
	if !bytes.Equal(d.keys.sessionLookup(s.Peer), lookup) {
		return Session{}, fmt.Errorf("%w: session peer does not match its row", ErrCorrupt)
	}
	return s, nil
}

// checkpoint copies the whole WAL into the main file and truncates the WAL to
// zero bytes, so that page images of deleted rows do not survive in the -wal
// file; with secure_delete the main file then holds only zeroed pages for
// them.
//
// Cost: every frame in the WAL is written to the main file, which is then
// synced, and the WAL is truncated and regrown by the next write. On a small
// client database this is a few extra writes and syncs, typically
// milliseconds, which is why it runs only after deleting secrets and not
// after every write.
//
// It is best effort: the deletion it follows has already been committed, and
// reporting an error would make the caller believe it had not. If the
// checkpoint cannot complete (another process is reading the file), the page
// images remain until the next successful checkpoint, at the latest in Close.
// It runs even if ctx has been cancelled.
func (d *DB) checkpoint(ctx context.Context) {
	_, _ = d.conn.ExecContext(context.WithoutCancel(ctx), `PRAGMA wal_checkpoint(TRUNCATE)`)
}
