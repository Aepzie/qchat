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

// Limits for groups and sender keys.
const (
	// MaxGroupStateSize is the maximum size of a serialized group state.
	MaxGroupStateSize = 256 << 10
	// MaxSenderKeyStateSize is the maximum size of a serialized own or
	// receiver sender key state.
	MaxSenderKeyStateSize = 256 << 10
)

// Group is a group the user belongs to or has left. State is the group
// package's own serialization of the membership state; this package stores
// it encrypted and does not interpret it.
type Group struct {
	ID [32]byte
	// State is the serialized group state. It must not be empty.
	State []byte
	// Joined is when the user joined or created the group.
	Joined time.Time
	// Left is true once the user left or was removed from the group.
	Left bool
}

// GroupMessage is one message of a group conversation.
type GroupMessage struct {
	Group    [32]byte
	Sender   [32]byte
	MsgID    [16]byte
	Dir      Direction
	Sent     time.Time
	Received time.Time
	Body     string
	Status   uint8
	Flags    uint8
	// Seq is the local sequence number assigned when the message was
	// appended. It is ignored by AppendGroupMessage and is the cursor to pass
	// as "before" to GroupMessages for the previous page. Group and 1:1
	// messages share one sequence.
	Seq int64
}

// groupRecord is the encrypted form of Group.
type groupRecord struct {
	ID     []byte `cbor:"1,keyasint"`
	State  []byte `cbor:"2,keyasint"`
	Joined int64  `cbor:"3,keyasint"`
	Left   bool   `cbor:"4,keyasint"`
}

// ownSenderKeyRecord is the encrypted form of the own sender key state.
type ownSenderKeyRecord struct {
	Group []byte `cbor:"1,keyasint"`
	State []byte `cbor:"2,keyasint"`
}

// memberSenderKeyRecord is the encrypted form of a receiver sender key
// state.
type memberSenderKeyRecord struct {
	Group      []byte `cbor:"1,keyasint"`
	Member     []byte `cbor:"2,keyasint"`
	Generation uint32 `cbor:"3,keyasint"`
	State      []byte `cbor:"4,keyasint"`
}

// groupMessageRecord is the encrypted form of GroupMessage.
type groupMessageRecord struct {
	Group    []byte `cbor:"1,keyasint"`
	Sender   []byte `cbor:"2,keyasint"`
	MsgID    []byte `cbor:"3,keyasint"`
	Dir      uint8  `cbor:"4,keyasint"`
	Sent     int64  `cbor:"5,keyasint"`
	Received int64  `cbor:"6,keyasint"`
	Body     string `cbor:"7,keyasint"`
	Status   uint8  `cbor:"8,keyasint"`
	Flags    uint8  `cbor:"9,keyasint"`
}

func (g *Group) validate() error {
	if len(g.State) == 0 {
		return fmt.Errorf("%w: empty group state", ErrInvalid)
	}
	if len(g.State) > MaxGroupStateSize {
		return fmt.Errorf("%w: group state larger than %d bytes", ErrInvalid, MaxGroupStateSize)
	}
	return checkTime("Joined", g.Joined)
}

func (r *groupRecord) group() (Group, error) {
	var g Group
	if len(r.ID) != len(g.ID) {
		return Group{}, fmt.Errorf("%w: bad group ID length", ErrCorrupt)
	}
	if len(r.State) == 0 {
		return Group{}, fmt.Errorf("%w: empty group state", ErrCorrupt)
	}
	copy(g.ID[:], r.ID)
	g.State = r.State
	g.Joined = nanosToTime(r.Joined)
	g.Left = r.Left
	return g, nil
}

func (m *GroupMessage) validate() error {
	plain := Message{Dir: m.Dir, Status: m.Status, Body: m.Body, Sent: m.Sent, Received: m.Received}
	return plain.validate()
}

func (m *GroupMessage) record() groupMessageRecord {
	return groupMessageRecord{
		Group:    m.Group[:],
		Sender:   m.Sender[:],
		MsgID:    m.MsgID[:],
		Dir:      uint8(m.Dir),
		Sent:     timeToNanos(m.Sent),
		Received: timeToNanos(m.Received),
		Body:     m.Body,
		Status:   m.Status,
		Flags:    m.Flags,
	}
}

func (r *groupMessageRecord) message(seq int64) (GroupMessage, error) {
	var m GroupMessage
	if len(r.Group) != len(m.Group) || len(r.Sender) != len(m.Sender) || len(r.MsgID) != len(m.MsgID) {
		return GroupMessage{}, fmt.Errorf("%w: bad group message identifier length", ErrCorrupt)
	}
	copy(m.Group[:], r.Group)
	copy(m.Sender[:], r.Sender)
	copy(m.MsgID[:], r.MsgID)
	m.Dir = Direction(r.Dir)
	m.Sent = nanosToTime(r.Sent)
	m.Received = nanosToTime(r.Received)
	m.Body = r.Body
	m.Status = r.Status
	m.Flags = r.Flags
	m.Seq = seq
	return m, nil
}

// checkSenderKeyState reports ErrInvalid unless state holds between 1 and
// MaxSenderKeyStateSize bytes.
func checkSenderKeyState(state []byte) error {
	if len(state) == 0 {
		return fmt.Errorf("%w: empty sender key state", ErrInvalid)
	}
	if len(state) > MaxSenderKeyStateSize {
		return fmt.Errorf("%w: sender key state larger than %d bytes", ErrInvalid, MaxSenderKeyStateSize)
	}
	return nil
}

// PutGroup stores g, replacing any group with the same ID.
func (d *DB) PutGroup(ctx context.Context, g Group) error {
	if err := g.validate(); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.groupLookup(g.ID)
	plain, err := encode(groupRecord{ID: g.ID[:], State: g.State, Joined: timeToNanos(g.Joined), Left: g.Left})
	if err != nil {
		return err
	}
	defer clear(plain)
	sealed, err := d.keys.seal(plain, rowAAD(tableGroups, lookup, -1))
	if err != nil {
		return err
	}
	_, err = d.conn.ExecContext(ctx,
		`INSERT INTO chat_groups (lookup, value) VALUES (?, ?)
		 ON CONFLICT (lookup) DO UPDATE SET value = excluded.value`, lookup, sealed)
	if err != nil {
		return fmt.Errorf("clientdb: put group: %w", err)
	}
	return nil
}

// GetGroup returns the group with the given ID, or ErrNotFound.
func (d *DB) GetGroup(ctx context.Context, id [32]byte) (Group, error) {
	if err := d.acquire(); err != nil {
		return Group{}, err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.groupLookup(id)
	var sealed []byte
	err := d.conn.QueryRowContext(ctx, `SELECT value FROM chat_groups WHERE lookup = ?`, lookup).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	if err != nil {
		return Group{}, fmt.Errorf("clientdb: get group: %w", err)
	}
	return d.openGroup(lookup, sealed)
}

// ListGroups returns all stored groups, including those the user has left,
// sorted by Joined and then by ID.
func (d *DB) ListGroups(ctx context.Context) ([]Group, error) {
	if err := d.acquire(); err != nil {
		return nil, err
	}
	defer d.mu.RUnlock()

	rows, err := d.conn.QueryContext(ctx, `SELECT lookup, value FROM chat_groups`)
	if err != nil {
		return nil, fmt.Errorf("clientdb: list groups: %w", err)
	}
	defer rows.Close()
	var groups []Group
	for rows.Next() {
		var lookup, sealed []byte
		if err := rows.Scan(&lookup, &sealed); err != nil {
			return nil, fmt.Errorf("clientdb: list groups: %w", err)
		}
		g, err := d.openGroup(lookup, sealed)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("clientdb: list groups: %w", err)
	}
	slices.SortFunc(groups, func(a, b Group) int {
		return cmp.Or(a.Joined.Compare(b.Joined), bytes.Compare(a.ID[:], b.ID[:]))
	})
	return groups, nil
}

// DeleteGroup deletes the group with the given ID together with its
// messages and every sender key state stored for it, own and received, in
// one transaction, and then checkpoints the WAL (see [DB.DeleteSession]) so
// the deleted chain keys do not linger in the -wal file. It returns
// ErrNotFound if no such group exists; orphaned messages and sender keys of
// that ID are deleted regardless.
//
// The replay tombstones of the deleted messages are kept, as for
// [DB.DeleteContact].
func (d *DB) DeleteGroup(ctx context.Context, id [32]byte) error {
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.groupLookup(id)
	var deleted int64
	err := d.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM messages WHERE peer = ?`, lookup); err != nil {
			return fmt.Errorf("clientdb: delete group messages: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sender_keys WHERE grp = ?`, lookup); err != nil {
			return fmt.Errorf("clientdb: delete group sender keys: %w", err)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM chat_groups WHERE lookup = ?`, lookup)
		if err != nil {
			return fmt.Errorf("clientdb: delete group: %w", err)
		}
		deleted, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return err
	}
	d.checkpoint(ctx)
	if deleted == 0 {
		return ErrNotFound
	}
	return nil
}

// openGroup decrypts a group row and checks that it belongs to lookup.
func (d *DB) openGroup(lookup, sealed []byte) (Group, error) {
	plain, err := d.keys.open(sealed, rowAAD(tableGroups, lookup, -1))
	if err != nil {
		return Group{}, err
	}
	var rec groupRecord
	if err := decode(plain, &rec); err != nil {
		return Group{}, err
	}
	g, err := rec.group()
	if err != nil {
		return Group{}, err
	}
	if !bytes.Equal(d.keys.groupLookup(g.ID), lookup) {
		return Group{}, fmt.Errorf("%w: group ID does not match its row", ErrCorrupt)
	}
	return g, nil
}

// PutOwnSenderKey stores state as the own sender key state of group,
// replacing the previous one. The superseded state stays in the -wal file
// until the next checkpoint, like a superseded ratchet state.
func (d *DB) PutOwnSenderKey(ctx context.Context, group [32]byte, state []byte) error {
	if err := checkSenderKeyState(state); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	return d.withTx(ctx, func(tx *sql.Tx) error {
		return d.putOwnSenderKeyTx(ctx, tx, group, state)
	})
}

// GetOwnSenderKey returns the own sender key state of group, or
// ErrNotFound.
func (d *DB) GetOwnSenderKey(ctx context.Context, group [32]byte) ([]byte, error) {
	if err := d.acquire(); err != nil {
		return nil, err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.ownSenderKeyLookup(group)
	sealed, err := d.senderKeyRow(ctx, lookup)
	if err != nil {
		return nil, err
	}
	plain, err := d.keys.open(sealed, rowAAD(tableSenderKeys, lookup, -1))
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var rec ownSenderKeyRecord
	if err := decode(plain, &rec); err != nil {
		return nil, err
	}
	if !bytes.Equal(rec.Group, group[:]) || len(rec.State) == 0 {
		return nil, fmt.Errorf("%w: own sender key does not match its row", ErrCorrupt)
	}
	return rec.State, nil
}

// PutMemberSenderKey stores state as the receiver state of the sender key
// generation of member in group, replacing any state stored for the same
// (group, member, generation).
func (d *DB) PutMemberSenderKey(ctx context.Context, group, member [32]byte, generation uint32, state []byte) error {
	if err := checkSenderKeyState(state); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	return d.withTx(ctx, func(tx *sql.Tx) error {
		return d.putMemberSenderKeyTx(ctx, tx, group, member, generation, state)
	})
}

// GetMemberSenderKey returns the receiver state of the sender key
// generation of member in group, or ErrNotFound.
func (d *DB) GetMemberSenderKey(ctx context.Context, group, member [32]byte, generation uint32) ([]byte, error) {
	if err := d.acquire(); err != nil {
		return nil, err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.memberSenderKeyLookup(group, member, generation)
	sealed, err := d.senderKeyRow(ctx, lookup)
	if err != nil {
		return nil, err
	}
	plain, err := d.keys.open(sealed, rowAAD(tableSenderKeys, lookup, -1))
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var rec memberSenderKeyRecord
	if err := decode(plain, &rec); err != nil {
		return nil, err
	}
	if !bytes.Equal(rec.Group, group[:]) || !bytes.Equal(rec.Member, member[:]) || rec.Generation != generation || len(rec.State) == 0 {
		return nil, fmt.Errorf("%w: sender key does not match its row", ErrCorrupt)
	}
	return rec.State, nil
}

// DeleteMemberSenderKey deletes the receiver state of one sender key
// generation of member in group, for example once a newer generation has
// delivered a message, and checkpoints the WAL. It returns ErrNotFound if
// no such state is stored.
func (d *DB) DeleteMemberSenderKey(ctx context.Context, group, member [32]byte, generation uint32) error {
	return d.deleteSenderKeys(ctx, true, `DELETE FROM sender_keys WHERE lookup = ?`,
		d.keys.memberSenderKeyLookup(group, member, generation))
}

// DeleteMemberSenderKeys deletes the receiver states of every sender key
// generation of member in group, for example after the member was removed,
// and checkpoints the WAL. Deleting nothing is not an error.
func (d *DB) DeleteMemberSenderKeys(ctx context.Context, group, member [32]byte) error {
	return d.deleteSenderKeys(ctx, false, `DELETE FROM sender_keys WHERE grp = ? AND member = ?`,
		d.keys.groupLookup(group), d.keys.groupMemberLookup(group, member))
}

// DeleteGroupSenderKeys deletes every sender key state of group, the own
// one and those of all members, and checkpoints the WAL. Deleting nothing
// is not an error.
func (d *DB) DeleteGroupSenderKeys(ctx context.Context, group [32]byte) error {
	return d.deleteSenderKeys(ctx, false, `DELETE FROM sender_keys WHERE grp = ?`, d.keys.groupLookup(group))
}

// deleteSenderKeys runs a delete statement on sender_keys and checkpoints
// the WAL. With mustExist it returns ErrNotFound if no row was deleted.
func (d *DB) deleteSenderKeys(ctx context.Context, mustExist bool, query string, args ...any) error {
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	res, err := d.conn.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("clientdb: delete sender keys: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("clientdb: delete sender keys: %w", err)
	}
	if n == 0 {
		if mustExist {
			return ErrNotFound
		}
		return nil
	}
	d.checkpoint(ctx)
	return nil
}

// senderKeyRow returns the sealed value of the sender key row lookup, or
// ErrNotFound.
func (d *DB) senderKeyRow(ctx context.Context, lookup []byte) ([]byte, error) {
	var sealed []byte
	err := d.conn.QueryRowContext(ctx, `SELECT value FROM sender_keys WHERE lookup = ?`, lookup).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("clientdb: get sender key: %w", err)
	}
	return sealed, nil
}

// putOwnSenderKeyTx encrypts and upserts the own sender key state of group
// inside tx. state must have been validated.
func (d *DB) putOwnSenderKeyTx(ctx context.Context, tx *sql.Tx, group [32]byte, state []byte) error {
	lookup := d.keys.ownSenderKeyLookup(group)
	plain, err := encode(ownSenderKeyRecord{Group: group[:], State: state})
	if err != nil {
		return err
	}
	defer clear(plain)
	return d.upsertSenderKeyTx(ctx, tx, lookup, d.keys.groupLookup(group), []byte{}, plain)
}

// putMemberSenderKeyTx encrypts and upserts a receiver sender key state
// inside tx. state must have been validated.
func (d *DB) putMemberSenderKeyTx(ctx context.Context, tx *sql.Tx, group, member [32]byte, generation uint32, state []byte) error {
	lookup := d.keys.memberSenderKeyLookup(group, member, generation)
	plain, err := encode(memberSenderKeyRecord{Group: group[:], Member: member[:], Generation: generation, State: state})
	if err != nil {
		return err
	}
	defer clear(plain)
	return d.upsertSenderKeyTx(ctx, tx, lookup, d.keys.groupLookup(group), d.keys.groupMemberLookup(group, member), plain)
}

// upsertSenderKeyTx seals plain for the sender key row lookup and upserts
// it with its group and member columns.
func (d *DB) upsertSenderKeyTx(ctx context.Context, tx *sql.Tx, lookup, groupColumn, memberColumn, plain []byte) error {
	sealed, err := d.keys.seal(plain, rowAAD(tableSenderKeys, lookup, -1))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO sender_keys (lookup, grp, member, value) VALUES (?, ?, ?, ?)
		 ON CONFLICT (lookup) DO UPDATE SET value = excluded.value`, lookup, groupColumn, memberColumn, sealed)
	if err != nil {
		return fmt.Errorf("clientdb: put sender key: %w", err)
	}
	return nil
}

// AppendGroupMessage stores m at the end of its group conversation and
// assigns it the next local sequence number. A message with the same
// (Group, Sender, MsgID) that is stored, or was stored and later removed by
// DeleteGroup, yields ErrDuplicate; like [DB.AppendMessage] it records a
// replay tombstone that deletion keeps. m.Seq is ignored.
func (d *DB) AppendGroupMessage(ctx context.Context, m GroupMessage) error {
	if err := m.validate(); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	return d.withTx(ctx, func(tx *sql.Tx) error {
		return d.appendGroupMessageTx(ctx, tx, m)
	})
}

// HasGroupMessage reports whether a group message with (group, sender,
// msgID) was ever appended, including one that DeleteGroup has removed,
// matching the duplicate check of AppendGroupMessage.
func (d *DB) HasGroupMessage(ctx context.Context, group, sender [32]byte, msgID [16]byte) (bool, error) {
	if err := d.acquire(); err != nil {
		return false, err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.groupMessageLookup(group, sender, msgID)
	var exists int
	err := d.conn.QueryRowContext(ctx,
		`SELECT 1 FROM seen WHERE lookup = ? UNION ALL SELECT 1 FROM messages WHERE lookup = ? LIMIT 1`,
		lookup, lookup).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("clientdb: has group message: %w", err)
	}
	return true, nil
}

// GroupMessages returns up to limit messages of group in chronological
// (sequence) order, paged like [DB.Messages]: with before == 0 the latest
// messages, otherwise only messages with Seq < before. limit must be
// positive and is capped at MaxPageSize.
func (d *DB) GroupMessages(ctx context.Context, group [32]byte, limit int, before int64) ([]GroupMessage, error) {
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

	groupLookup := d.keys.groupLookup(group)
	rows, err := d.conn.QueryContext(ctx,
		`SELECT seq, lookup, value FROM messages
		 WHERE peer = ? AND (? = 0 OR seq < ?)
		 ORDER BY seq DESC LIMIT ?`, groupLookup, before, before, limit)
	if err != nil {
		return nil, fmt.Errorf("clientdb: group messages: %w", err)
	}
	defer rows.Close()
	var msgs []GroupMessage
	for rows.Next() {
		var seq int64
		var lookup, sealed []byte
		if err := rows.Scan(&seq, &lookup, &sealed); err != nil {
			return nil, fmt.Errorf("clientdb: group messages: %w", err)
		}
		m, err := d.openGroupMessage(groupLookup, lookup, seq, sealed)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("clientdb: group messages: %w", err)
	}
	slices.Reverse(msgs)
	return msgs, nil
}

// CommitGroupReceive atomically records the processing of a received group
// message: it appends m and stores receiverState as the receiver state of
// the sender key generation of member in group. Either both changes are
// committed or neither is.
//
// m must be Incoming, m.Group must equal group and m.Sender must equal
// member. If the message was already appended, CommitGroupReceive returns
// ErrDuplicate and writes nothing, so the receiver state is not advanced.
func (d *DB) CommitGroupReceive(ctx context.Context, group, member [32]byte, generation uint32, receiverState []byte, m GroupMessage) error {
	if m.Dir != Incoming {
		return fmt.Errorf("%w: CommitGroupReceive needs an incoming message", ErrInvalid)
	}
	if m.Group != group || m.Sender != member {
		return fmt.Errorf("%w: message belongs to another group or sender", ErrInvalid)
	}
	if err := checkSenderKeyState(receiverState); err != nil {
		return err
	}
	if err := m.validate(); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	return d.withTx(ctx, func(tx *sql.Tx) error {
		if err := d.appendGroupMessageTx(ctx, tx, m); err != nil {
			return err
		}
		return d.putMemberSenderKeyTx(ctx, tx, group, member, generation, receiverState)
	})
}

// CommitGroupSend atomically appends the outgoing message m and stores
// ownState as the own sender key state of m.Group, so the state that
// produced a ciphertext is saved before the ciphertext is handed to the
// relay. m must be Outgoing. On ErrDuplicate nothing is written.
func (d *DB) CommitGroupSend(ctx context.Context, ownState []byte, m GroupMessage) error {
	if m.Dir != Outgoing {
		return fmt.Errorf("%w: CommitGroupSend needs an outgoing message", ErrInvalid)
	}
	if err := checkSenderKeyState(ownState); err != nil {
		return err
	}
	if err := m.validate(); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	return d.withTx(ctx, func(tx *sql.Tx) error {
		if err := d.appendGroupMessageTx(ctx, tx, m); err != nil {
			return err
		}
		return d.putOwnSenderKeyTx(ctx, tx, m.Group, ownState)
	})
}

// appendGroupMessageTx is the body of AppendGroupMessage inside the
// caller's transaction. It returns ErrDuplicate before writing anything if
// the message was already appended. m must have been validated.
func (d *DB) appendGroupMessageTx(ctx context.Context, tx *sql.Tx, m GroupMessage) error {
	groupLookup := d.keys.groupLookup(m.Group)
	lookup := d.keys.groupMessageLookup(m.Group, m.Sender, m.MsgID)
	plain, err := encode(m.record())
	if err != nil {
		return err
	}
	defer clear(plain)
	var exists int
	err = tx.QueryRowContext(ctx,
		`SELECT 1 FROM seen WHERE lookup = ? UNION ALL SELECT 1 FROM messages WHERE lookup = ? LIMIT 1`,
		lookup, lookup).Scan(&exists)
	if err == nil {
		return ErrDuplicate
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("clientdb: append group message: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO seen (lookup) VALUES (?)`, lookup); err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return fmt.Errorf("clientdb: append group message: %w", err)
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO messages (peer, lookup, value) VALUES (?, ?, x'')`, groupLookup, lookup)
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("clientdb: append group message: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("clientdb: append group message: %w", err)
	}
	sealed, err := d.keys.seal(plain, rowAAD(tableGroupMessages, lookup, seq))
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE messages SET value = ? WHERE seq = ?`, sealed, seq); err != nil {
		return fmt.Errorf("clientdb: append group message: %w", err)
	}
	return nil
}

// UpdateGroupMessageStatus changes the status of the group message
// identified by (group, sender, msgID), for example once the relay has
// answered a send. It returns [ErrNotFound] if there is no such message.
func (d *DB) UpdateGroupMessageStatus(ctx context.Context, group, sender [32]byte, msgID [16]byte, status uint8) error {
	if !validStatus(status) {
		return fmt.Errorf("%w: unknown status %d", ErrInvalid, status)
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	groupLookup := d.keys.groupLookup(group)
	lookup := d.keys.groupMessageLookup(group, sender, msgID)
	return d.withTx(ctx, func(tx *sql.Tx) error {
		var seq int64
		var rowGroup, sealed []byte
		err := tx.QueryRowContext(ctx, `SELECT seq, peer, value FROM messages WHERE lookup = ?`, lookup).Scan(&seq, &rowGroup, &sealed)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("clientdb: update group message status: %w", err)
		}
		if !bytes.Equal(rowGroup, groupLookup) {
			return fmt.Errorf("%w: group message row has the wrong group", ErrCorrupt)
		}
		m, err := d.openGroupMessage(groupLookup, lookup, seq, sealed)
		if err != nil {
			return err
		}
		m.Status = status
		plain, err := encode(m.record())
		if err != nil {
			return err
		}
		defer clear(plain)
		resealed, err := d.keys.seal(plain, rowAAD(tableGroupMessages, lookup, seq))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE messages SET value = ? WHERE seq = ?`, resealed, seq); err != nil {
			return fmt.Errorf("clientdb: update group message status: %w", err)
		}
		return nil
	})
}

// openGroupMessage decrypts a group message row and checks that its
// identifiers match the row's peer and lookup columns.
func (d *DB) openGroupMessage(groupLookup, lookup []byte, seq int64, sealed []byte) (GroupMessage, error) {
	plain, err := d.keys.open(sealed, rowAAD(tableGroupMessages, lookup, seq))
	if err != nil {
		return GroupMessage{}, err
	}
	var rec groupMessageRecord
	if err := decode(plain, &rec); err != nil {
		return GroupMessage{}, err
	}
	m, err := rec.message(seq)
	if err != nil {
		return GroupMessage{}, err
	}
	if !bytes.Equal(d.keys.groupLookup(m.Group), groupLookup) ||
		!bytes.Equal(d.keys.groupMessageLookup(m.Group, m.Sender, m.MsgID), lookup) {
		return GroupMessage{}, fmt.Errorf("%w: group message identifiers do not match their row", ErrCorrupt)
	}
	return m, nil
}
