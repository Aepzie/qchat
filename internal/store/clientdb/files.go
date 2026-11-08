package clientdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MaxFileOfferSize bounds FileTransfer.Offer.
const MaxFileOfferSize = 4 << 10

// File transfer states.
const (
	// FileReceiving: chunks are still arriving.
	FileReceiving uint8 = 1
	// FileComplete: every chunk arrived and the file was verified (for a
	// received file), or every chunk was handed to the relay (for a sent
	// one).
	FileComplete uint8 = 2
	// FileFailed: the transfer was abandoned, or the file failed
	// verification.
	FileFailed uint8 = 3
	// FileExpired: the transfer did not complete in time.
	FileExpired uint8 = 4
	// FileSending: chunks are being handed to the relay.
	FileSending uint8 = 5
)

// FileTransfer is the local record of a file sent or received in a
// conversation. The offer, with the file key, is kept here, encrypted under
// the database key; the file content lives in the profile's file store
// (package filexfer) under Local.
type FileTransfer struct {
	// Conv is the contact or group the file was sent in, and Group tells
	// which.
	Conv  [32]byte
	Group bool
	// Sender is the identity that offered the file (the user for an
	// outgoing file).
	Sender [32]byte
	// FileID is the sender's file ID and MsgID the message ID of its offer.
	FileID [16]byte
	MsgID  [16]byte
	// Local names the file in the store.
	Local [16]byte
	Dir   Direction
	// Offer is the encoded file offer, including the file key.
	Offer []byte
	State uint8
	// Done counts the chunks received or sent so far.
	Done    uint32
	Created time.Time
}

type fileRecord struct {
	Conv    []byte `cbor:"1,keyasint"`
	Group   bool   `cbor:"2,keyasint"`
	Sender  []byte `cbor:"3,keyasint"`
	FileID  []byte `cbor:"4,keyasint"`
	MsgID   []byte `cbor:"5,keyasint"`
	Local   []byte `cbor:"6,keyasint"`
	Dir     uint8  `cbor:"7,keyasint"`
	Offer   []byte `cbor:"8,keyasint"`
	State   uint8  `cbor:"9,keyasint"`
	Done    uint32 `cbor:"10,keyasint"`
	Created int64  `cbor:"11,keyasint"`
}

func (f *FileTransfer) validate() error {
	switch {
	case f.Dir != Outgoing && f.Dir != Incoming:
		return fmt.Errorf("%w: unknown direction %d", ErrInvalid, f.Dir)
	case f.State < FileReceiving || f.State > FileSending:
		return fmt.Errorf("%w: unknown file state %d", ErrInvalid, f.State)
	case len(f.Offer) == 0 || len(f.Offer) > MaxFileOfferSize:
		return fmt.Errorf("%w: file offer must be 1 to %d bytes", ErrInvalid, MaxFileOfferSize)
	}
	return checkTime("Created", f.Created)
}

func (f *FileTransfer) record() fileRecord {
	return fileRecord{Conv: f.Conv[:], Group: f.Group, Sender: f.Sender[:], FileID: f.FileID[:], MsgID: f.MsgID[:], Local: f.Local[:],
		Dir: uint8(f.Dir), Offer: f.Offer, State: f.State, Done: f.Done, Created: timeToNanos(f.Created)}
}

func (r *fileRecord) transfer() (FileTransfer, error) {
	if len(r.Conv) != 32 || len(r.Sender) != 32 || len(r.FileID) != 16 || len(r.MsgID) != 16 || len(r.Local) != 16 {
		return FileTransfer{}, fmt.Errorf("%w: bad file transfer identifier length", ErrCorrupt)
	}
	return FileTransfer{Conv: [32]byte(r.Conv), Group: r.Group, Sender: [32]byte(r.Sender), FileID: [16]byte(r.FileID), MsgID: [16]byte(r.MsgID),
		Local: [16]byte(r.Local), Dir: Direction(r.Dir), Offer: r.Offer, State: r.State, Done: r.Done, Created: nanosToTime(r.Created)}, nil
}

// fileLookup and fileMessageLookup return the lookup and msg columns of a
// file transfer.
func (k *keys) fileLookup(conv, sender [32]byte, fileID [16]byte) []byte {
	return k.lookup(labelFile, conv[:], sender[:], fileID[:])
}

func (k *keys) fileMessageLookup(conv, sender [32]byte, msgID [16]byte) []byte {
	return k.lookup(labelFileMessage, conv[:], sender[:], msgID[:])
}

// PutFileTransfer stores f, replacing the record of the same (Conv,
// Sender, FileID).
func (d *DB) PutFileTransfer(ctx context.Context, f FileTransfer) error {
	if err := f.validate(); err != nil {
		return err
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.fileLookup(f.Conv, f.Sender, f.FileID)
	plain, err := encode(f.record())
	if err != nil {
		return err
	}
	defer clear(plain)
	sealed, err := d.keys.seal(plain, rowAAD(tableFiles, lookup, -1))
	if err != nil {
		return err
	}
	_, err = d.conn.ExecContext(ctx,
		`INSERT INTO files (lookup, msg, value) VALUES (?, ?, ?)
		 ON CONFLICT (lookup) DO UPDATE SET msg = excluded.msg, value = excluded.value`,
		lookup, d.keys.fileMessageLookup(f.Conv, f.Sender, f.MsgID), sealed)
	if err != nil {
		return fmt.Errorf("clientdb: put file transfer: %w", err)
	}
	return nil
}

// GetFileTransfer returns the transfer of fileID offered by sender in conv,
// or ErrNotFound.
func (d *DB) GetFileTransfer(ctx context.Context, conv, sender [32]byte, fileID [16]byte) (FileTransfer, error) {
	if err := d.acquire(); err != nil {
		return FileTransfer{}, err
	}
	defer d.mu.RUnlock()
	lookup := d.keys.fileLookup(conv, sender, fileID)
	var sealed []byte
	err := d.conn.QueryRowContext(ctx, `SELECT value FROM files WHERE lookup = ?`, lookup).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return FileTransfer{}, ErrNotFound
	}
	if err != nil {
		return FileTransfer{}, fmt.Errorf("clientdb: get file transfer: %w", err)
	}
	return d.openFile(lookup, sealed)
}

// FileTransferByMessage returns the transfer offered by the message msgID
// of sender in conv, or ErrNotFound.
func (d *DB) FileTransferByMessage(ctx context.Context, conv, sender [32]byte, msgID [16]byte) (FileTransfer, error) {
	if err := d.acquire(); err != nil {
		return FileTransfer{}, err
	}
	defer d.mu.RUnlock()
	msg := d.keys.fileMessageLookup(conv, sender, msgID)
	rows, err := d.conn.QueryContext(ctx, `SELECT lookup, value FROM files WHERE msg = ?`, msg)
	if err != nil {
		return FileTransfer{}, fmt.Errorf("clientdb: file transfer by message: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var lookup, sealed []byte
		if err := rows.Scan(&lookup, &sealed); err != nil {
			return FileTransfer{}, fmt.Errorf("clientdb: file transfer by message: %w", err)
		}
		f, err := d.openFile(lookup, sealed)
		if err != nil {
			return FileTransfer{}, err
		}
		if f.MsgID == msgID {
			return f, nil
		}
	}
	if err := rows.Err(); err != nil {
		return FileTransfer{}, fmt.Errorf("clientdb: file transfer by message: %w", err)
	}
	return FileTransfer{}, ErrNotFound
}

// ListFileTransfers returns every file transfer record.
func (d *DB) ListFileTransfers(ctx context.Context) ([]FileTransfer, error) {
	if err := d.acquire(); err != nil {
		return nil, err
	}
	defer d.mu.RUnlock()
	rows, err := d.conn.QueryContext(ctx, `SELECT lookup, value FROM files`)
	if err != nil {
		return nil, fmt.Errorf("clientdb: list file transfers: %w", err)
	}
	defer rows.Close()
	var out []FileTransfer
	for rows.Next() {
		var lookup, sealed []byte
		if err := rows.Scan(&lookup, &sealed); err != nil {
			return nil, fmt.Errorf("clientdb: list file transfers: %w", err)
		}
		f, err := d.openFile(lookup, sealed)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("clientdb: list file transfers: %w", err)
	}
	return out, nil
}

// DeleteFileTransfer deletes a transfer record, which holds a file key, and
// checkpoints the WAL so that the key leaves the files (see the package
// documentation). Deleting a missing record is not an error.
func (d *DB) DeleteFileTransfer(ctx context.Context, conv, sender [32]byte, fileID [16]byte) error {
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()
	if _, err := d.conn.ExecContext(ctx, `DELETE FROM files WHERE lookup = ?`, d.keys.fileLookup(conv, sender, fileID)); err != nil {
		return fmt.Errorf("clientdb: delete file transfer: %w", err)
	}
	d.checkpoint(ctx)
	return nil
}

func (d *DB) openFile(lookup, sealed []byte) (FileTransfer, error) {
	plain, err := d.keys.open(sealed, rowAAD(tableFiles, lookup, -1))
	if err != nil {
		return FileTransfer{}, err
	}
	defer clear(plain)
	var rec fileRecord
	if err := decode(plain, &rec); err != nil {
		return FileTransfer{}, err
	}
	f, err := rec.transfer()
	if err != nil {
		return FileTransfer{}, err
	}
	if !bytes.Equal(d.keys.fileLookup(f.Conv, f.Sender, f.FileID), lookup) {
		return FileTransfer{}, fmt.Errorf("%w: file transfer identifiers do not match their row", ErrCorrupt)
	}
	return f, nil
}
