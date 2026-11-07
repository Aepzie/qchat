package clientdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Well-known setting names.
const (
	// SettingDisplayName holds the user's own display name.
	SettingDisplayName = "self.display_name"
)

// PutSetting stores value under name, replacing any previous value. Names are
// 1 to MaxSettingNameLen bytes of [a-z0-9._-]; values are at most
// MaxSettingValueSize bytes.
func (d *DB) PutSetting(ctx context.Context, name string, value []byte) error {
	if err := validateSettingName(name); err != nil {
		return err
	}
	if len(value) > MaxSettingValueSize {
		return fmt.Errorf("%w: setting value larger than %d bytes", ErrInvalid, MaxSettingValueSize)
	}
	if err := d.acquire(); err != nil {
		return err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.settingLookup(name)
	plain, err := encode(settingRecord{Name: name, Value: value})
	if err != nil {
		return err
	}
	sealed, err := d.keys.seal(plain, rowAAD(tableSettings, lookup, -1))
	if err != nil {
		return err
	}
	_, err = d.conn.ExecContext(ctx,
		`INSERT INTO settings (lookup, value) VALUES (?, ?)
		 ON CONFLICT (lookup) DO UPDATE SET value = excluded.value`, lookup, sealed)
	if err != nil {
		return fmt.Errorf("clientdb: put setting: %w", err)
	}
	return nil
}

// GetSetting returns the value stored under name, or ErrNotFound.
func (d *DB) GetSetting(ctx context.Context, name string) ([]byte, error) {
	if err := validateSettingName(name); err != nil {
		return nil, err
	}
	if err := d.acquire(); err != nil {
		return nil, err
	}
	defer d.mu.RUnlock()

	lookup := d.keys.settingLookup(name)
	var sealed []byte
	err := d.conn.QueryRowContext(ctx, `SELECT value FROM settings WHERE lookup = ?`, lookup).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("clientdb: get setting: %w", err)
	}
	plain, err := d.keys.open(sealed, rowAAD(tableSettings, lookup, -1))
	if err != nil {
		return nil, err
	}
	var rec settingRecord
	if err := decode(plain, &rec); err != nil {
		return nil, err
	}
	if rec.Name != name {
		return nil, fmt.Errorf("%w: setting name does not match its row", ErrCorrupt)
	}
	if rec.Value == nil {
		rec.Value = []byte{}
	}
	return rec.Value, nil
}
