package serverdb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Bounds for CreateInvite.
const (
	// MaxInviteTTL is the longest validity of an invite.
	MaxInviteTTL = 30 * 24 * time.Hour
	// MaxInviteUses is the largest number of uses of one invite.
	MaxInviteUses = 1000
)

const (
	inviteCodeBytes = 16
	inviteGroupSize = 4
	inviteSeparator = '-'
)

// inviteEncoding is the RFC 4648 base32 alphabet without padding.
var inviteEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Invite describes a stored invite without revealing its code.
type Invite struct {
	// ExpiresAt is the first second at which the invite is no longer valid.
	ExpiresAt time.Time
	// UsesLeft is the number of registrations the invite still allows.
	UsesLeft int
}

// Expired reports whether the invite is no longer valid at now.
func (i Invite) Expired(now time.Time) bool {
	return now.Unix() >= i.ExpiresAt.Unix()
}

// CreateInvite stores a new invite valid for ttl (between one second and
// MaxInviteTTL; the expiry is rounded down to a whole second) that allows
// uses registrations (between 1 and MaxInviteUses), and returns its code in
// grouped form. The code is not stored and cannot be retrieved again.
func (db *DB) CreateInvite(ctx context.Context, ttl time.Duration, uses int) (string, error) {
	if ttl < time.Second || ttl > MaxInviteTTL {
		return "", fmt.Errorf("%w: invite validity %s not between 1s and %s", ErrInvalidArgument, ttl, MaxInviteTTL)
	}
	if uses < 1 || uses > MaxInviteUses {
		return "", fmt.Errorf("%w: invite uses %d not between 1 and %d", ErrInvalidArgument, uses, MaxInviteUses)
	}
	raw := make([]byte, inviteCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("serverdb: generate invite code: %w", err)
	}
	normalized := inviteEncoding.EncodeToString(raw)
	clear(raw)
	hash := sha256.Sum256([]byte(normalized))
	expiresAt := db.now().Add(ttl).Unix()
	if _, err := db.sql.ExecContext(ctx, "INSERT INTO invites (code_hash, expires_at, uses_left) VALUES (?, ?, ?)", hash[:], expiresAt, uses); err != nil {
		return "", fmt.Errorf("serverdb: insert invite: %w", err)
	}
	return groupInviteCode(normalized), nil
}

// RedeemInvite uses up one use of the invite code if it is valid at now.
// When the last use is redeemed the invite is deleted. Unknown, malformed,
// expired and used-up codes all fail with ErrInviteInvalid.
func (db *DB) RedeemInvite(ctx context.Context, code string, now time.Time) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		return redeemInvite(ctx, tx, code, now)
	})
}

// ListInvites returns all stored invites, including expired ones that have
// not been pruned yet, ordered by expiry. Codes are never returned.
func (db *DB) ListInvites(ctx context.Context) ([]Invite, error) {
	rows, err := db.sql.QueryContext(ctx, "SELECT expires_at, uses_left FROM invites ORDER BY expires_at")
	if err != nil {
		return nil, fmt.Errorf("serverdb: list invites: %w", err)
	}
	defer rows.Close()
	var invites []Invite
	for rows.Next() {
		var expiresAt int64
		var usesLeft int
		if err := rows.Scan(&expiresAt, &usesLeft); err != nil {
			return nil, fmt.Errorf("serverdb: list invites: %w", err)
		}
		invites = append(invites, Invite{ExpiresAt: time.Unix(expiresAt, 0).UTC(), UsesLeft: usesLeft})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("serverdb: list invites: %w", err)
	}
	return invites, nil
}

// PruneExpiredInvites deletes the invites that are expired at now, as well
// as any without uses left, and returns how many it deleted.
func (db *DB) PruneExpiredInvites(ctx context.Context, now time.Time) (int64, error) {
	result, err := db.sql.ExecContext(ctx, "DELETE FROM invites WHERE expires_at <= ? OR uses_left <= 0", now.Unix())
	if err != nil {
		return 0, fmt.Errorf("serverdb: prune invites: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("serverdb: prune invites: %w", err)
	}
	return deleted, nil
}

// redeemInvite decrements the uses of a valid invite inside tx, deleting
// it when no use is left.
func redeemInvite(ctx context.Context, tx *sql.Tx, code string, now time.Time) error {
	normalized, ok := normalizeInviteCode(code)
	if !ok {
		return ErrInviteInvalid
	}
	hash := sha256.Sum256([]byte(normalized))
	var usesLeft int
	err := tx.QueryRowContext(ctx,
		"UPDATE invites SET uses_left = uses_left - 1 WHERE code_hash = ? AND uses_left > 0 AND expires_at > ? RETURNING uses_left",
		hash[:], now.Unix()).Scan(&usesLeft)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInviteInvalid
	}
	if err != nil {
		return fmt.Errorf("serverdb: redeem invite: %w", err)
	}
	if usesLeft > 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM invites WHERE code_hash = ?", hash[:]); err != nil {
		return fmt.Errorf("serverdb: delete used invite: %w", err)
	}
	return nil
}

// normalizeInviteCode removes separators and white space, upper-cases the
// code and checks that it is a well-formed 128-bit base32 code. A code whose
// unused trailing bits are not zero is rejected, so each code has exactly
// one normalized form.
func normalizeInviteCode(code string) (string, bool) {
	normalized := strings.Map(func(r rune) rune {
		if r == inviteSeparator || unicode.IsSpace(r) {
			return -1
		}
		if 'a' <= r && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}, code)
	if len(normalized) != inviteEncoding.EncodedLen(inviteCodeBytes) {
		return "", false
	}
	raw, err := inviteEncoding.DecodeString(normalized)
	if err != nil || len(raw) != inviteCodeBytes {
		return "", false
	}
	canonical := inviteEncoding.EncodeToString(raw) == normalized
	clear(raw)
	if !canonical {
		return "", false
	}
	return normalized, true
}

// groupInviteCode inserts a separator after every inviteGroupSize
// characters.
func groupInviteCode(normalized string) string {
	var b strings.Builder
	for i, r := range normalized {
		if i > 0 && i%inviteGroupSize == 0 {
			b.WriteRune(inviteSeparator)
		}
		b.WriteRune(r)
	}
	return b.String()
}
