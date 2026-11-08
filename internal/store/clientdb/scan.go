package clientdb

import (
	"context"
	"fmt"
	"slices"
)

// ScanPage is one page of a conversation read by ScanMessages or
// ScanGroupMessages.
type ScanPage[M any] struct {
	// Messages are the rows that decrypted and decoded, in chronological
	// (sequence) order.
	Messages []M
	// Rows is how many rows were read, including skipped ones. A page with
	// fewer rows than the limit is the last one.
	Rows int
	// Skipped is how many rows could not be decrypted or decoded.
	Skipped int
	// Next is the cursor for the following (older) page: the Seq of the
	// oldest row read, or 0 when no row was read.
	Next int64
}

// ScanMessages reads a page of the conversation with peer like
// [DB.Messages], but skips and counts rows that fail to decrypt or decode
// instead of failing the whole page. It is meant for best-effort scans such
// as search, where one damaged row must not hide the rest of the history.
func (d *DB) ScanMessages(ctx context.Context, peer [32]byte, limit int, before int64) (ScanPage[Message], error) {
	if err := d.acquire(); err != nil {
		return ScanPage[Message]{}, err
	}
	defer d.mu.RUnlock()
	peerLookup := d.keys.contactLookup(peer)
	return scanRows(ctx, d, peerLookup, limit, before, func(lookup []byte, seq int64, sealed []byte) (Message, error) {
		return d.openMessage(peerLookup, lookup, seq, sealed)
	})
}

// ScanGroupMessages reads a page of group like [DB.GroupMessages], skipping
// and counting rows that fail to decrypt or decode, like ScanMessages.
func (d *DB) ScanGroupMessages(ctx context.Context, group [32]byte, limit int, before int64) (ScanPage[GroupMessage], error) {
	if err := d.acquire(); err != nil {
		return ScanPage[GroupMessage]{}, err
	}
	defer d.mu.RUnlock()
	groupLookup := d.keys.groupLookup(group)
	return scanRows(ctx, d, groupLookup, limit, before, func(lookup []byte, seq int64, sealed []byte) (GroupMessage, error) {
		return d.openGroupMessage(groupLookup, lookup, seq, sealed)
	})
}

// scanRows reads up to limit message rows of peerLookup older than before
// (or the latest ones when before is 0) and opens each with open. The
// caller holds the read lock.
func scanRows[M any](ctx context.Context, d *DB, peerLookup []byte, limit int, before int64, open func(lookup []byte, seq int64, sealed []byte) (M, error)) (ScanPage[M], error) {
	var page ScanPage[M]
	if limit <= 0 {
		return page, fmt.Errorf("%w: limit must be positive", ErrInvalid)
	}
	if before < 0 {
		return page, fmt.Errorf("%w: negative cursor", ErrInvalid)
	}
	limit = min(limit, MaxPageSize)
	rows, err := d.conn.QueryContext(ctx,
		`SELECT seq, lookup, value FROM messages
		 WHERE peer = ? AND (? = 0 OR seq < ?)
		 ORDER BY seq DESC LIMIT ?`, peerLookup, before, before, limit)
	if err != nil {
		return page, fmt.Errorf("clientdb: scan messages: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var lookup, sealed []byte
		if err := rows.Scan(&seq, &lookup, &sealed); err != nil {
			return ScanPage[M]{}, fmt.Errorf("clientdb: scan messages: %w", err)
		}
		page.Rows++
		page.Next = seq
		m, err := open(lookup, seq, sealed)
		if err != nil {
			page.Skipped++
			continue
		}
		page.Messages = append(page.Messages, m)
	}
	if err := rows.Err(); err != nil {
		return ScanPage[M]{}, fmt.Errorf("clientdb: scan messages: %w", err)
	}
	slices.Reverse(page.Messages)
	return page, nil
}
