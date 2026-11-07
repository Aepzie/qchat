package serverdb

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var groupedCodePattern = regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}-[A-Z2-7]{2}$`)

func fixedClock(db *DB, at time.Time) {
	db.now = func() time.Time { return at }
}

func TestCreateInviteFormatAndStorage(t *testing.T) {
	db, path := openTestDB(t)
	ctx := context.Background()
	start := time.Unix(1_800_000_000, 700_000_000)
	fixedClock(db, start)

	code, err := db.CreateInvite(ctx, 72*time.Hour, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !groupedCodePattern.MatchString(code) {
		t.Fatalf("code %q is not grouped base32", code)
	}
	other, err := db.CreateInvite(ctx, time.Hour, 1)
	if err != nil || other == code {
		t.Fatalf("second code %q, %v", other, err)
	}

	invites, err := db.ListInvites(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []Invite{
		{ExpiresAt: time.Unix(1_800_000_000+3600, 0).UTC(), UsesLeft: 1},
		{ExpiresAt: time.Unix(1_800_000_000+72*3600, 0).UTC(), UsesLeft: 3},
	}
	if len(invites) != len(want) || invites[0] != want[0] || invites[1] != want[1] {
		t.Fatalf("ListInvites = %+v, want %+v", invites, want)
	}

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var dump string
	if err := conn.QueryRow("SELECT group_concat(hex(code_hash) || expires_at || uses_left) FROM invites").Scan(&dump); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{code, other} {
		normalized := strings.ReplaceAll(c, "-", "")
		if strings.Contains(dump, normalized) {
			t.Fatalf("invite code stored in clear: %s", dump)
		}
	}
}

func TestCreateInviteBounds(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	bad := []struct {
		ttl  time.Duration
		uses int
	}{
		{0, 1}, {-time.Hour, 1}, {999 * time.Millisecond, 1}, {MaxInviteTTL + time.Second, 1},
		{time.Hour, 0}, {time.Hour, -1}, {time.Hour, MaxInviteUses + 1},
	}
	for _, tc := range bad {
		if _, err := db.CreateInvite(ctx, tc.ttl, tc.uses); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("CreateInvite(%s, %d): %v, want ErrInvalidArgument", tc.ttl, tc.uses, err)
		}
	}
	for _, tc := range []struct {
		ttl  time.Duration
		uses int
	}{{time.Second, 1}, {MaxInviteTTL, MaxInviteUses}} {
		if _, err := db.CreateInvite(ctx, tc.ttl, tc.uses); err != nil {
			t.Errorf("CreateInvite(%s, %d): %v", tc.ttl, tc.uses, err)
		}
	}
}

func TestRedeemInviteLifecycle(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	start := time.Unix(1_800_000_000, 0)
	fixedClock(db, start)
	code, err := db.CreateInvite(ctx, time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.RedeemInvite(ctx, code, start); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if invites, _ := db.ListInvites(ctx); len(invites) != 1 || invites[0].UsesLeft != 1 {
		t.Fatalf("after first use: %+v", invites)
	}
	if err := db.RedeemInvite(ctx, code, start.Add(time.Hour-time.Second)); err != nil {
		t.Fatalf("second use just before expiry: %v", err)
	}
	if invites, _ := db.ListInvites(ctx); len(invites) != 0 {
		t.Fatalf("used-up invite not deleted: %+v", invites)
	}
	if err := db.RedeemInvite(ctx, code, start); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("third use: %v, want ErrInviteInvalid", err)
	}
}

func TestRedeemInviteExpiry(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	start := time.Unix(1_800_000_000, 0)
	fixedClock(db, start)
	code, err := db.CreateInvite(ctx, time.Hour, 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{start.Add(time.Hour), start.Add(time.Hour + time.Nanosecond), start.Add(48 * time.Hour)} {
		if err := db.RedeemInvite(ctx, code, at); !errors.Is(err, ErrInviteInvalid) {
			t.Errorf("redeem at expiry+%s: %v, want ErrInviteInvalid", at.Sub(start.Add(time.Hour)), err)
		}
	}
	invites, err := db.ListInvites(ctx)
	if err != nil || len(invites) != 1 || invites[0].UsesLeft != 5 {
		t.Fatalf("failed redemption changed the invite: %+v, %v", invites, err)
	}
	if !invites[0].Expired(start.Add(time.Hour)) || invites[0].Expired(start.Add(time.Hour-time.Second)) {
		t.Error("Invite.Expired disagrees with redemption")
	}
}

func TestRedeemInviteNormalization(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	now := time.Now()
	code, err := db.CreateInvite(ctx, time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	plain := strings.ReplaceAll(code, "-", "")
	spaced := strings.ReplaceAll(code, "-", " ")
	variants := []string{
		code,
		strings.ToLower(code),
		plain,
		strings.ToLower(plain),
		" " + spaced + "\n",
		"\t" + strings.ReplaceAll(code, "-", "--") + " ",
		plain[:3] + "-" + plain[3:],
	}
	for _, variant := range variants {
		if err := db.RedeemInvite(ctx, variant, now); err != nil {
			t.Errorf("RedeemInvite(%q): %v", variant, err)
		}
	}
}

func TestRedeemInviteRejectsMalformedAndUnknown(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	now := time.Now()
	code, err := db.CreateInvite(ctx, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	plain := strings.ReplaceAll(code, "-", "")
	lastBitsSet := plain[:25] + "7"
	unknown := strings.Repeat("A", 26)
	for _, bad := range []string{"", "-", plain[:25], plain + "A", plain[:25] + "1", plain[:25] + "=", plain[:24] + "é", lastBitsSet, unknown} {
		if err := db.RedeemInvite(ctx, bad, now); !errors.Is(err, ErrInviteInvalid) {
			t.Errorf("RedeemInvite(%q): %v, want ErrInviteInvalid", bad, err)
		}
	}
	if err := db.RedeemInvite(ctx, code, now); err != nil {
		t.Fatalf("valid code rejected after malformed attempts: %v", err)
	}
}

func TestRedeemInviteConcurrentSingleUse(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	code, err := db.CreateInvite(ctx, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	var successes, invalid atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, workers)
	for range workers {
		wg.Go(func() {
			<-start
			err := db.RedeemInvite(ctx, code, time.Now())
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrInviteInvalid):
				invalid.Add(1)
			default:
				errs <- err
			}
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("unexpected error: %v", err)
	}
	if successes.Load() != 1 || invalid.Load() != workers-1 {
		t.Fatalf("%d successes and %d invalid, want 1 and %d", successes.Load(), invalid.Load(), workers-1)
	}
}

func TestRedeemInviteAndPut(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	now := time.Now()
	code, err := db.CreateInvite(ctx, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	id := testID(7)

	if _, err := db.RedeemInviteAndPut(ctx, "", id, []byte("v1"), 1, now); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("new ID without invite: %v, want ErrInviteInvalid", err)
	}
	if _, _, err := db.GetBundle(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("identity stored without invite: %v", err)
	}

	got, err := db.RedeemInviteAndPut(ctx, code, id, []byte("v1"), 1, now)
	if err != nil || got != Created {
		t.Fatalf("new ID with invite: %v, %v", got, err)
	}
	if invites, _ := db.ListInvites(ctx); len(invites) != 0 {
		t.Fatalf("invite not used up: %+v", invites)
	}

	for _, tc := range []struct {
		code    string
		bundle  string
		serial  uint64
		want    PutResult
		wantErr error
	}{
		{"", "v1", 1, Unchanged, nil},
		{code, "v1", 1, Unchanged, nil},
		{"garbage", "v2", 2, Replaced, nil},
		{"", "vx", 1, 0, ErrConflict},
	} {
		got, err := db.RedeemInviteAndPut(ctx, tc.code, id, []byte(tc.bundle), tc.serial, now)
		if got != tc.want || !errors.Is(err, tc.wantErr) {
			t.Errorf("known ID %q/%d: %v, %v; want %v, %v", tc.bundle, tc.serial, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestRedeemInviteAndPutRollsBack(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	now := time.Now()
	code, err := db.CreateInvite(ctx, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	id := testID(3)

	if _, err := db.RedeemInviteAndPut(ctx, code, id, nil, 1, now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty bundle: %v, want ErrInvalidArgument", err)
	}

	bundle := make([]byte, MaxBundleSize)
	if _, err := db.sql.ExecContext(ctx, `CREATE TRIGGER reject_insert BEFORE INSERT ON identities
		BEGIN SELECT RAISE(ABORT, 'rejected for test'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RedeemInviteAndPut(ctx, code, id, bundle, 1, now); err == nil {
		t.Fatal("insert failure not reported")
	}
	if invites, _ := db.ListInvites(ctx); len(invites) != 1 || invites[0].UsesLeft != 1 {
		t.Fatalf("failed put used up the invite: %+v", invites)
	}
	if _, err := db.sql.ExecContext(ctx, "DROP TRIGGER reject_insert"); err != nil {
		t.Fatal(err)
	}
	if got, err := db.RedeemInviteAndPut(ctx, code, id, bundle, 1, now); err != nil || got != Created {
		t.Fatalf("retry after rollback: %v, %v", got, err)
	}
}

func TestPruneExpiredInvites(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	start := time.Unix(1_800_000_000, 0)
	fixedClock(db, start)
	for _, ttl := range []time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour} {
		if _, err := db.CreateInvite(ctx, ttl, 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.sql.ExecContext(ctx, "INSERT INTO invites (code_hash, expires_at, uses_left) VALUES (zeroblob(32), ?, 0)", start.Add(10*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	deleted, err := db.PruneExpiredInvites(ctx, start.Add(2*time.Hour))
	if err != nil || deleted != 3 {
		t.Fatalf("PruneExpiredInvites = %d, %v; want 3", deleted, err)
	}
	invites, err := db.ListInvites(ctx)
	if err != nil || len(invites) != 1 || !invites[0].ExpiresAt.Equal(start.Add(3*time.Hour)) {
		t.Fatalf("remaining invites %+v, %v", invites, err)
	}
	if deleted, err := db.PruneExpiredInvites(ctx, start.Add(2*time.Hour)); err != nil || deleted != 0 {
		t.Fatalf("second prune = %d, %v", deleted, err)
	}
}

func TestGroupInviteCode(t *testing.T) {
	if got := groupInviteCode("ABCDEFGHIJ"); got != "ABCD-EFGH-IJ" {
		t.Fatalf("groupInviteCode = %q", got)
	}
}
