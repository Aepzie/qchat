package serverdb

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

var testLimits = QueueLimits{MaxMessages: 1000, MaxBytes: 1 << 20}

// mustEnqueue stores payload and returns its queue ID.
func mustEnqueue(t *testing.T, db *DB, recipient, sender [32]byte, payload string, now time.Time, ttl time.Duration) uint64 {
	t.Helper()
	qid, err := db.Enqueue(context.Background(), recipient, sender, []byte(payload), now, now.Add(ttl), testLimits)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	return qid
}

// payloads returns the payloads of msgs as strings.
func payloads(msgs []Queued) []string {
	out := make([]string, len(msgs))
	for i, m := range msgs {
		out[i] = string(m.Payload)
	}
	return out
}

func TestQueueOrderAndPaging(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice, bob := testID(1), testID(2)
	registerTestIdentity(t, db, bob)
	now := time.Unix(1_700_000_000, 0)

	var qids []uint64
	for i := range 5 {
		qids = append(qids, mustEnqueue(t, db, bob, alice, fmt.Sprintf("m%d", i), now, time.Hour))
	}
	for i := 1; i < len(qids); i++ {
		if qids[i] <= qids[i-1] || qids[0] < 1 {
			t.Fatalf("queue IDs not increasing: %v", qids)
		}
	}

	first, err := db.QueuedFor(ctx, bob, 0, 2, now)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(payloads(first)) != "[m0 m1]" || first[0].Sender != alice || first[0].QID != qids[0] {
		t.Fatalf("first page = %+v", first)
	}
	rest, err := db.QueuedFor(ctx, bob, first[1].QID, 10, now)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(payloads(rest)) != "[m2 m3 m4]" {
		t.Fatalf("second page = %v", payloads(rest))
	}
	if none, err := db.QueuedFor(ctx, alice, 0, 10, now); err != nil || len(none) != 0 {
		t.Fatalf("QueuedFor(sender) = %v, %v; want nothing", none, err)
	}
	if none, err := db.QueuedFor(ctx, bob, 1<<64-1, 10, now); err != nil || len(none) != 0 {
		t.Fatalf("QueuedFor(after max) = %v, %v", none, err)
	}
	if _, err := db.QueuedFor(ctx, bob, 0, 0, now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("QueuedFor(limit 0): %v", err)
	}
}

func TestEnqueueRejects(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice, bob := testID(1), testID(2)
	registerTestIdentity(t, db, bob)
	now := time.Unix(1_700_000_000, 0)
	later := now.Add(time.Hour)

	if _, err := db.Enqueue(ctx, alice, bob, []byte("x"), now, later, testLimits); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Enqueue for unknown recipient: %v, want ErrNotFound", err)
	}
	tests := []struct {
		name    string
		payload []byte
		expires time.Time
		limits  QueueLimits
	}{
		{"EmptyPayload", nil, later, testLimits},
		{"HugePayload", make([]byte, MaxQueuedPayloadSize+1), later, testLimits},
		{"AlreadyExpired", []byte("x"), now, testLimits},
		{"ZeroMessages", []byte("x"), later, QueueLimits{MaxBytes: 10}},
		{"ZeroBytes", []byte("x"), later, QueueLimits{MaxMessages: 10}},
	}
	for _, tc := range tests {
		if _, err := db.Enqueue(ctx, bob, alice, tc.payload, now, tc.expires, tc.limits); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v, want ErrInvalidArgument", tc.name, err)
		}
	}
}

func TestQueueLimits(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice, bob, carol := testID(1), testID(2), testID(3)
	registerTestIdentity(t, db, bob)
	registerTestIdentity(t, db, carol)
	now := time.Unix(1_700_000_000, 0)
	later := now.Add(time.Hour)

	byCount := QueueLimits{MaxMessages: 3, MaxBytes: 1 << 20}
	for i := range 3 {
		if _, err := db.Enqueue(ctx, bob, alice, []byte{byte(i)}, now, later, byCount); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if _, err := db.Enqueue(ctx, bob, alice, []byte{9}, now, later, byCount); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("message over count limit: %v, want ErrQueueFull", err)
	}
	if _, err := db.Enqueue(ctx, carol, alice, []byte{9}, now, later, byCount); err != nil {
		t.Fatalf("other recipient affected by bob's full queue: %v", err)
	}
	msgs, _ := db.QueuedFor(ctx, bob, 0, 10, now)
	if err := db.Ack(ctx, bob, msgs[0].QID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Enqueue(ctx, bob, alice, []byte{9}, now, later, byCount); err != nil {
		t.Fatalf("message after ack freed a slot: %v", err)
	}

	bySize := QueueLimits{MaxMessages: 100, MaxBytes: 10}
	if _, err := db.Enqueue(ctx, carol, alice, make([]byte, 9), now, later, bySize); err != nil {
		t.Fatalf("message within byte limit: %v", err)
	}
	if _, err := db.Enqueue(ctx, carol, alice, make([]byte, 1), now, later, bySize); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("message over byte limit (1 + 9 + 1 > 10): %v, want ErrQueueFull", err)
	}
	if _, err := db.Enqueue(ctx, carol, alice, make([]byte, 11), now, later, QueueLimits{MaxMessages: 100, MaxBytes: 10}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("single message over byte limit: %v, want ErrQueueFull", err)
	}

	expiredLater := now.Add(2 * time.Hour)
	if _, err := db.Enqueue(ctx, bob, alice, []byte{7}, expiredLater, expiredLater.Add(time.Hour), byCount); err != nil {
		t.Fatalf("expired messages still count toward the limit: %v", err)
	}
	if left, _ := db.QueuedFor(ctx, bob, 0, 10, expiredLater); len(left) != 1 {
		t.Fatalf("%d messages left for bob, want only the new one", len(left))
	}
}

func TestAckIsolation(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice, bob := testID(1), testID(2)
	registerTestIdentity(t, db, alice)
	registerTestIdentity(t, db, bob)
	now := time.Unix(1_700_000_000, 0)
	toBob := mustEnqueue(t, db, bob, alice, "for bob", now, time.Hour)
	toAlice := mustEnqueue(t, db, alice, bob, "for alice", now, time.Hour)

	if err := db.Ack(ctx, alice, toBob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("alice acknowledging bob's message: %v, want ErrNotFound", err)
	}
	if msgs, _ := db.QueuedFor(ctx, bob, 0, 10, now); len(msgs) != 1 {
		t.Fatal("bob's message deleted by another identity's ack")
	}
	if err := db.Ack(ctx, bob, toBob); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if err := db.Ack(ctx, bob, toBob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Ack: %v, want ErrNotFound", err)
	}
	for _, qid := range []uint64{0, 1<<64 - 1} {
		if err := db.Ack(ctx, bob, qid); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Ack(%d): %v, want ErrNotFound", qid, err)
		}
	}
	if msgs, _ := db.QueuedFor(ctx, bob, 0, 10, now); len(msgs) != 0 {
		t.Fatal("acknowledged message still queued")
	}
	if msgs, _ := db.QueuedFor(ctx, alice, 0, 10, now); len(msgs) != 1 || msgs[0].QID != toAlice {
		t.Fatalf("alice's queue = %+v", msgs)
	}
}

func TestQueueExpiryAndPrune(t *testing.T) {
	db, path := openTestDB(t)
	ctx := context.Background()
	alice, bob := testID(1), testID(2)
	registerTestIdentity(t, db, bob)
	now := time.Unix(1_700_000_000, 0)
	short := mustEnqueue(t, db, bob, alice, "short", now, time.Hour)
	long := mustEnqueue(t, db, bob, alice, "long", now, 3*time.Hour)

	if msgs, _ := db.QueuedFor(ctx, bob, 0, 10, now.Add(time.Hour)); len(msgs) != 1 || msgs[0].QID != long {
		t.Fatalf("expired message returned: %+v", msgs)
	}
	n, err := db.PruneQueue(ctx, now.Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("PruneQueue = %d, %v; want 1", n, err)
	}
	if err := db.Ack(ctx, bob, short); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pruned message still stored: %v", err)
	}
	if n, err := db.PruneQueue(ctx, now.Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("second PruneQueue = %d, %v", n, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := reopened.Enqueue(ctx, bob, alice, []byte("next"), now, now.Add(time.Hour), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	if next <= long {
		t.Fatalf("queue ID %d reused after %d", next, long)
	}
	if n, err := reopened.PruneQueue(ctx, now.Add(4*time.Hour)); err != nil || n != 2 {
		t.Fatalf("final PruneQueue = %d, %v; want 2", n, err)
	}
}
