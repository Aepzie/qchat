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

// qidsOf returns the queue IDs of outcomes and fails the test if any
// recipient was refused.
func qidsOf(t *testing.T, outcomes []Enqueued) []uint64 {
	t.Helper()
	qids := make([]uint64, len(outcomes))
	for i, o := range outcomes {
		if o.Err != nil || o.QID == 0 {
			t.Fatalf("recipient %d: QID %d, %v", i, o.QID, o.Err)
		}
		qids[i] = o.QID
	}
	return qids
}

// payloadStats returns the number of stored payloads, their total size and
// the sum of their reference counts.
func payloadStats(t *testing.T, db *DB) (rows int, size int64, refs int) {
	t.Helper()
	if err := db.sql.QueryRow("SELECT count(*), coalesce(sum(size), 0), coalesce(sum(refs), 0) FROM queue_payloads").Scan(&rows, &size, &refs); err != nil {
		t.Fatal(err)
	}
	return rows, size, refs
}

// queueRows returns the number of rows in the queue table.
func queueRows(t *testing.T, db *DB) int {
	t.Helper()
	var n int
	if err := db.sql.QueryRow("SELECT count(*) FROM queue").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEnqueueMulti(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice, bob, carol, dave := testID(1), testID(2), testID(3), testID(4)
	for _, id := range [][32]byte{bob, carol, dave} {
		registerTestIdentity(t, db, id)
	}
	now := time.Unix(1_700_000_000, 0)
	later := now.Add(time.Hour)

	outcomes, err := db.EnqueueMulti(ctx, [][32]byte{bob, carol, dave}, alice, []byte("group"), now, later, testLimits)
	if err != nil {
		t.Fatalf("EnqueueMulti: %v", err)
	}
	qids := qidsOf(t, outcomes)
	if len(qids) != 3 || qids[0] >= qids[1] || qids[1] >= qids[2] {
		t.Fatalf("queue IDs %v, want three increasing IDs", qids)
	}
	for i, id := range [][32]byte{bob, carol, dave} {
		msgs, err := db.QueuedFor(ctx, id, 0, 10, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(msgs) != 1 || msgs[0].QID != qids[i] || msgs[0].Sender != alice || string(msgs[0].Payload) != "group" {
			t.Fatalf("recipient %d queue = %+v", i, msgs)
		}
	}
	if err := db.Ack(ctx, carol, qids[1]); err != nil {
		t.Fatal(err)
	}
	if msgs, _ := db.QueuedFor(ctx, bob, 0, 10, now); len(msgs) != 1 {
		t.Fatal("acknowledging one copy deleted another recipient's copy")
	}
}

// TestEnqueueMultiPartial checks that unknown recipients and full queues
// are reported per recipient without keeping the others from getting the
// message.
func TestEnqueueMultiPartial(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice, bob, carol, dave, stranger := testID(1), testID(2), testID(3), testID(4), testID(9)
	for _, id := range [][32]byte{bob, carol, dave} {
		registerTestIdentity(t, db, id)
	}
	now := time.Unix(1_700_000_000, 0)
	later := now.Add(time.Hour)
	limits := QueueLimits{MaxMessages: 1, MaxBytes: 1 << 20}
	mustEnqueue(t, db, carol, alice, "fills carol", now, time.Hour)

	outcomes, err := db.EnqueueMulti(ctx, [][32]byte{bob, stranger, carol, dave}, alice, []byte("x"), now, later, limits)
	if err != nil {
		t.Fatalf("EnqueueMulti: %v", err)
	}
	if outcomes[0].Err != nil || outcomes[3].Err != nil || outcomes[0].QID == 0 || outcomes[3].QID <= outcomes[0].QID {
		t.Fatalf("stored outcomes %+v", outcomes)
	}
	if !errors.Is(outcomes[1].Err, ErrNotFound) || outcomes[1].QID != 0 {
		t.Fatalf("unknown recipient outcome %+v", outcomes[1])
	}
	if !errors.Is(outcomes[2].Err, ErrQueueFull) || outcomes[2].QID != 0 {
		t.Fatalf("full recipient outcome %+v", outcomes[2])
	}
	for id, want := range map[[32]byte]int{bob: 1, carol: 1, dave: 1, stranger: 0} {
		if msgs, _ := db.QueuedFor(ctx, id, 0, 10, now); len(msgs) != want {
			t.Fatalf("%x has %d messages, want %d", id[:1], len(msgs), want)
		}
	}
	if rows, _, refs := payloadStats(t, db); rows != 2 || refs != 3 {
		t.Fatalf("%d payloads with %d references, want 2 with 3", rows, refs)
	}

	before := queueRows(t, db)
	outcomes, err = db.EnqueueMulti(ctx, [][32]byte{carol, stranger}, alice, []byte("x"), now, later, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(outcomes[0].Err, ErrQueueFull) || !errors.Is(outcomes[1].Err, ErrNotFound) {
		t.Fatalf("outcomes %+v", outcomes)
	}
	if rows, _, _ := payloadStats(t, db); rows != 2 || queueRows(t, db) != before {
		t.Fatal("a request no recipient could take stored something")
	}

	bySize := QueueLimits{MaxMessages: 100, MaxBytes: 6}
	outcomes, err = db.EnqueueMulti(ctx, [][32]byte{dave}, alice, []byte("123456"), now, later, bySize)
	if err != nil || !errors.Is(outcomes[0].Err, ErrQueueFull) {
		t.Fatalf("payload over byte limit: %+v, %v; want ErrQueueFull", outcomes, err)
	}
}

// TestEnqueueMultiStoresPayloadOnce checks that a message for many
// recipients is stored once, while every recipient's limits still count its
// full size.
func TestEnqueueMultiStoresPayloadOnce(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice := testID(1)
	recipients := make([][32]byte, MaxMultiRecipients)
	for i := range recipients {
		recipients[i] = testID(byte(i))
		recipients[i][1] = 0xee
		registerTestIdentity(t, db, recipients[i])
	}
	now := time.Unix(1_700_000_000, 0)
	payload := make([]byte, 64<<10)
	limits := QueueLimits{MaxMessages: 10, MaxBytes: int64(len(payload)) * 2}

	outcomes, err := db.EnqueueMulti(ctx, recipients, alice, payload, now, now.Add(time.Hour), limits)
	if err != nil {
		t.Fatal(err)
	}
	qidsOf(t, outcomes)
	rows, size, refs := payloadStats(t, db)
	if rows != 1 || size != int64(len(payload)) || refs != MaxMultiRecipients {
		t.Fatalf("payloads: %d rows, %d bytes, %d references; want 1, %d, %d", rows, size, refs, len(payload), MaxMultiRecipients)
	}
	if n := queueRows(t, db); n != MaxMultiRecipients {
		t.Fatalf("%d queue rows, want %d", n, MaxMultiRecipients)
	}
	var counted int64
	if err := db.sql.QueryRow("SELECT sum(size) FROM queue").Scan(&counted); err != nil {
		t.Fatal(err)
	}
	if counted != int64(len(payload))*MaxMultiRecipients {
		t.Fatalf("queue rows count %d bytes, want the full size per recipient", counted)
	}

	if _, err := db.EnqueueMulti(ctx, recipients[:2], alice, payload, now, now.Add(time.Hour), limits); err != nil {
		t.Fatal(err)
	}
	outcomes, err = db.EnqueueMulti(ctx, recipients[:2], alice, []byte("x"), now, now.Add(time.Hour), limits)
	if err != nil {
		t.Fatal(err)
	}
	for i, o := range outcomes {
		if !errors.Is(o.Err, ErrQueueFull) {
			t.Fatalf("recipient %d with two full-size copies: %+v, want ErrQueueFull", i, o)
		}
	}
}

// TestSharedPayloadRefcount checks that a shared payload is deleted with
// its last copy, whether copies are acknowledged, expire or vanish with
// their recipient.
func TestSharedPayloadRefcount(t *testing.T) {
	ctx := context.Background()
	alice, bob, carol, dave := testID(1), testID(2), testID(3), testID(4)
	now := time.Unix(1_700_000_000, 0)
	setup := func(t *testing.T) (*DB, []uint64) {
		db, _ := openTestDB(t)
		for _, id := range [][32]byte{bob, carol, dave} {
			registerTestIdentity(t, db, id)
		}
		outcomes, err := db.EnqueueMulti(ctx, [][32]byte{bob, carol, dave}, alice, []byte("shared"), now, now.Add(time.Hour), testLimits)
		if err != nil {
			t.Fatal(err)
		}
		return db, qidsOf(t, outcomes)
	}
	expectPayloads := func(t *testing.T, db *DB, rows, refs int) {
		t.Helper()
		if gotRows, _, gotRefs := payloadStats(t, db); gotRows != rows || gotRefs != refs {
			t.Fatalf("%d payloads with %d references, want %d with %d", gotRows, gotRefs, rows, refs)
		}
	}

	t.Run("Ack", func(t *testing.T) {
		db, qids := setup(t)
		if err := db.Ack(ctx, bob, qids[0]); err != nil {
			t.Fatal(err)
		}
		if err := db.Ack(ctx, bob, qids[1]); !errors.Is(err, ErrNotFound) {
			t.Fatalf("ack of another recipient's copy: %v", err)
		}
		expectPayloads(t, db, 1, 2)
		if err := db.Ack(ctx, carol, qids[1]); err != nil {
			t.Fatal(err)
		}
		expectPayloads(t, db, 1, 1)
		if msgs, _ := db.QueuedFor(ctx, dave, 0, 10, now); len(msgs) != 1 || string(msgs[0].Payload) != "shared" {
			t.Fatalf("last copy lost its payload: %+v", msgs)
		}
		if err := db.Ack(ctx, dave, qids[2]); err != nil {
			t.Fatal(err)
		}
		expectPayloads(t, db, 0, 0)
	})
	t.Run("Prune", func(t *testing.T) {
		db, qids := setup(t)
		mustEnqueue(t, db, bob, alice, "survives", now, 3*time.Hour)
		if err := db.Ack(ctx, carol, qids[1]); err != nil {
			t.Fatal(err)
		}
		n, err := db.PruneQueue(ctx, now.Add(2*time.Hour))
		if err != nil || n != 2 {
			t.Fatalf("PruneQueue = %d, %v; want 2", n, err)
		}
		expectPayloads(t, db, 1, 1)
		if msgs, _ := db.QueuedFor(ctx, bob, 0, 10, now); len(msgs) != 1 || string(msgs[0].Payload) != "survives" {
			t.Fatalf("bob's queue after prune: %+v", msgs)
		}
	})
	t.Run("PruneOnEnqueue", func(t *testing.T) {
		db, _ := setup(t)
		for _, id := range [][32]byte{bob, carol, dave} {
			if _, err := db.Enqueue(ctx, id, alice, []byte("next"), now.Add(2*time.Hour), now.Add(3*time.Hour), testLimits); err != nil {
				t.Fatal(err)
			}
		}
		expectPayloads(t, db, 3, 3)
	})
	t.Run("IdentityDeleted", func(t *testing.T) {
		db, _ := setup(t)
		if _, err := db.sql.Exec("DELETE FROM identities WHERE id = ?", bob[:]); err != nil {
			t.Fatal(err)
		}
		expectPayloads(t, db, 1, 2)
		if _, err := db.sql.Exec("DELETE FROM identities WHERE id IN (?, ?)", carol[:], dave[:]); err != nil {
			t.Fatal(err)
		}
		expectPayloads(t, db, 0, 0)
	})
}

func TestEnqueueMultiRejects(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice, bob := testID(1), testID(2)
	registerTestIdentity(t, db, bob)
	now := time.Unix(1_700_000_000, 0)
	later := now.Add(time.Hour)
	tooMany := make([][32]byte, MaxMultiRecipients+1)
	for i := range tooMany {
		tooMany[i] = testID(byte(i))
		tooMany[i][1] = byte(i >> 8)
	}
	tests := []struct {
		name       string
		recipients [][32]byte
		payload    []byte
		expires    time.Time
		limits     QueueLimits
	}{
		{"NoRecipients", nil, []byte("x"), later, testLimits},
		{"TooManyRecipients", tooMany, []byte("x"), later, testLimits},
		{"DuplicateRecipient", [][32]byte{bob, bob}, []byte("x"), later, testLimits},
		{"EmptyPayload", [][32]byte{bob}, nil, later, testLimits},
		{"HugePayload", [][32]byte{bob}, make([]byte, MaxQueuedPayloadSize+1), later, testLimits},
		{"AlreadyExpired", [][32]byte{bob}, []byte("x"), now, testLimits},
		{"ZeroLimits", [][32]byte{bob}, []byte("x"), later, QueueLimits{}},
	}
	for _, tc := range tests {
		if _, err := db.EnqueueMulti(ctx, tc.recipients, alice, tc.payload, now, tc.expires, tc.limits); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v, want ErrInvalidArgument", tc.name, err)
		}
	}
	if msgs, _ := db.QueuedFor(ctx, bob, 0, 10, now); len(msgs) != 0 {
		t.Fatalf("%d messages stored by rejected calls", len(msgs))
	}
}
