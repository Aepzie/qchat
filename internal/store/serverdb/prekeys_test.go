package serverdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// registerTestIdentity stores a dummy bundle under id.
func registerTestIdentity(t *testing.T, db *DB, id [32]byte) {
	t.Helper()
	if _, err := db.PutIdentity(context.Background(), id, []byte("bundle-"+fmt.Sprint(id[0])), 1); err != nil {
		t.Fatalf("PutIdentity: %v", err)
	}
}

// otps returns n one-time prekeys with key IDs first, first+1, ...
func otps(first uint32, n int) []OneTimePrekey {
	out := make([]OneTimePrekey, n)
	for i := range out {
		keyID := first + uint32(i)
		out[i] = OneTimePrekey{KeyID: keyID, Prekey: []byte(fmt.Sprintf("otp-%d", keyID))}
	}
	return out
}

func TestPrekeysUnknownIdentity(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	id := testID(1)
	if err := db.PutSignedPrekey(ctx, id, 1, []byte("spk"), time.Now().Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("PutSignedPrekey: %v, want ErrNotFound", err)
	}
	if _, err := db.AddOneTimePrekeys(ctx, id, otps(1, 1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AddOneTimePrekeys: %v, want ErrNotFound", err)
	}
	if _, _, _, err := db.TakePrekeys(ctx, id, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TakePrekeys: %v, want ErrNotFound", err)
	}
	status, err := db.GetPrekeyStatus(ctx, id)
	if err != nil || status != (PrekeyStatus{}) {
		t.Fatalf("GetPrekeyStatus = %+v, %v; want zero", status, err)
	}
}

func TestPrekeyInvalidArguments(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	id := testID(1)
	registerTestIdentity(t, db, id)
	for _, prekey := range [][]byte{nil, {}, make([]byte, MaxPrekeySize+1)} {
		if err := db.PutSignedPrekey(ctx, id, 1, prekey, time.Now()); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("PutSignedPrekey(%d bytes): %v, want ErrInvalidArgument", len(prekey), err)
		}
		if _, err := db.AddOneTimePrekeys(ctx, id, []OneTimePrekey{{KeyID: 1, Prekey: []byte{1}}, {KeyID: 2, Prekey: prekey}}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("AddOneTimePrekeys(%d bytes): %v, want ErrInvalidArgument", len(prekey), err)
		}
	}
	if n, err := db.CountOneTimePrekeys(ctx, id); err != nil || n != 0 {
		t.Fatalf("CountOneTimePrekeys = %d, %v; a rejected batch must store nothing", n, err)
	}
}

func TestSignedPrekeyNewestWins(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	id := testID(1)
	registerTestIdentity(t, db, id)
	now := time.Unix(1_700_000_000, 0)

	steps := []struct {
		keyID   uint32
		prekey  string
		expires time.Time
		want    string
	}{
		{1, "first", now.Add(21 * 24 * time.Hour), "first"},
		{2, "newer", now.Add(28 * 24 * time.Hour), "newer"},
		{3, "older", now.Add(22 * 24 * time.Hour), "newer"},
		{2, "newer", now.Add(28 * 24 * time.Hour), "newer"},
		{4, "same-expiry", now.Add(28 * 24 * time.Hour), "same-expiry"},
	}
	for i, step := range steps {
		if err := db.PutSignedPrekey(ctx, id, step.keyID, []byte(step.prekey), step.expires); err != nil {
			t.Fatalf("step %d: PutSignedPrekey: %v", i, err)
		}
		_, signed, _, err := db.TakePrekeys(ctx, id, now)
		if err != nil {
			t.Fatalf("step %d: TakePrekeys: %v", i, err)
		}
		if string(signed) != step.want {
			t.Fatalf("step %d: stored signed prekey %q, want %q", i, signed, step.want)
		}
	}
	status, err := db.GetPrekeyStatus(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !status.SignedPrekeyExpires.Equal(now.Add(28 * 24 * time.Hour)) {
		t.Fatalf("SignedPrekeyExpires = %v", status.SignedPrekeyExpires)
	}
}

func TestTakePrekeysRequiresValidSignedPrekey(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	id := testID(1)
	registerTestIdentity(t, db, id)
	now := time.Unix(1_700_000_000, 0)
	if _, err := db.AddOneTimePrekeys(ctx, id, otps(1, 2)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := db.TakePrekeys(ctx, id, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TakePrekeys without signed prekey: %v, want ErrNotFound", err)
	}
	if err := db.PutSignedPrekey(ctx, id, 9, []byte("spk"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := db.TakePrekeys(ctx, id, now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TakePrekeys with expired signed prekey: %v, want ErrNotFound", err)
	}
	if n, _ := db.CountOneTimePrekeys(ctx, id); n != 2 {
		t.Fatalf("failed TakePrekeys consumed one-time prekeys: %d left", n)
	}
	bundle, signed, oneTime, err := db.TakePrekeys(ctx, id, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(bundle) != "bundle-1" || string(signed) != "spk" || string(oneTime) != "otp-1" {
		t.Fatalf("TakePrekeys = %q, %q, %q", bundle, signed, oneTime)
	}
}

func TestOneTimePrekeysOrderDuplicatesAndCap(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	id := testID(1)
	registerTestIdentity(t, db, id)
	now := time.Unix(1_700_000_000, 0)
	if err := db.PutSignedPrekey(ctx, id, 1, []byte("spk"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if n, err := db.AddOneTimePrekeys(ctx, id, otps(100, 3)); err != nil || n != 3 {
		t.Fatalf("AddOneTimePrekeys = %d, %v; want 3", n, err)
	}
	dup := []OneTimePrekey{{KeyID: 101, Prekey: []byte("replacement")}, {KeyID: 5, Prekey: []byte("otp-5")}}
	if n, err := db.AddOneTimePrekeys(ctx, id, dup); err != nil || n != 4 {
		t.Fatalf("AddOneTimePrekeys with duplicate = %d, %v; want 4", n, err)
	}
	if n, err := db.AddOneTimePrekeys(ctx, id, nil); err != nil || n != 4 {
		t.Fatalf("AddOneTimePrekeys(nil) = %d, %v; want 4", n, err)
	}
	for _, want := range []string{"otp-100", "otp-101", "otp-102", "otp-5"} {
		_, _, oneTime, err := db.TakePrekeys(ctx, id, now)
		if err != nil {
			t.Fatal(err)
		}
		if string(oneTime) != want {
			t.Fatalf("TakePrekeys handed out %q, want %q (oldest first, duplicate ignored)", oneTime, want)
		}
	}
	_, signed, oneTime, err := db.TakePrekeys(ctx, id, now)
	if err != nil || oneTime != nil || string(signed) != "spk" {
		t.Fatalf("TakePrekeys after exhaustion = %q, %q, %v; want signed prekey only", signed, oneTime, err)
	}

	if n, err := db.AddOneTimePrekeys(ctx, id, otps(1000, MaxOneTimePrekeys-10)); err != nil || n != MaxOneTimePrekeys-10 {
		t.Fatalf("AddOneTimePrekeys = %d, %v", n, err)
	}
	if n, err := db.AddOneTimePrekeys(ctx, id, otps(5000, 100)); err != nil || n != MaxOneTimePrekeys {
		t.Fatalf("AddOneTimePrekeys over the cap = %d, %v; want %d", n, err, MaxOneTimePrekeys)
	}
	if n, err := db.CountOneTimePrekeys(ctx, id); err != nil || n != MaxOneTimePrekeys {
		t.Fatalf("CountOneTimePrekeys = %d, %v", n, err)
	}
	status, err := db.GetPrekeyStatus(ctx, id)
	if err != nil || status.OneTimeRemaining != MaxOneTimePrekeys {
		t.Fatalf("GetPrekeyStatus = %+v, %v", status, err)
	}
}

func TestOneTimePrekeysAreIsolatedPerIdentity(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	alice, bob := testID(1), testID(2)
	now := time.Unix(1_700_000_000, 0)
	for _, id := range [][32]byte{alice, bob} {
		registerTestIdentity(t, db, id)
		if err := db.PutSignedPrekey(ctx, id, 1, []byte("spk"), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.AddOneTimePrekeys(ctx, alice, otps(1, 1)); err != nil {
		t.Fatal(err)
	}
	if n, err := db.AddOneTimePrekeys(ctx, bob, otps(1, 1)); err != nil || n != 1 {
		t.Fatalf("same key ID for another identity: %d, %v", n, err)
	}
	if _, _, oneTime, err := db.TakePrekeys(ctx, bob, now); err != nil || oneTime == nil {
		t.Fatalf("TakePrekeys(bob) = %q, %v", oneTime, err)
	}
	if n, _ := db.CountOneTimePrekeys(ctx, alice); n != 1 {
		t.Fatalf("taking bob's prekey changed alice's count to %d", n)
	}
}

// TestOneTimePrekeyHandedOutOnce races many TakePrekeys calls and checks
// that every one-time prekey is handed out exactly once.
func TestOneTimePrekeyHandedOutOnce(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	id := testID(1)
	registerTestIdentity(t, db, id)
	now := time.Unix(1_700_000_000, 0)
	if err := db.PutSignedPrekey(ctx, id, 1, []byte("spk"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	const prekeyCount, workers, perWorker = 40, 8, 8
	if _, err := db.AddOneTimePrekeys(ctx, id, otps(1, prekeyCount)); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	seen := make(map[string]int)
	empty := 0
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				_, _, oneTime, err := db.TakePrekeys(ctx, id, now)
				if err != nil {
					errs <- err
					return
				}
				mu.Lock()
				if oneTime == nil {
					empty++
				} else {
					seen[string(oneTime)]++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("TakePrekeys: %v", err)
	}
	if len(seen) != prekeyCount || empty != workers*perWorker-prekeyCount {
		t.Fatalf("handed out %d distinct prekeys and %d empty answers, want %d and %d",
			len(seen), empty, prekeyCount, workers*perWorker-prekeyCount)
	}
	for prekey, n := range seen {
		if n != 1 {
			t.Fatalf("prekey %q handed out %d times", prekey, n)
		}
	}
	if n, _ := db.CountOneTimePrekeys(ctx, id); n != 0 {
		t.Fatalf("%d one-time prekeys left", n)
	}
}

func TestPrekeysSurviveReopen(t *testing.T) {
	db, path := openTestDB(t)
	ctx := context.Background()
	id := testID(1)
	registerTestIdentity(t, db, id)
	now := time.Unix(1_700_000_000, 0)
	if err := db.PutSignedPrekey(ctx, id, 1, []byte("spk"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddOneTimePrekeys(ctx, id, otps(1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	_, signed, oneTime, err := reopened.TakePrekeys(ctx, id, now)
	if err != nil || !bytes.Equal(signed, []byte("spk")) || !bytes.Equal(oneTime, []byte("otp-1")) {
		t.Fatalf("after reopen: %q, %q, %v", signed, oneTime, err)
	}
}
