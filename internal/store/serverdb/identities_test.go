package serverdb

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"
)

func TestGetBundleNotFound(t *testing.T) {
	db, _ := openTestDB(t)
	if _, _, err := db.GetBundle(context.Background(), testID(9)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetBundle of unknown ID: %v, want ErrNotFound", err)
	}
}

func TestPutIdentityRules(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	id := testID(1)

	steps := []struct {
		name    string
		bundle  string
		serial  uint64
		want    PutResult
		wantErr error
		stored  string
	}{
		{"new", "v1", 1, Created, nil, "v1"},
		{"identical", "v1", 1, Unchanged, nil, "v1"},
		{"different bundle same serial", "v1b", 1, 0, ErrConflict, "v1"},
		{"same bundle different serial below", "v1", 0, 0, ErrConflict, "v1"},
		{"higher serial", "v2", 5, Replaced, nil, "v2"},
		{"identical after replace", "v2", 5, Unchanged, nil, "v2"},
		{"lower serial", "v0", 4, 0, ErrConflict, "v2"},
		{"lower serial old bundle", "v1", 1, 0, ErrConflict, "v2"},
		{"maximum serial", "vmax", math.MaxUint64, Replaced, nil, "vmax"},
		{"above int64 range is not lower", "vlow", math.MaxInt64 + 1, 0, ErrConflict, "vmax"},
	}
	for _, step := range steps {
		got, err := db.PutIdentity(ctx, id, []byte(step.bundle), step.serial)
		if !errors.Is(err, step.wantErr) || got != step.want {
			t.Fatalf("%s: PutIdentity = %v, %v; want %v, %v", step.name, got, err, step.want, step.wantErr)
		}
		bundle, serial, err := db.GetBundle(ctx, id)
		if err != nil || string(bundle) != step.stored {
			t.Fatalf("%s: stored bundle %q, %v; want %q", step.name, bundle, err, step.stored)
		}
		if step.wantErr == nil && serial != step.serial {
			t.Fatalf("%s: stored serial %d, want %d", step.name, serial, step.serial)
		}
	}

	other := testID(2)
	if got, err := db.PutIdentity(ctx, other, []byte("v1"), 1); err != nil || got != Created {
		t.Fatalf("second identity: %v, %v", got, err)
	}
}

func TestPutIdentityRejectsBadBundles(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	for _, bundle := range [][]byte{nil, {}, bytes.Repeat([]byte{1}, MaxBundleSize+1)} {
		if _, err := db.PutIdentity(ctx, testID(1), bundle, 1); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("bundle of %d bytes: %v, want ErrInvalidArgument", len(bundle), err)
		}
	}
	if got, err := db.PutIdentity(ctx, testID(1), bytes.Repeat([]byte{1}, MaxBundleSize), 1); err != nil || got != Created {
		t.Fatalf("bundle of MaxBundleSize: %v, %v", got, err)
	}
}

func TestPutResultString(t *testing.T) {
	for result, want := range map[PutResult]string{Created: "created", Unchanged: "unchanged", Replaced: "replaced", 0: "PutResult(0)"} {
		if got := result.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", int(result), got, want)
		}
	}
}
