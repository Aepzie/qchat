package app

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/prekey"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/store/clientdb"
)

func (u *fakeUser) uploads() []protocol.PrekeyUpload {
	u.relay.mu.Lock()
	defer u.relay.mu.Unlock()
	return slices.Clone(u.relay.uploads[u.id])
}

func (u *fakeUser) maintain() []protocol.PrekeyUpload {
	u.t.Helper()
	before := len(u.uploads())
	if err := u.app.maintainPrekeys(context.Background()); err != nil {
		u.t.Fatalf("maintainPrekeys: %v", err)
	}
	return u.uploads()[before:]
}

func oneTimeIDs(t *testing.T, u *fakeUser, raws [][]byte) []uint32 {
	t.Helper()
	ids := make([]uint32, 0, len(raws))
	for _, raw := range raws {
		p, err := prekey.ParseOneTimePrekey(raw, u.app.self)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, p.KeyID)
	}
	slices.Sort(ids)
	return ids
}

func TestPrekeyMaintenance(t *testing.T) {
	r := newFakeRelay()
	t0 := r.clock.Now()
	u := newFakeUser(t, r, "Alice")

	first := u.uploads()
	if len(first) != 2 || first[0].SignedPrekey != nil || len(first[0].OneTimePrekeys) != 0 {
		t.Fatalf("first run did not start with a status query: %d uploads", len(first))
	}
	if first[1].SignedPrekey == nil || len(first[1].OneTimePrekeys) != oneTimePrekeyPool {
		t.Fatalf("first run uploaded signed=%v, %d one-time prekeys", first[1].SignedPrekey != nil, len(first[1].OneTimePrekeys))
	}
	signed := u.prekeys(clientdb.PrekeySigned)
	if len(signed) != 1 || !signed[0].Uploaded || !signed[0].RetireAt.Equal(signed[0].Created.Add(signedPrekeyRetention)) {
		t.Fatalf("signed prekeys %+v", signed)
	}
	spk, err := prekey.ParseSignedPrekey(signed[0].Public, u.app.self, t0)
	if err != nil || !spk.Expires.Equal(spk.Created.Add(signedPrekeyLifetime)) {
		t.Fatalf("signed prekey %+v, %v", spk, err)
	}
	oneTime := u.prekeys(clientdb.PrekeyOneTime)
	if len(oneTime) != oneTimePrekeyPool || slices.ContainsFunc(oneTime, func(p clientdb.PrekeySecret) bool { return !p.Uploaded }) {
		t.Fatalf("%d one-time prekeys, all uploaded: %v", len(oneTime), !slices.ContainsFunc(oneTime, func(p clientdb.PrekeySecret) bool { return !p.Uploaded }))
	}

	r.clock.Advance(24 * time.Hour)
	if runs := u.maintain(); len(runs) != 1 {
		t.Fatalf("idle run made %d uploads, want only the status query", len(runs))
	}

	r.mu.Lock()
	r.oneTime[u.id] = r.oneTime[u.id][:oneTimePrekeyLow]
	r.mu.Unlock()
	if runs := u.maintain(); len(runs) != 1 {
		t.Fatalf("run at the threshold made %d uploads", len(runs))
	}
	r.mu.Lock()
	r.oneTime[u.id] = r.oneTime[u.id][:oneTimePrekeyLow-1]
	r.mu.Unlock()
	runs := u.maintain()
	if len(runs) != 2 || runs[1].SignedPrekey != nil || len(runs[1].OneTimePrekeys) != oneTimePrekeyPool-oneTimePrekeyLow+1 {
		t.Fatalf("top-up uploads %+v", runs)
	}
	if n := len(u.prekeys(clientdb.PrekeyOneTime)); n != 2*oneTimePrekeyPool-oneTimePrekeyLow+1 {
		t.Fatalf("%d one-time prekeys stored after top-up", n)
	}

	r.mu.Lock()
	delete(r.signed, u.id)
	r.mu.Unlock()
	runs = u.maintain()
	if len(runs) != 2 || !slices.Equal(runs[1].SignedPrekey, signed[0].Public) {
		t.Fatal("signed prekey missing on the relay was not uploaded again")
	}

	r.clock.Advance(signedPrekeyRotation)
	runs = u.maintain()
	if len(runs) != 2 || runs[1].SignedPrekey == nil || slices.Equal(runs[1].SignedPrekey, signed[0].Public) {
		t.Fatal("signed prekey not rotated after 7 days")
	}
	rotated := u.prekeys(clientdb.PrekeySigned)
	if len(rotated) != 2 || rotated[0].KeyID != signed[0].KeyID {
		t.Fatalf("after rotation %d signed prekeys", len(rotated))
	}

	r.clock.Advance(signedPrekeyRetention - signedPrekeyRotation - 24*time.Hour)
	if left := u.prekeys(clientdb.PrekeySigned); len(left) != 2 {
		t.Fatal("old signed prekey deleted early")
	}
	r.clock.Advance(time.Second)
	u.maintain()
	left := u.prekeys(clientdb.PrekeySigned)
	if len(left) != 2 || left[0].KeyID != rotated[1].KeyID {
		t.Fatalf("after retention %d signed prekeys, want the rotated one and its successor", len(left))
	}
}

func TestPrekeyUploadInterrupted(t *testing.T) {
	r := newFakeRelay()
	u := newFakeUser(t, r, "Alice")
	r.mu.Lock()
	r.oneTime[u.id] = nil
	r.failUploads = true
	r.mu.Unlock()
	if err := u.app.maintainPrekeys(context.Background()); err == nil {
		t.Fatal("failed upload not reported")
	}
	failed := u.uploads()
	attempted := oneTimeIDs(t, u, failed[len(failed)-1].OneTimePrekeys)
	if len(attempted) != oneTimePrekeyPool {
		t.Fatalf("attempted %d one-time prekeys", len(attempted))
	}
	var pending []uint32
	for _, p := range u.prekeys(clientdb.PrekeyOneTime) {
		if !p.Uploaded {
			pending = append(pending, p.KeyID)
		}
	}
	slices.Sort(pending)
	if !slices.Equal(pending, attempted) {
		t.Fatal("private keys of attempted prekeys were not stored first")
	}

	r.mu.Lock()
	r.failUploads = false
	r.mu.Unlock()
	runs := u.maintain()
	if got := oneTimeIDs(t, u, runs[len(runs)-1].OneTimePrekeys); !slices.Equal(got, attempted) {
		t.Fatal("retry did not upload the stored prekeys")
	}
	for _, p := range u.prekeys(clientdb.PrekeyOneTime) {
		if !p.Uploaded {
			t.Fatalf("prekey %d not marked uploaded", p.KeyID)
		}
	}
}
