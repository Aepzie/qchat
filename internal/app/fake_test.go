package app

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/crypto/vault"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/prekey"
	"github.com/craguS/qchat/internal/profile"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/store/clientdb"
	"github.com/craguS/qchat/internal/tui"
)

// fakeClock is a settable clock shared by the fake relay and its Apps.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeRelay is an in-memory relay with the semantics the App relies on:
// prekeys are handed out once, every Send is queued until the recipient
// acknowledges it, and nothing is pushed: tests deliver explicitly.
type fakeRelay struct {
	clock *fakeClock

	mu      sync.Mutex
	bundles map[identity.ID][]byte
	signed  map[identity.ID][]byte
	oneTime map[identity.ID][][]byte
	queues  map[identity.ID][]client.Delivery
	acked   map[identity.ID][]uint64
	uploads map[identity.ID][]protocol.PrekeyUpload
	nextQID uint64
	// multi counts SendMulti requests.
	multi int
	// failUploads makes every non-empty PrekeyUpload fail.
	failUploads bool
}

func newFakeRelay() *fakeRelay {
	return &fakeRelay{
		clock:   &fakeClock{now: time.Unix(1_800_000_000, 0)},
		bundles: map[identity.ID][]byte{},
		signed:  map[identity.ID][]byte{},
		oneTime: map[identity.ID][][]byte{},
		queues:  map[identity.ID][]client.Delivery{},
		acked:   map[identity.ID][]uint64{},
		uploads: map[identity.ID][]protocol.PrekeyUpload{},
	}
}

// fakeConn is one authenticated connection of id to the fake relay.
type fakeConn struct {
	relay *fakeRelay
	id    identity.ID
}

func remote(code protocol.ErrorCode) error { return &client.RemoteError{Code: code} }

func (c *fakeConn) Ack(queueID uint64) error {
	r := c.relay
	r.mu.Lock()
	defer r.mu.Unlock()
	r.acked[c.id] = append(r.acked[c.id], queueID)
	return nil
}

func (c *fakeConn) Request(ctx context.Context, t protocol.FrameType, body any) (protocol.Frame, error) {
	r := c.relay
	r.mu.Lock()
	defer r.mu.Unlock()
	switch req := body.(type) {
	case protocol.KeyRequest:
		b, ok := r.bundles[identity.ID(req.ID)]
		if !ok {
			return protocol.Frame{}, remote(protocol.ErrCodeNotFound)
		}
		return protocol.NewFrame(protocol.TypeKeyResponse, 1, protocol.KeyResponse{Bundle: b})
	case protocol.PrekeyUpload:
		r.uploads[c.id] = append(r.uploads[c.id], req)
		if r.failUploads && (req.SignedPrekey != nil || len(req.OneTimePrekeys) > 0) {
			return protocol.Frame{}, remote(protocol.ErrCodeRateLimited)
		}
		if req.SignedPrekey != nil {
			r.signed[c.id] = req.SignedPrekey
		}
		r.oneTime[c.id] = append(r.oneTime[c.id], req.OneTimePrekeys...)
		return protocol.NewFrame(protocol.TypePrekeyStatus, 1, r.statusLocked(c.id))
	case protocol.PrekeyRequest:
		id := identity.ID(req.ID)
		spk, ok := r.signed[id]
		if !ok {
			return protocol.Frame{}, remote(protocol.ErrCodeNotFound)
		}
		resp := protocol.PrekeyResponse{Bundle: r.bundles[id], SignedPrekey: spk}
		if pool := r.oneTime[id]; len(pool) > 0 {
			resp.OneTimePrekey, r.oneTime[id] = pool[0], pool[1:]
		}
		return protocol.NewFrame(protocol.TypePrekeyResponse, 1, resp)
	case protocol.Send:
		to := identity.ID(req.To)
		if _, ok := r.bundles[to]; !ok {
			return protocol.Frame{}, remote(protocol.ErrCodeNotFound)
		}
		r.nextQID++
		r.queues[to] = append(r.queues[to], client.Delivery{From: [32]byte(c.id), Payload: slices.Clone(req.Payload), QueueID: r.nextQID})
		return protocol.NewFrame(protocol.TypeSendResult, 1, protocol.SendResult{Status: protocol.SendAccepted})
	case protocol.SendMulti:
		result := protocol.SendMultiResult{Status: protocol.SendAccepted}
		for _, raw := range req.To {
			to := identity.ID(raw)
			if _, ok := r.bundles[to]; !ok || to == c.id {
				result.Failed = append(result.Failed, raw)
				result.Reasons = append(result.Reasons, protocol.ErrCodeNotFound)
				continue
			}
			r.nextQID++
			r.queues[to] = append(r.queues[to], client.Delivery{From: [32]byte(c.id), Payload: slices.Clone(req.Payload), QueueID: r.nextQID})
		}
		r.multi++
		return protocol.NewFrame(protocol.TypeSendMultiResult, 1, result)
	}
	return protocol.Frame{}, errors.New("fake relay: unexpected request")
}

func (r *fakeRelay) statusLocked(id identity.ID) protocol.PrekeyStatus {
	status := protocol.PrekeyStatus{OneTimeRemaining: uint32(len(r.oneTime[id]))}
	if raw, ok := r.signed[id]; ok {
		owner, err := identity.ParseBundleForID(r.bundles[id], id)
		if err == nil {
			if spk, err := prekey.ParseSignedPrekey(raw, owner, r.clock.Now()); err == nil {
				status.SignedPrekeyExpires = spk.Expires.Unix()
			}
		}
	}
	return status
}

// take removes and returns the queued deliveries for id.
func (r *fakeRelay) take(id identity.ID) []client.Delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := r.queues[id]
	delete(r.queues, id)
	return q
}

func (r *fakeRelay) acksOf(id identity.ID) []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.acked[id])
}

// fakeUser is an App attached to the fake relay, driven without Run.
type fakeUser struct {
	t     *testing.T
	relay *fakeRelay
	dir   string
	prof  *profile.Profile
	app   *App
	id    identity.ID
}

const testPassphrase = "correct horse battery"

func newFakeUser(t *testing.T, r *fakeRelay, name string) *fakeUser {
	t.Helper()
	dir := t.TempDir()
	p, err := profile.Create(dir, []byte(testPassphrase), name, vault.TestParams())
	if err != nil {
		t.Fatal(err)
	}
	u := &fakeUser{t: t, relay: r, dir: dir}
	u.attach(p)
	if err := u.app.maintainPrekeys(context.Background()); err != nil {
		t.Fatalf("%s: prekey maintenance: %v", name, err)
	}
	return u
}

// attach builds the App for p and registers its bundle with the relay.
func (u *fakeUser) attach(p *profile.Profile) {
	u.t.Helper()
	a, err := New(p, "")
	if err != nil {
		u.t.Fatal(err)
	}
	a.now = u.relay.clock.Now
	u.prof, u.app, u.id = p, a, p.Identity.ID()
	a.UseSession(&fakeConn{relay: u.relay, id: u.id})
	u.relay.mu.Lock()
	u.relay.bundles[u.id] = a.selfRaw
	u.relay.mu.Unlock()
	u.t.Cleanup(func() { p.Close() })
}

// restart closes the profile and opens it again with a fresh App, as a
// client restart would.
func (u *fakeUser) restart() {
	u.t.Helper()
	_ = u.prof.Close()
	p, err := profile.Unlock(u.dir, []byte(testPassphrase))
	if err != nil {
		u.t.Fatal(err)
	}
	u.attach(p)
}

func (u *fakeUser) cid() string { return canonicalID(u.id) }

func (u *fakeUser) add(other *fakeUser) {
	u.t.Helper()
	if _, err := u.app.AddContact(context.Background(), other.cid(), ""); err != nil {
		u.t.Fatal(err)
	}
	u.drainEvents()
}

func (u *fakeUser) send(to *fakeUser, text string) tui.MessageInfo {
	u.t.Helper()
	m, err := u.app.Send(context.Background(), to.cid(), text)
	if err != nil {
		u.t.Fatalf("Send(%q): %v", text, err)
	}
	return m
}

// receive delivers every queued message and returns the texts shown.
func (u *fakeUser) receive() []string {
	u.t.Helper()
	for _, d := range u.relay.take(u.id) {
		u.app.handleDelivery(context.Background(), d)
	}
	var texts []string
	for _, ev := range u.drainEvents() {
		if in, ok := ev.(tui.IncomingMessage); ok {
			texts = append(texts, in.Message.Text)
		}
	}
	return texts
}

func (u *fakeUser) drainEvents() []tui.ChatEvent {
	var out []tui.ChatEvent
	for {
		select {
		case ev := <-u.app.chat:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func (u *fakeUser) dropped() int {
	u.app.mu.Lock()
	defer u.app.mu.Unlock()
	return u.app.dropped
}

func (u *fakeUser) session(peer *fakeUser) (clientdb.Session, bool) {
	u.t.Helper()
	s, found, err := u.app.loadSession(context.Background(), peer.id)
	if err != nil {
		u.t.Fatal(err)
	}
	return s, found
}

func (u *fakeUser) prekeys(kind clientdb.PrekeyKind) []clientdb.PrekeySecret {
	u.t.Helper()
	list, err := u.prof.DB.ListPrekeySecrets(context.Background(), kind)
	if err != nil {
		u.t.Fatal(err)
	}
	return list
}

func wantTexts(t *testing.T, who string, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s received %q, want %q", who, got, want)
	}
}
