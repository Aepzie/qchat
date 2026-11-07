package app

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/crypto/vault"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/profile"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/server"
	"github.com/craguS/qchat/internal/store/clientdb"
	"github.com/craguS/qchat/internal/transport"
	"github.com/craguS/qchat/internal/tui"
)

const eventTimeout = 10 * time.Second

type relay struct {
	addr string
	pin  transport.Fingerprint
}

// startRelay runs an in-process relay with open registration.
func startRelay(t *testing.T) relay {
	t.Helper()
	certPEM, keyPEM, err := transport.GenerateServerIdentity([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := transport.FingerprintOfTLS(cert)
	if err != nil {
		t.Fatal(err)
	}
	cfg := server.DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Registration = server.RegistrationOpen
	cfg.Database = filepath.Join(t.TempDir(), "relay.db")
	srv, err := server.New(cfg, cert, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return relay{addr: ln.Addr().String(), pin: pin}
}

// user is one client: profile, App and session.
type user struct {
	prof   *profile.Profile
	app    *App
	sess   *client.Session
	inject chan client.Event
	cancel context.CancelFunc
	done   chan struct{}

	mu         sync.Mutex
	deliveries []client.Delivery
}

func newUser(t *testing.T, r relay, name string) *user {
	t.Helper()
	p, err := profile.Create(t.TempDir(), []byte("correct horse battery"), name, vault.TestParams())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	a, err := New(p, "")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := client.New(client.Options{Addr: r.addr, Pin: r.pin, Auth: a.Authenticator()})
	if err != nil {
		t.Fatal(err)
	}
	a.UseSession(sess)
	ctx, cancel := context.WithCancel(context.Background())
	u := &user{prof: p, app: a, sess: sess, inject: make(chan client.Event), cancel: cancel, done: make(chan struct{})}

	tapped := make(chan client.Event)
	sessDone := make(chan struct{})
	go func() {
		defer close(sessDone)
		sess.Run(ctx)
	}()
	go func() {
		for ev := range sess.Events() {
			if d, ok := ev.(client.Delivery); ok {
				u.mu.Lock()
				u.deliveries = append(u.deliveries, d)
				u.mu.Unlock()
			}
			select {
			case tapped <- ev:
			case <-ctx.Done():
			}
		}
	}()
	go func() {
		for {
			select {
			case ev := <-u.inject:
				tapped <- ev
			case <-ctx.Done():
				return
			}
		}
	}()
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		a.Run(ctx, tapped)
	}()
	connected := make(chan struct{})
	go func() {
		signalled := false
		for ev := range a.TUIEvents() {
			if sc, ok := ev.(client.StateChanged); ok && sc.State == client.Connected && !signalled {
				signalled = true
				close(connected)
			}
		}
	}()
	go func() {
		<-sessDone
		<-runDone
		close(u.done)
	}()
	t.Cleanup(u.stop)
	select {
	case <-connected:
	case <-time.After(eventTimeout):
		t.Fatalf("%s did not connect", name)
	}
	return u
}

func (u *user) stop() {
	u.cancel()
	<-u.done
}

func (u *user) id() string { return u.app.Self().ID }

func (u *user) lastDelivery(t *testing.T) client.Delivery {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.deliveries) == 0 {
		t.Fatal("no delivery recorded")
	}
	return u.deliveries[len(u.deliveries)-1]
}

func (u *user) droppedCount() int {
	u.app.mu.Lock()
	defer u.app.mu.Unlock()
	return u.app.dropped
}

// expectEvent returns the next chat event of type T.
func expectEvent[T tui.ChatEvent](t *testing.T, u *user) T {
	t.Helper()
	deadline := time.After(eventTimeout)
	for {
		select {
		case ev, ok := <-u.app.ChatEvents():
			if !ok {
				t.Fatal("chat events closed")
			}
			if e, ok := ev.(T); ok {
				return e
			}
		case <-deadline:
			var zero T
			t.Fatalf("no %T event", zero)
		}
	}
}

func expectNoEvent(t *testing.T, u *user) {
	t.Helper()
	select {
	case ev := <-u.app.ChatEvents():
		t.Fatalf("unexpected chat event %#v", ev)
	default:
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(eventTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func contact(t *testing.T, u *user, id string) tui.ContactInfo {
	t.Helper()
	list, err := u.app.Contacts()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range list {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("contact %s not found", id)
	return tui.ContactInfo{}
}

func send(t *testing.T, from *user, to, text string) tui.MessageInfo {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), eventTimeout)
	defer cancel()
	m, err := from.app.Send(ctx, to, text)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func addContact(t *testing.T, u *user, id, name string) tui.ContactInfo {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), eventTimeout)
	defer cancel()
	c, err := u.app.AddContact(ctx, id, name)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConversation(t *testing.T) {
	r := startRelay(t)
	alice, bob := newUser(t, r, "Alice"), newUser(t, r, "Bob")
	ctx := context.Background()

	if self := alice.app.Self(); len(self.ID) != len(identity.IDPrefix)+52 || strings.Count(self.ID, "-") != 1 || self.DisplayName != "Alice" {
		t.Fatalf("Self = %+v", self)
	}
	if _, err := alice.app.AddContact(ctx, alice.id(), ""); !errors.Is(err, ErrOwnID) {
		t.Fatalf("adding own ID: %v", err)
	}
	if _, err := alice.app.AddContact(ctx, "qc1-nonsense", ""); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("adding invalid ID: %v", err)
	}
	if _, err := alice.app.Send(ctx, bob.id(), "hi"); !errors.Is(err, ErrNotContact) {
		t.Fatalf("sending to a stranger: %v", err)
	}

	c := addContact(t, alice, bob.id(), "")
	if c.ID != bob.id() || c.DisplayName != "" || c.Verified || c.KeyChanged {
		t.Fatalf("added contact %+v", c)
	}
	if _, err := alice.app.Send(ctx, bob.id(), strings.Repeat("x", 64<<10+1)); !errors.Is(err, ErrMessageTooLong) {
		t.Fatalf("oversized message: %v", err)
	}

	sent := send(t, alice, bob.id(), "hi bob")
	if sent.Status != tui.StatusSent || !sent.Outgoing || sent.ID == "" {
		t.Fatalf("sent %+v", sent)
	}
	req := expectEvent[tui.IncomingMessage](t, bob)
	if !req.UnknownSender || req.ContactID != alice.id() || req.Message.Text != "hi bob" || req.Message.ID != sent.ID {
		t.Fatalf("request %+v", req)
	}
	if h, _ := bob.app.History(alice.id(), 50); len(h) != 0 {
		t.Fatalf("message request was persisted: %+v", h)
	}

	added := addContact(t, bob, alice.id(), "Alice")
	if added.Unread != 1 || added.DisplayName != "Alice" {
		t.Fatalf("bob's contact %+v", added)
	}
	h, err := bob.app.History(alice.id(), 50)
	if err != nil || len(h) != 1 || h[0].Text != "hi bob" || h[0].Outgoing {
		t.Fatalf("bob's history %+v, %v", h, err)
	}

	reply := send(t, bob, alice.id(), "hello alice")
	if reply.Status != tui.StatusSent {
		t.Fatalf("reply %+v", reply)
	}
	in := expectEvent[tui.IncomingMessage](t, alice)
	if in.UnknownSender || in.ContactID != bob.id() || in.Message.Text != "hello alice" {
		t.Fatalf("alice received %+v", in)
	}
	if got := contact(t, alice, bob.id()).Unread; got != 1 {
		t.Fatalf("alice unread %d", got)
	}
	if err := alice.app.MarkRead(bob.id()); err != nil {
		t.Fatal(err)
	}
	if got := contact(t, alice, bob.id()).Unread; got != 0 {
		t.Fatalf("unread after MarkRead %d", got)
	}
	h, err = alice.app.History(bob.id(), 50)
	if err != nil || len(h) != 2 || !h[0].Outgoing || h[0].Status != tui.StatusSent || h[1].Text != "hello alice" {
		t.Fatalf("alice's history %+v, %v", h, err)
	}

	replayed := alice.lastDelivery(t)
	alice.inject <- replayed
	waitFor(t, "replay to be dropped", func() bool { return alice.droppedCount() == 1 })
	tampered := client.Delivery{From: replayed.From, Payload: append([]byte(nil), replayed.Payload...)}
	tampered.Payload[len(tampered.Payload)/2] ^= 1
	alice.inject <- tampered
	waitFor(t, "tampered payload to be dropped", func() bool { return alice.droppedCount() == 2 })
	forged := client.Delivery{From: [32]byte(alice.prof.Identity.ID()), Payload: replayed.Payload}
	alice.inject <- forged
	waitFor(t, "misattributed payload to be dropped", func() bool { return alice.droppedCount() == 3 })
	expectNoEvent(t, alice)
	if h, _ := alice.app.History(bob.id(), 50); len(h) != 2 {
		t.Fatalf("history after replay has %d messages", len(h))
	}

	if err := alice.app.RenameContact(bob.id(), "Bobby"); err != nil {
		t.Fatal(err)
	}
	if got := contact(t, alice, bob.id()).DisplayName; got != "Bobby" {
		t.Fatalf("renamed to %q", got)
	}

	bob.stop()
	var offline tui.MessageInfo
	waitFor(t, "recipient offline status", func() bool {
		offline = send(t, alice, bob.id(), "are you there?")
		return offline.Status == tui.StatusRecipientOffline
	})
	h, _ = alice.app.History(bob.id(), 1)
	if len(h) != 1 || h[0].ID != offline.ID || h[0].Status != tui.StatusRecipientOffline {
		t.Fatalf("stored offline message %+v", h)
	}

	if err := alice.app.RemoveContact(bob.id()); err != nil {
		t.Fatal(err)
	}
	if list, _ := alice.app.Contacts(); len(list) != 0 {
		t.Fatalf("contacts after remove %+v", list)
	}
}

// rotatedIdentity returns an identity with the signing keys, and so the
// ID, of base and a fresh encryption key.
func rotatedIdentity(t *testing.T, base *identity.Identity) *identity.Identity {
	t.Helper()
	type secret struct {
		Version   uint8  `cbor:"1,keyasint"`
		EdSeed    []byte `cbor:"2,keyasint"`
		MLDSASeed []byte `cbor:"3,keyasint"`
		KEMKey    []byte `cbor:"4,keyasint"`
	}
	other, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	decode := func(i *identity.Identity) secret {
		raw, err := i.MarshalSecret()
		if err != nil {
			t.Fatal(err)
		}
		var s secret
		if err := cbor.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	mixed := decode(base)
	mixed.KEMKey = decode(other).KEMKey
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := enc.Marshal(mixed)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := identity.UnmarshalSecret(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotated.Destroy)
	if rotated.ID() != base.ID() {
		t.Fatal("rotated identity has a different ID")
	}
	return rotated
}

func TestKeyChange(t *testing.T) {
	r := startRelay(t)
	alice, bob := newUser(t, r, "Alice"), newUser(t, r, "Bob")
	addContact(t, alice, bob.id(), "Bob")

	before, err := alice.app.Verification(bob.id())
	if err != nil || len(strings.ReplaceAll(before.SafetyNumber, " ", "")) != 60 || !strings.HasPrefix(before.QRPayload, "qchat-verify:1:") {
		t.Fatalf("verification %+v, %v", before, err)
	}
	if err := alice.app.MarkVerified(bob.id(), true); err != nil {
		t.Fatal(err)
	}
	if c := contact(t, alice, bob.id()); !c.Verified || c.KeyChanged {
		t.Fatalf("after verifying %+v", c)
	}

	addContact(t, alice, bob.id(), "")
	expectNoEvent(t, alice)
	if c := contact(t, alice, bob.id()); !c.Verified || c.KeyChanged || c.DisplayName != "Bob" {
		t.Fatalf("refresh with the same bundle changed the contact: %+v", c)
	}

	rotated := rotatedIdentity(t, bob.prof.Identity)
	rotatedBundle, err := rotated.Bundle(2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), eventTimeout)
	defer cancel()
	if _, err := bob.sess.Request(ctx, protocol.TypeRegister, protocol.Register{Bundle: rotatedBundle}); err != nil {
		t.Fatalf("registering rotated bundle: %v", err)
	}

	addContact(t, alice, bob.id(), "")
	if e := expectEvent[tui.ContactKeyChanged](t, alice); e.ContactID != bob.id() {
		t.Fatalf("key change for %s", e.ContactID)
	}
	c := contact(t, alice, bob.id())
	if c.Verified || !c.KeyChanged {
		t.Fatalf("after key change %+v", c)
	}
	v, err := alice.app.Verification(bob.id())
	if err != nil || v.Verified || !v.KeyChanged {
		t.Fatalf("verification after key change %+v, %v", v, err)
	}
	if err := alice.app.MarkVerified(bob.id(), true); err != nil {
		t.Fatal(err)
	}
	if c := contact(t, alice, bob.id()); !c.Verified || c.KeyChanged {
		t.Fatalf("after verifying again %+v", c)
	}
	if err := alice.app.MarkVerified(bob.id(), false); err != nil {
		t.Fatal(err)
	}
	if c := contact(t, alice, bob.id()); c.Verified || c.KeyChanged {
		t.Fatalf("after unverifying %+v", c)
	}
}

func TestApplyBundleIgnoresRollback(t *testing.T) {
	base, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	defer base.Destroy()
	rotated := rotatedIdentity(t, base)
	bundle := func(i *identity.Identity, serial uint64) *identity.Bundle {
		raw, err := i.Bundle(serial, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		b, err := identity.ParseBundleForID(raw, base.ID())
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	current := bundle(base, 5)
	now := time.Now()
	stored := clientdb.Contact{ID: base.ID(), Bundle: current.Raw, BundleSerial: 5, Verified: true, VerifiedAt: now}

	for _, serial := range []uint64{4, 5} {
		c := stored
		if applyBundle(&c, bundle(rotated, serial), now) || c.BundleSerial != 5 || !c.Verified {
			t.Fatalf("bundle with serial %d was applied: %+v", serial, c)
		}
	}
	c := stored
	if applyBundle(&c, bundle(base, 6), now) || c.BundleSerial != 6 || !c.Verified || !c.KeyChangedAt.IsZero() {
		t.Fatalf("same key with higher serial: %+v", c)
	}
	c = stored
	if !applyBundle(&c, bundle(rotated, 6), now) || c.BundleSerial != 6 || c.Verified || c.KeyChangedAt.IsZero() {
		t.Fatalf("new key with higher serial: %+v", c)
	}
}

func TestSendWithoutSession(t *testing.T) {
	r := startRelay(t)
	alice, bob := newUser(t, r, "Alice"), newUser(t, r, "Bob")
	addContact(t, alice, bob.id(), "")
	alice.stop()
	m := send(t, alice, bob.id(), "lost")
	if m.Status != tui.StatusFailed || m.Error == "" {
		t.Fatalf("send while disconnected %+v", m)
	}
	if _, err := alice.app.AddContact(context.Background(), bob.id(), ""); !errors.Is(err, ErrOffline) {
		t.Fatalf("add while disconnected: %v", err)
	}
}
