package app

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/crypto/vault"
	"github.com/craguS/qchat/internal/e2e"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/profile"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/sealed"
	"github.com/craguS/qchat/internal/senderkey"
	"github.com/craguS/qchat/internal/tui"
)

func newSealedUser(t *testing.T, r *fakeRelay, name string) *fakeUser {
	t.Helper()
	u := newFakeUser(t, r, name)
	u.enableSealed()
	return u
}

// peerKey returns the access key u stores for peer.
func (u *fakeUser) peerKey(peer *fakeUser) (sealed.AccessKey, bool) {
	u.t.Helper()
	key, found, err := u.app.peerAccessKey(context.Background(), peer.id)
	if err != nil {
		u.t.Fatal(err)
	}
	return key, found
}

// incoming delivers every queued message and returns the messages shown.
func (u *fakeUser) incoming() []tui.IncomingMessage {
	u.t.Helper()
	for _, d := range u.relay.take(u.id) {
		u.app.handleDelivery(context.Background(), d)
	}
	var out []tui.IncomingMessage
	for _, ev := range u.drainEvents() {
		if in, ok := ev.(tui.IncomingMessage); ok {
			out = append(out, in)
		}
	}
	return out
}

func (u *fakeUser) routes(peer *fakeUser) []tui.SendRoute {
	u.t.Helper()
	msgs, err := u.app.History(peer.cid(), 100)
	if err != nil {
		u.t.Fatal(err)
	}
	var out []tui.SendRoute
	for _, m := range msgs {
		if m.Outgoing {
			out = append(out, m.Route)
		}
	}
	return out
}

// sealedFriends makes a and b contacts of each other, sends the first message
// from a and delivers everything until both hold the other's access key.
func sealedFriends(t *testing.T, a, b *fakeUser) {
	t.Helper()
	a.add(b)
	b.add(a)
	if m := a.send(b, "hello"); m.Status != tui.StatusSent || m.Route != tui.RouteIdentified {
		t.Fatalf("first message: status %v, route %v (%s)", m.Status, m.Route, m.Error)
	}
	settle(t, a, b)
	if key, ok := a.peerKey(b); !ok || key != b.app.ownAccessKey() {
		t.Fatalf("%s lacks %s's access key", a.prof.DisplayName(), b.prof.DisplayName())
	}
	if key, ok := b.peerKey(a); !ok || key != a.app.ownAccessKey() {
		t.Fatalf("%s lacks %s's access key", b.prof.DisplayName(), a.prof.DisplayName())
	}
}

func TestAccessKeyExchangeAndSealedSend(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newSealedUser(t, r, "Alice"), newSealedUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)

	first := alice.send(bob, "hello")
	if first.Status != tui.StatusSent || first.Route != tui.RouteIdentified {
		t.Fatalf("first message: status %v, route %v (%s)", first.Status, first.Route, first.Error)
	}
	if rows := r.queued(bob.id); len(rows) != 1 || rows[0].From != [32]byte(alice.id) {
		t.Fatalf("first message rows %+v, want one identified row", rows)
	}
	wantTexts(t, "bob", bob.receive(), "hello")
	if rows := r.queued(alice.id); len(rows) != 1 || rows[0].From != [32]byte(bob.id) {
		t.Fatalf("bob queued %d rows for alice, want his access key, identified", len(rows))
	}
	wantTexts(t, "alice", alice.receive())
	if key, ok := alice.peerKey(bob); !ok || key != bob.app.ownAccessKey() {
		t.Fatal("alice did not store bob's access key")
	}
	if r.sealedSends != 1 {
		t.Fatalf("%d sealed sends, want alice's own key going back sealed", r.sealedSends)
	}
	wantTexts(t, "bob", bob.receive())
	if key, ok := bob.peerKey(alice); !ok || key != alice.app.ownAccessKey() {
		t.Fatal("bob did not store alice's access key")
	}
	if len(r.queued(alice.id))+len(r.queued(bob.id)) != 0 {
		t.Fatal("access keys were shared more than once")
	}
	for _, u := range []*fakeUser{alice, bob} {
		verifier := u.app.ownAccessKey().Verifier()
		if !bytes.Equal(r.verifiers[u.id], verifier[:]) {
			t.Fatalf("relay holds no verifier for %s", u.prof.DisplayName())
		}
	}

	m := alice.send(bob, "sealed hello")
	if m.Status != tui.StatusSent || m.Route != tui.RouteSealed {
		t.Fatalf("sealed message: status %v, route %v (%s)", m.Status, m.Route, m.Error)
	}
	rows := r.queued(bob.id)
	if len(rows) != 1 || rows[0].From != protocol.SealedFrom || bytes.Contains(rows[0].Payload, alice.id[:]) || !sealed.IsEnvelope(rows[0].Payload) {
		t.Fatalf("sealed row %+v names the sender", rows)
	}
	got := bob.incoming()
	if len(got) != 1 || got[0].ContactID != alice.cid() || got[0].Message.Text != "sealed hello" || got[0].UnknownSender {
		t.Fatalf("bob was shown %+v", got)
	}
	if reply := bob.send(alice, "sealed reply"); reply.Route != tui.RouteSealed || reply.Status != tui.StatusSent {
		t.Fatalf("reply: status %v, route %v (%s)", reply.Status, reply.Route, reply.Error)
	}
	if rows := r.queued(alice.id); len(rows) != 1 || rows[0].From != protocol.SealedFrom {
		t.Fatalf("reply rows %+v", rows)
	}
	wantTexts(t, "alice", alice.receive(), "sealed reply")
	if got := alice.routes(bob); !slices.Equal(got, []tui.SendRoute{tui.RouteIdentified, tui.RouteSealed}) {
		t.Fatalf("alice's stored routes %v", got)
	}
	if alice.dropped()+bob.dropped() != 0 {
		t.Fatalf("dropped %d and %d deliveries", alice.dropped(), bob.dropped())
	}
}

func TestForgedSealedEnvelopeIsDropped(t *testing.T) {
	r := newFakeRelay()
	ctx := context.Background()
	alice, bob := newSealedUser(t, r, "Alice"), newSealedUser(t, r, "Bob")
	sealedFriends(t, alice, bob)
	carol := newFakeUser(t, r, "Carol")
	bob.add(carol)
	mallory := newFakeUser(t, r, "Mallory")
	mallory.add(bob)
	mallory.send(bob, "from mallory")
	genuine := r.take(bob.id)
	if len(genuine) != 1 {
		t.Fatalf("%d deliveries from mallory", len(genuine))
	}
	withInit := genuine[0].Payload
	env, err := e2e.ParseEnvelope(withInit)
	if err != nil || env.Init == nil {
		t.Fatalf("mallory's envelope: %v", err)
	}
	env.Init = nil
	withoutInit, err := e2e.MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := bob.session(alice)
	dropped := bob.dropped()

	forgeries := []struct {
		claimed identity.ID
		inner   []byte
	}{
		{alice.id, withInit},
		{alice.id, withoutInit},
		{carol.id, withInit},
		{bob.id, withInit},
	}
	for i, f := range forgeries {
		forged, err := sealed.Seal(f.claimed, bob.app.self, f.inner)
		if err != nil {
			t.Fatal(err)
		}
		bob.app.handleDelivery(ctx, client.Delivery{From: protocol.SealedFrom, Payload: forged, QueueID: uint64(9000 + i)})
	}
	bob.app.handleDelivery(ctx, client.Delivery{From: protocol.SealedFrom, Payload: withoutInit, QueueID: 9100})
	bob.app.handleDelivery(ctx, client.Delivery{From: protocol.SealedFrom, Payload: []byte{0xa2, 0x01, 0x01, 0x02, 0x40}, QueueID: 9101})

	if evs := bob.drainEvents(); len(evs) != 0 {
		t.Fatalf("forgeries reached the interface: %+v", evs)
	}
	if got := bob.dropped() - dropped; got != len(forgeries)+2 {
		t.Fatalf("%d deliveries dropped, want %d", got, len(forgeries)+2)
	}
	acks := bob.relay.acksOf(bob.id)
	for _, q := range []uint64{9000, 9001, 9002, 9003, 9100, 9101} {
		if !slices.Contains(acks, q) {
			t.Errorf("forged delivery %d not acknowledged", q)
		}
	}
	if after, _ := bob.session(alice); !bytes.Equal(after.State, before.State) || after.Updated != before.Updated {
		t.Fatal("a forgery changed bob's session with alice")
	}
	if _, found := bob.session(carol); found {
		t.Fatal("a forgery claiming carol started a session")
	}
	if n := len(bob.app.handshakes[carol.id]); n != 0 {
		t.Fatalf("a forgery spent %d of carol's session starts", n)
	}
	if _, found := bob.session(mallory); found {
		t.Fatal("a forgery started a session with mallory")
	}

	bob.app.handleDelivery(ctx, genuine[0])
	got := bob.drainEvents()
	if len(got) != 1 {
		t.Fatalf("genuine delivery: %+v", got)
	}
	if in, ok := got[0].(tui.IncomingMessage); !ok || in.ContactID != mallory.cid() || !in.UnknownSender || in.Message.Text != "from mallory" {
		t.Fatalf("genuine delivery shown as %+v", got[0])
	}
	if m := alice.send(bob, "still fine"); m.Route != tui.RouteSealed {
		t.Fatalf("route %v", m.Route)
	}
	wantTexts(t, "bob", bob.receive(), "still fine")
}

func TestGroupMessagesUseSealedSendMulti(t *testing.T) {
	r := newFakeRelay()
	alice, bob, carol := newSealedUser(t, r, "Alice"), newSealedUser(t, r, "Bob"), newSealedUser(t, r, "Carol")
	alice.add(bob)
	alice.add(carol)
	bob.add(alice)
	carol.add(alice)
	gid := alice.createGroup("Trio", bob, carol)
	settle(t, alice, bob, carol)
	for _, pair := range [][2]*fakeUser{{alice, bob}, {alice, carol}, {bob, alice}, {carol, alice}} {
		if _, ok := pair[0].peerKey(pair[1]); !ok {
			t.Fatalf("%s lacks %s's key after the group was created", pair[0].prof.DisplayName(), pair[1].prof.DisplayName())
		}
	}
	if _, ok := bob.peerKey(carol); ok {
		t.Fatal("bob has carol's key without a session")
	}

	multi, sealedMulti := r.multi, r.sealedMulti
	if m := alice.sendGroup(gid, "sealed to all"); m.Route != tui.RouteSealed {
		t.Fatalf("alice's group message route %v", m.Route)
	}
	if r.sealedMulti != sealedMulti+1 || r.multi != multi {
		t.Fatalf("SealedSendMulti %d, SendMulti %d", r.sealedMulti-sealedMulti, r.multi-multi)
	}
	for _, u := range []*fakeUser{alice, bob, carol} {
		rows := r.queued(u.id)
		if len(rows) == 0 || !senderkey.IsGroupEnvelope(rows[len(rows)-1].Payload) || (u == alice && len(rows) != 1) {
			t.Fatalf("%s has %d rows, want the group envelope last (and only the echo for the sender)", u.prof.DisplayName(), len(rows))
		}
		for _, row := range rows {
			if row.From != protocol.SealedFrom {
				t.Fatalf("an identified row for %s", u.prof.DisplayName())
			}
		}
	}
	echo := r.queued(alice.id)[0].QueueID
	got := settle(t, alice, bob, carol)
	if len(got[alice]) != 0 || !slices.Contains(r.acksOf(alice.id), echo) {
		t.Fatalf("alice's echo was shown (%v) or not acknowledged", got[alice])
	}
	if !slices.Equal(got[bob], []string{"sealed to all"}) || !slices.Equal(got[carol], []string{"sealed to all"}) {
		t.Fatalf("group texts %v / %v", got[bob], got[carol])
	}

	multi, sealedMulti = r.multi, r.sealedMulti
	if m := bob.sendGroup(gid, "from bob"); m.Route != tui.RouteIdentified {
		t.Fatalf("bob's first group message route %v, want identified (carol's key unknown)", m.Route)
	}
	if r.sealedMulti != sealedMulti || r.multi != multi+1 {
		t.Fatalf("SealedSendMulti %d, SendMulti %d, want the whole fan-out identified", r.sealedMulti-sealedMulti, r.multi-multi)
	}
	got = settle(t, alice, bob, carol)
	if !slices.Equal(got[alice], []string{"from bob"}) || !slices.Equal(got[carol], []string{"from bob"}) {
		t.Fatalf("group texts %v / %v", got[alice], got[carol])
	}
	if _, ok := bob.peerKey(carol); !ok {
		t.Fatal("bob did not get carol's key from their new session")
	}
	if _, ok := carol.peerKey(bob); !ok {
		t.Fatal("carol did not get bob's key from their new session")
	}
	multi = r.multi
	if m := bob.sendGroup(gid, "bob sealed"); m.Route != tui.RouteSealed {
		t.Fatalf("bob's second group message route %v", m.Route)
	}
	if r.multi != multi {
		t.Fatal("a group message went identified although every key is known")
	}
	got = settle(t, alice, bob, carol)
	if !slices.Equal(got[alice], []string{"bob sealed"}) || !slices.Equal(got[carol], []string{"bob sealed"}) {
		t.Fatalf("group texts %v / %v", got[alice], got[carol])
	}
	for _, u := range []*fakeUser{alice, bob, carol} {
		if u.dropped() != 0 {
			t.Errorf("%s dropped %d deliveries", u.prof.DisplayName(), u.dropped())
		}
	}
}

func TestSealedSenderFallbackAndRefusal(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newSealedUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)
	alice.send(bob, "hello")
	wantTexts(t, "bob", bob.receive(), "hello")
	if len(r.queued(alice.id)) != 0 {
		t.Fatal("a client without an anonymous session shared its access key")
	}
	if m := bob.send(alice, "hi"); m.Route != tui.RouteIdentified {
		t.Fatalf("bob's route %v", m.Route)
	}
	wantTexts(t, "alice", alice.receive(), "hi")
	wantTexts(t, "bob", bob.receive())
	if _, ok := bob.peerKey(alice); !ok {
		t.Fatal("bob did not store alice's key")
	}
	if m := bob.send(alice, "still identified"); m.Route != tui.RouteIdentified {
		t.Fatalf("bob without an anonymous session sent %v", m.Route)
	}
	if rows := r.queued(alice.id); len(rows) != 1 || rows[0].From != [32]byte(bob.id) {
		t.Fatalf("rows %+v", rows)
	}
	if m := alice.send(bob, "no key yet"); m.Route != tui.RouteIdentified || m.Status != tui.StatusSent {
		t.Fatalf("alice without bob's key: status %v, route %v", m.Status, m.Route)
	}

	r2 := newFakeRelay()
	carol, dave := newSealedUser(t, r2, "Carol"), newSealedUser(t, r2, "Dave")
	sealedFriends(t, carol, dave)
	r2.mu.Lock()
	r2.verifiers[dave.id] = make([]byte, sealed.VerifierSize)
	r2.mu.Unlock()
	m := carol.send(dave, "refused")
	if m.Status != tui.StatusFailed || m.Route != tui.RouteSealed || !strings.Contains(m.Error, "waiting for updated key") {
		t.Fatalf("refused sealed send: status %v, route %v, error %q", m.Status, m.Route, m.Error)
	}
	if !carol.app.keyStale(context.Background(), dave.id) {
		t.Fatal("the refused key was not marked stale")
	}
	if m := carol.send(dave, "still sealed"); m.Route != tui.RouteSealed || m.Status != tui.StatusFailed {
		t.Fatalf("send with a stale key: status %v, route %v", m.Status, m.Route)
	}
	if rows := r2.queued(dave.id); len(rows) != 0 {
		t.Fatalf("a refused sealed send fell back to an identified one: %+v", rows)
	}
}

func TestAccessKeysSurviveRestart(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newSealedUser(t, r, "Alice"), newSealedUser(t, r, "Bob")
	sealedFriends(t, alice, bob)
	aliceKey, bobKey := alice.app.ownAccessKey(), bob.app.ownAccessKey()
	alice.restart()
	bob.restart()
	if alice.app.ownAccessKey() != aliceKey || bob.app.ownAccessKey() != bobKey {
		t.Fatal("own access keys changed across a restart")
	}
	if key, ok := alice.peerKey(bob); !ok || key != bobKey {
		t.Fatal("alice lost bob's key")
	}
	if key, ok := bob.peerKey(alice); !ok || key != aliceKey {
		t.Fatal("bob lost alice's key")
	}
	if m := alice.send(bob, "after restart"); m.Route != tui.RouteSealed || m.Status != tui.StatusSent {
		t.Fatalf("after restart: status %v, route %v (%s)", m.Status, m.Route, m.Error)
	}
	if n := len(r.queued(bob.id)); n != 1 {
		t.Fatalf("%d rows for bob, want the message only (no key shared again)", n)
	}
	wantTexts(t, "bob", bob.receive(), "after restart")
	if got := alice.routes(bob); !slices.Equal(got, []tui.SendRoute{tui.RouteIdentified, tui.RouteSealed}) {
		t.Fatalf("routes after restart %v", got)
	}
}

func TestRotateAccessKey(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newSealedUser(t, r, "Alice"), newSealedUser(t, r, "Bob")
	sealedFriends(t, alice, bob)
	old := bob.app.ownAccessKey()
	if err := bob.app.RotateAccessKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	bob.app.bg.Wait()
	fresh := bob.app.ownAccessKey()
	verifier := fresh.Verifier()
	if fresh == old || !bytes.Equal(r.verifiers[bob.id], verifier[:]) {
		t.Fatal("rotation did not replace the key at the relay")
	}
	rows := r.queued(alice.id)
	if len(rows) != 1 || rows[0].From != protocol.SealedFrom {
		t.Fatalf("new key rows %+v, want one sealed row", rows)
	}
	wantTexts(t, "alice", alice.receive())
	if key, ok := alice.peerKey(bob); !ok || key != fresh {
		t.Fatal("alice did not get bob's new key")
	}
	if m := alice.send(bob, "new key"); m.Route != tui.RouteSealed || m.Status != tui.StatusSent {
		t.Fatalf("after rotation: status %v (%s)", m.Status, m.Error)
	}
	wantTexts(t, "bob", bob.receive(), "new key")
}

func TestRemovingContactRevokesAccessKey(t *testing.T) {
	r := newFakeRelay()
	alice, bob, carol := newSealedUser(t, r, "Alice"), newSealedUser(t, r, "Bob"), newSealedUser(t, r, "Carol")
	sealedFriends(t, alice, bob)
	sealedFriends(t, alice, carol)
	old := alice.app.ownAccessKey()
	if err := alice.app.RemoveContact(carol.cid()); err != nil {
		t.Fatal(err)
	}
	alice.app.bg.Wait()
	fresh := alice.app.ownAccessKey()
	verifier := fresh.Verifier()
	if fresh == old || !bytes.Equal(r.verifiers[alice.id], verifier[:]) {
		t.Fatal("removing a contact did not rotate the access key")
	}
	if rows := r.queued(carol.id); len(rows) != 0 {
		t.Fatalf("the removed contact got %d rows, want none", len(rows))
	}
	wantTexts(t, "bob", bob.receive())
	if key, ok := bob.peerKey(alice); !ok || key != fresh {
		t.Fatal("the remaining contact did not get the new key")
	}
	if m := carol.send(alice, "with the old key"); m.Status != tui.StatusFailed || m.Route != tui.RouteSealed {
		t.Fatalf("removed contact's sealed send: status %v, route %v", m.Status, m.Route)
	}
	if len(r.queued(alice.id)) != 0 {
		t.Fatal("the removed contact still reached alice")
	}
}

func TestSealedSessionStartUsesPrefetchedPrekeys(t *testing.T) {
	r := newFakeRelay()
	ctx := context.Background()
	alice, carol := newSealedUser(t, r, "Alice"), newSealedUser(t, r, "Carol")
	alice.add(carol)
	carol.add(alice)
	key := carol.app.ownAccessKey()
	if err := alice.prof.DB.PutSetting(ctx, idSetting(peerKeyPrefix, carol.id), key[:]); err != nil {
		t.Fatal(err)
	}
	pool := func() int {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.oneTime[carol.id])
	}
	before := pool()
	m := alice.send(carol, "first, sealed")
	if m.Status != tui.StatusFailed || m.Route != tui.RouteSealed || !strings.Contains(m.Error, "preparing") {
		t.Fatalf("sealed send without a session: status %v, route %v, error %q", m.Status, m.Route, m.Error)
	}
	alice.app.bg.Wait()
	if pool() != before-1 {
		t.Fatal("prekeys were not fetched in the background")
	}
	m = alice.send(carol, "second, sealed")
	if m.Status != tui.StatusSent || m.Route != tui.RouteSealed {
		t.Fatalf("send with prefetched prekeys: status %v (%s)", m.Status, m.Error)
	}
	if pool() != before-1 {
		t.Fatal("prekeys were fetched right before the sealed send")
	}
	if rows := r.queued(carol.id); len(rows) != 1 || rows[0].From != protocol.SealedFrom {
		t.Fatalf("rows %+v", rows)
	}
	got := carol.incoming()
	if len(got) != 1 || got[0].ContactID != alice.cid() || got[0].Message.Text != "second, sealed" {
		t.Fatalf("carol was shown %+v", got)
	}
}

func TestSealedRoutingByShape(t *testing.T) {
	r := newFakeRelay()
	ctx := context.Background()
	alice, bob := newSealedUser(t, r, "Alice"), newSealedUser(t, r, "Bob")
	sealedFriends(t, alice, bob)
	mallory := newFakeUser(t, r, "Mallory")
	bob.add(mallory)
	alice.send(bob, "real")
	rows := r.take(bob.id)
	if len(rows) != 1 {
		t.Fatalf("%d rows", len(rows))
	}
	dropped := bob.dropped()
	identifiedFromMallory := client.Delivery{From: [32]byte(mallory.id), Payload: rows[0].Payload, QueueID: 7001}
	bob.app.handleDelivery(ctx, identifiedFromMallory)
	if bob.dropped() != dropped+1 || len(bob.drainEvents()) != 0 {
		t.Fatal("an identified delivery whose sealed claim differs from the relay's sender was accepted")
	}
	identifiedFromAlice := client.Delivery{From: [32]byte(alice.id), Payload: rows[0].Payload, QueueID: 7002}
	bob.app.handleDelivery(ctx, identifiedFromAlice)
	got := bob.drainEvents()
	if len(got) != 1 {
		t.Fatalf("matching identified sealed delivery: %+v", got)
	}
	if in, ok := got[0].(tui.IncomingMessage); !ok || in.ContactID != alice.cid() || in.Message.Text != "real" {
		t.Fatalf("shown as %+v", got[0])
	}
	if acks := r.acksOf(bob.id); !slices.Contains(acks, 7001) || !slices.Contains(acks, 7002) {
		t.Fatalf("acks %v", acks)
	}
}

func newSealedRelayUser(t *testing.T, r relay, name string) *user {
	t.Helper()
	dir := t.TempDir()
	p, err := profile.Create(dir, []byte(testPassphrase), name, vault.TestParams())
	if err != nil {
		t.Fatal(err)
	}
	return startUserWith(t, r, dir, name, p, true)
}

// TestSealedSenderThroughRelay exchanges access keys through a real relay
// and then sends sealed in both directions: the relay delivers the
// messages without a sender.
func TestSealedSenderThroughRelay(t *testing.T) {
	r := startRelay(t)
	alice, bob := newSealedRelayUser(t, r, "Alice"), newSealedRelayUser(t, r, "Bob")
	addContact(t, alice, bob.id(), "Bob")
	addContact(t, bob, alice.id(), "Alice")
	aliceID, bobID := alice.app.selfID(), bob.app.selfID()
	hasKey := func(u *user, peer identity.ID) func() bool {
		return func() bool {
			_, found, err := u.app.peerAccessKey(context.Background(), peer)
			return err == nil && found
		}
	}

	if m := send(t, alice, bob.id(), "hello"); m.Status != tui.StatusSent || m.Route != tui.RouteIdentified {
		t.Fatalf("first message: status %v, route %v (%s)", m.Status, m.Route, m.Error)
	}
	if in := expectEvent[tui.IncomingMessage](t, bob); in.Message.Text != "hello" || bob.lastDelivery(t).IsSealed() {
		t.Fatalf("first message %+v", in)
	}
	waitFor(t, "alice to store bob's key", hasKey(alice, bobID))
	waitFor(t, "bob to store alice's key", hasKey(bob, aliceID))

	if m := send(t, alice, bob.id(), "sealed hello"); m.Status != tui.StatusSent || m.Route != tui.RouteSealed {
		t.Fatalf("sealed message: status %v, route %v (%s)", m.Status, m.Route, m.Error)
	}
	in := expectEvent[tui.IncomingMessage](t, bob)
	if in.Message.Text != "sealed hello" || in.ContactID != alice.id() || in.UnknownSender {
		t.Fatalf("sealed message shown as %+v", in)
	}
	if d := bob.lastDelivery(t); !d.IsSealed() || !sealed.IsEnvelope(d.Payload) {
		t.Fatalf("relay delivered the sealed message from %x", d.From)
	}
	if m := send(t, bob, alice.id(), "sealed reply"); m.Route != tui.RouteSealed || m.Status != tui.StatusSent {
		t.Fatalf("reply: status %v, route %v (%s)", m.Status, m.Route, m.Error)
	}
	if in := expectEvent[tui.IncomingMessage](t, alice); in.Message.Text != "sealed reply" || in.ContactID != bob.id() {
		t.Fatalf("reply shown as %+v", in)
	}
	if !alice.lastDelivery(t).IsSealed() {
		t.Fatal("the reply was not sealed")
	}
	if alice.droppedCount()+bob.droppedCount() != 0 {
		t.Fatalf("dropped %d and %d deliveries", alice.droppedCount(), bob.droppedCount())
	}
}
