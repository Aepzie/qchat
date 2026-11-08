package app

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Aepzie/qchat/internal/client"
	"github.com/Aepzie/qchat/internal/e2e"
	"github.com/Aepzie/qchat/internal/handshake"
	"github.com/Aepzie/qchat/internal/store/clientdb"
	"github.com/Aepzie/qchat/internal/tui"
)

func TestOfflineStartAndReply(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)

	m := alice.send(bob, "first")
	if m.Status != tui.StatusSent || m.Error != "" {
		t.Fatalf("send %+v", m)
	}
	alice.send(bob, "second")
	s, found := alice.session(bob)
	if !found || !s.Initiator || s.Confirmed || len(s.PendingInit) == 0 {
		t.Fatalf("alice's pending session %+v", s)
	}
	for _, d := range r.queues[bob.id] {
		env, err := e2e.ParseEnvelope(d.Payload)
		if err != nil || !bytes.Equal(env.Init, s.PendingInit) {
			t.Fatalf("unconfirmed message without Init: %v", err)
		}
	}

	bob.add(alice)
	wantTexts(t, "bob", bob.receive(), "first", "second")
	if got := r.acksOf(bob.id); len(got) != 2 {
		t.Fatalf("bob acked %v, want both deliveries", got)
	}
	bs, found := bob.session(alice)
	if !found || bs.Initiator || !bs.Confirmed || established(bs) {
		t.Fatalf("bob's session %+v", bs)
	}

	bob.send(alice, "reply")
	if bs, _ = bob.session(alice); !established(bs) {
		t.Fatal("responder session not marked as used for sending")
	}
	wantTexts(t, "alice", alice.receive(), "reply")
	if s, _ = alice.session(bob); !s.Confirmed || s.PendingInit != nil {
		t.Fatalf("alice's session after reply %+v", s)
	}
	alice.send(bob, "no init now")
	for _, d := range r.queues[bob.id] {
		if env, err := e2e.ParseEnvelope(d.Payload); err != nil || env.Init != nil {
			t.Fatalf("confirmed session still attaches Init (%v)", err)
		}
	}
	wantTexts(t, "bob", bob.receive(), "no init now")

	h, err := alice.app.History(bob.cid(), 10)
	if err != nil || len(h) != 4 || h[0].Status != tui.StatusSent || h[2].Text != "reply" {
		t.Fatalf("alice's history %+v, %v", h, err)
	}
}

func TestMessageRequestKeepsSession(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	alice.send(bob, "hello stranger")
	for _, d := range r.take(bob.id) {
		bob.app.handleDelivery(context.Background(), d)
	}
	evs := bob.drainEvents()
	if len(evs) != 1 || !evs[0].(tui.IncomingMessage).UnknownSender {
		t.Fatalf("events %+v", evs)
	}
	if h, _ := bob.app.History(alice.cid(), 10); len(h) != 0 {
		t.Fatalf("message request was persisted: %+v", h)
	}
	if _, found := bob.session(alice); !found {
		t.Fatal("session with unknown sender not stored")
	}
	if n := len(bob.prekeys(clientdb.PrekeyOneTime)); n != oneTimePrekeyPool-1 {
		t.Fatalf("bob holds %d one-time prekeys, want %d", n, oneTimePrekeyPool-1)
	}
	bob.add(alice)
	if h, _ := bob.app.History(alice.cid(), 10); len(h) != 1 || h[0].Text != "hello stranger" {
		t.Fatalf("history after adding %+v", h)
	}
	bob.send(alice, "hi, now you are a contact")
	wantTexts(t, "alice", alice.receive(), "hi, now you are a contact")
}

func TestSimultaneousStart(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)

	alice.send(bob, "from alice 1")
	bob.send(alice, "from bob 1")
	alice.send(bob, "from alice 2")
	bob.send(alice, "from bob 2")
	wantTexts(t, "alice", alice.receive(), "from bob 1", "from bob 2")
	wantTexts(t, "bob", bob.receive(), "from alice 1", "from alice 2")

	winner, loser := alice, bob
	if handshake.Winner(alice.id, bob.id) == bob.id {
		winner, loser = bob, alice
	}
	ws, _ := winner.session(loser)
	ls, _ := loser.session(winner)
	if !ws.Initiator || ls.Initiator {
		t.Fatalf("winner session initiator=%v, loser session initiator=%v", ws.Initiator, ls.Initiator)
	}

	for i := range 3 {
		alice.send(bob, "a"+strings.Repeat("!", i))
		bob.send(alice, "b"+strings.Repeat("!", i))
		wantTexts(t, "alice", alice.receive(), "b"+strings.Repeat("!", i))
		wantTexts(t, "bob", bob.receive(), "a"+strings.Repeat("!", i))
	}
	if alice.dropped() != 0 || bob.dropped() != 0 {
		t.Fatalf("dropped alice=%d bob=%d", alice.dropped(), bob.dropped())
	}
	if ws, _ = winner.session(loser); !ws.Confirmed {
		t.Fatal("winning session not confirmed")
	}
	if ls, _ = loser.session(winner); !established(ls) {
		t.Fatal("loser did not adopt the winning session")
	}
}

func TestOneTimePrekeyConsumedOnce(t *testing.T) {
	r := newFakeRelay()
	alice, bob, carol := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob"), newFakeUser(t, r, "Carol")
	r.mu.Lock()
	r.oneTime[bob.id] = r.oneTime[bob.id][:1]
	r.mu.Unlock()
	before := len(bob.prekeys(clientdb.PrekeyOneTime))
	alice.add(bob)
	carol.add(bob)
	bob.add(alice)
	bob.add(carol)

	alice.send(bob, "with one-time prekey")
	replay := slices.Clone(r.queues[bob.id])
	wantTexts(t, "bob", bob.receive(), "with one-time prekey")
	if n := len(bob.prekeys(clientdb.PrekeyOneTime)); n != before-1 {
		t.Fatalf("one-time prekeys %d, want %d", n, before-1)
	}

	carol.send(bob, "without one-time prekey")
	env, err := e2e.ParseEnvelope(r.queues[bob.id][0].Payload)
	if err != nil || env.Init == nil {
		t.Fatalf("carol's first envelope %+v, %v", env, err)
	}
	wantTexts(t, "bob", bob.receive(), "without one-time prekey")
	if n := len(bob.prekeys(clientdb.PrekeyOneTime)); n != before-1 {
		t.Fatalf("a session without one-time prekey deleted one: %d left", n)
	}

	dropped := bob.dropped()
	r.mu.Lock()
	r.queues[bob.id] = replay
	r.mu.Unlock()
	wantTexts(t, "bob", bob.receive())
	if bob.dropped() != dropped+1 {
		t.Fatal("replayed session start was not dropped")
	}
	if acks := r.acksOf(bob.id); acks[len(acks)-1] != replay[0].QueueID {
		t.Fatalf("replay not acknowledged: %v", acks)
	}
	bob.send(alice, "still fine")
	wantTexts(t, "alice", alice.receive(), "still fine")
}

func TestRestartKeepsSessions(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)
	alice.send(bob, "one")
	bob.restart()
	wantTexts(t, "bob", bob.receive(), "one")
	bob.send(alice, "two")
	alice.restart()
	wantTexts(t, "alice", alice.receive(), "two")
	alice.send(bob, "three")
	bob.send(alice, "four")
	alice.restart()
	bob.restart()
	wantTexts(t, "bob", bob.receive(), "three")
	wantTexts(t, "alice", alice.receive(), "four")
	if h, _ := alice.app.History(bob.cid(), 10); len(h) != 4 {
		t.Fatalf("alice's history after restarts %+v", h)
	}
}

func TestAckRules(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)
	alice.send(bob, "original")
	queued := r.take(bob.id)[0]
	ctx := context.Background()
	acked := func(qid uint64) bool { return slices.Contains(r.acksOf(bob.id), qid) }

	tampered := queued
	tampered.Payload = slices.Clone(queued.Payload)
	tampered.Payload[len(tampered.Payload)-3] ^= 1
	tampered.QueueID = 1001
	bob.app.handleDelivery(ctx, tampered)
	if !acked(1001) || bob.dropped() != 1 {
		t.Fatal("tampered delivery not dropped and acknowledged")
	}
	if _, found := bob.session(alice); found {
		t.Fatal("tampered session start created a session")
	}
	if n := len(bob.prekeys(clientdb.PrekeyOneTime)); n != oneTimePrekeyPool {
		t.Fatalf("tampered session start consumed a one-time prekey (%d left)", n)
	}

	garbage := client.Delivery{From: queued.From, Payload: []byte("not an envelope"), QueueID: 1002}
	bob.app.handleDelivery(ctx, garbage)
	if !acked(1002) {
		t.Fatal("malformed delivery not acknowledged")
	}

	bob.app.handleDelivery(ctx, queued)
	if !acked(queued.QueueID) {
		t.Fatal("valid delivery not acknowledged")
	}
	wantTexts(t, "bob", bob.receive(), "original")

	again := queued
	again.QueueID = 1003
	bob.app.handleDelivery(ctx, again)
	if !acked(1003) || bob.dropped() != 3 {
		t.Fatalf("redelivered message: acked=%v dropped=%d", acked(1003), bob.dropped())
	}
	if h, _ := bob.app.History(alice.cid(), 10); len(h) != 1 {
		t.Fatalf("redelivery duplicated the message: %+v", h)
	}

	alice.send(bob, "while the database is down")
	pending := r.take(bob.id)[0]
	if err := bob.prof.DB.Close(); err != nil {
		t.Fatal(err)
	}
	bob.app.handleDelivery(ctx, pending)
	if acked(pending.QueueID) {
		t.Fatal("delivery acknowledged although it could not be stored")
	}
	bob.restart()
	bob.app.handleDelivery(ctx, pending)
	if !acked(pending.QueueID) {
		t.Fatal("redelivered message not acknowledged after recovery")
	}
	if h, _ := bob.app.History(alice.cid(), 10); len(h) != 2 || h[1].Text != "while the database is down" {
		t.Fatalf("history after recovery %+v", h)
	}
}

func TestEstablishedSessionIsNeverReplaced(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)
	alice.send(bob, "hi")
	wantTexts(t, "bob", bob.receive(), "hi")
	bob.send(alice, "hello")
	wantTexts(t, "alice", alice.receive(), "hello")
	before, _ := bob.session(alice)

	if err := alice.prof.DB.DeleteSession(context.Background(), bob.id); err != nil {
		t.Fatal(err)
	}
	alice.send(bob, "new start")
	wantTexts(t, "bob", bob.receive())
	after, _ := bob.session(alice)
	if !bytes.Equal(before.State, after.State) {
		t.Fatal("an Init replaced a session used in both directions")
	}
}

func TestPeerRestartReplacesUnusedResponderSession(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)
	alice.send(bob, "hi")
	wantTexts(t, "bob", bob.receive(), "hi")
	if err := alice.prof.DB.DeleteSession(context.Background(), bob.id); err != nil {
		t.Fatal(err)
	}
	alice.send(bob, "started over")
	wantTexts(t, "bob", bob.receive(), "started over")
	bob.send(alice, "fine")
	wantTexts(t, "alice", alice.receive(), "fine")
}

func TestStaleUnconfirmedSessionIsRestarted(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)
	alice.send(bob, "lost")
	r.take(bob.id)
	first, _ := alice.session(bob)

	r.clock.Advance(initRefreshAge + time.Hour)
	if err := bob.app.maintainPrekeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	alice.send(bob, "again")
	second, _ := alice.session(bob)
	if bytes.Equal(first.PendingInit, second.PendingInit) {
		t.Fatal("stale session start was reused")
	}
	wantTexts(t, "bob", bob.receive(), "again")
}

func TestHandshakeRateLimit(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)
	ctx := context.Background()
	for i := range handshakeBurst + 1 {
		if err := alice.prof.DB.DeleteSession(ctx, bob.id); err != nil && i > 0 {
			t.Fatal(err)
		}
		alice.send(bob, "start")
		d := r.take(bob.id)[0]
		d.Payload[len(d.Payload)-1] ^= 1
		bob.app.handleDelivery(ctx, d)
	}
	bob.app.ratchetMu.Lock()
	n := len(bob.app.handshakes[alice.id])
	bob.app.ratchetMu.Unlock()
	if n != handshakeBurst {
		t.Fatalf("%d handshakes recorded, want the limit %d", n, handshakeBurst)
	}
	if err := alice.prof.DB.DeleteSession(ctx, bob.id); err != nil {
		t.Fatal(err)
	}
	alice.send(bob, "limited")
	wantTexts(t, "bob", bob.receive())
	r.clock.Advance(handshakeWindow)
	if err := alice.prof.DB.DeleteSession(ctx, bob.id); err != nil {
		t.Fatal(err)
	}
	alice.send(bob, "later")
	wantTexts(t, "bob", bob.receive(), "later")
}

func TestSendFailsWithoutPrekeys(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	r.mu.Lock()
	delete(r.signed, bob.id)
	r.mu.Unlock()
	m := alice.send(bob, "nobody home")
	if m.Status != tui.StatusFailed || !strings.Contains(m.Error, "no keys") {
		t.Fatalf("send %+v", m)
	}
	if _, found := alice.session(bob); found {
		t.Fatal("session stored without prekeys")
	}
	if h, _ := alice.app.History(bob.cid(), 10); len(h) != 1 || h[0].Status != tui.StatusFailed {
		t.Fatalf("history %+v", h)
	}
}

func TestReplayedInitRejectedByReplaySet(t *testing.T) {
	for _, contact := range []bool{true, false} {
		t.Run(map[bool]string{true: "contact", false: "unknown sender"}[contact], func(t *testing.T) {
			r := newFakeRelay()
			alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
			r.mu.Lock()
			r.oneTime[bob.id] = nil
			r.mu.Unlock()
			alice.add(bob)
			if contact {
				bob.add(alice)
			}
			ctx := context.Background()
			acked := func(qid uint64) bool { return slices.Contains(r.acksOf(bob.id), qid) }

			alice.send(bob, "one")
			alice.send(bob, "two")
			queued := r.take(bob.id)
			bob.app.handleDelivery(ctx, queued[0])
			if texts := bob.receive(); len(texts) != 1 || texts[0] != "one" {
				t.Fatalf("bob received %q", texts)
			}

			if err := bob.prof.DB.DeleteSession(ctx, alice.id); err != nil {
				t.Fatal(err)
			}
			dropped := bob.dropped()
			bob.app.handleDelivery(ctx, queued[1])
			if bob.dropped() != dropped+1 || !acked(queued[1].QueueID) {
				t.Fatal("Init replayed after its session was deleted was not dropped and acknowledged")
			}
			if _, found := bob.session(alice); found {
				t.Fatal("replayed Init started a session again")
			}
			wantTexts(t, "bob", bob.receive())

			if err := alice.prof.DB.DeleteSession(ctx, bob.id); err != nil {
				t.Fatal(err)
			}
			alice.send(bob, "fresh start")
			wantTexts(t, "bob", bob.receive(), "fresh start")
			fresh, _ := bob.session(alice)
			replay := queued[1]
			replay.QueueID = 999
			bob.app.handleDelivery(ctx, replay)
			if !acked(999) || bob.dropped() != dropped+2 {
				t.Fatal("old Init replayed against a newer session was not dropped and acknowledged")
			}
			if now, _ := bob.session(alice); !bytes.Equal(now.State, fresh.State) || !bytes.Equal(now.PendingInit, fresh.PendingInit) {
				t.Fatal("replayed Init replaced the newer session")
			}
			if !contact {
				bob.add(alice)
			}
			bob.send(alice, "works")
			wantTexts(t, "alice", alice.receive(), "works")
		})
	}
}
