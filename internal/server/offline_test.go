package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/craguS/qchat/internal/protocol"
)

// testClock is a settable clock for the server.
type testClock struct {
	unixNano atomic.Int64
}

func newTestClock() *testClock {
	c := &testClock{}
	c.unixNano.Store(time.Now().UnixNano())
	return c
}

func (c *testClock) now() time.Time { return time.Unix(0, c.unixNano.Load()) }

func (c *testClock) advance(d time.Duration) { c.unixNano.Add(int64(d)) }

// alignToHour moves the clock forward to the next full hour, where stored
// messages get their expiry rounded to.
func (c *testClock) alignToHour() {
	now := c.now()
	c.advance(roundUpToHour(now).Sub(now))
}

// fastFrames lifts the per-session frame rate limit for tests that send
// many frames.
func fastFrames(c *Config) {
	c.Registration = RegistrationOpen
	c.Limits.FramesPerSecond = 10_000
	c.Limits.Burst = 10_000
}

// registerOffline registers u without authenticating it.
func registerOffline(t *testing.T, ts *testServer, u testUser) {
	t.Helper()
	conn := openSession(t, ts)
	mustRegister(t, conn, u.bundle, "")
	conn.Close(websocket.StatusNormalClosure, "")
}

// login opens a new authenticated session for an already registered u.
func login(t *testing.T, ts *testServer, u testUser) *websocket.Conn {
	t.Helper()
	conn := openSession(t, ts)
	authenticate(t, ts, conn, u)
	return conn
}

func ack(t *testing.T, conn *websocket.Conn, qid uint64) {
	t.Helper()
	sendFrame(t, conn, protocol.TypeAck, 0, protocol.Ack{QueueID: qid})
}

// sendAccepted sends payload to to and expects SendAccepted.
func sendAccepted(t *testing.T, conn *websocket.Conn, id uint64, to []byte, payload string) {
	t.Helper()
	sendMessage(t, conn, id, to, []byte(payload))
	expectSendResult(t, conn, id, protocol.SendAccepted)
}

// queuedCount returns the number of messages stored for u that are still
// valid at the server's clock.
func queuedCount(t *testing.T, ts *testServer, u testUser) int {
	t.Helper()
	stored, err := ts.srv.db.QueuedFor(context.Background(), u.ident.ID(), 0, 10_000, ts.srv.now())
	if err != nil {
		t.Fatal(err)
	}
	return len(stored)
}

func TestOfflineDeliveryAndAck(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	alice, bob := newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	registerOffline(t, ts, bob)

	for i := range 3 {
		sendAccepted(t, aliceConn, uint64(10+i), bob.id(), fmt.Sprintf("offline %d", i))
	}

	bobConn := login(t, ts, bob)
	var qids []uint64
	for i := range 3 {
		qids = append(qids, expectDeliver(t, bobConn, alice.id(), []byte(fmt.Sprintf("offline %d", i))))
	}
	if qids[0] >= qids[1] || qids[1] >= qids[2] {
		t.Fatalf("queue IDs not increasing: %v", qids)
	}
	expectAlive(t, bobConn)
	ack(t, bobConn, qids[0])
	ack(t, bobConn, qids[1])
	expectAlive(t, bobConn)

	sendAccepted(t, aliceConn, 20, bob.id(), "live")
	live := expectDeliver(t, bobConn, alice.id(), []byte("live"))
	if live <= qids[2] {
		t.Fatalf("live queue ID %d not after %d", live, qids[2])
	}
	expectAlive(t, bobConn)
	bobConn.Close(websocket.StatusNormalClosure, "")

	again := login(t, ts, bob)
	if got := expectDeliver(t, again, alice.id(), []byte("offline 2")); got != qids[2] {
		t.Fatalf("redelivered queue ID %d, want %d", got, qids[2])
	}
	if got := expectDeliver(t, again, alice.id(), []byte("live")); got != live {
		t.Fatalf("redelivered queue ID %d, want %d", got, live)
	}
	expectAlive(t, again)
	ack(t, again, qids[2])
	ack(t, again, live)
	ack(t, again, live)
	ack(t, again, 1<<64-1)
	expectAlive(t, again)
	again.Close(websocket.StatusNormalClosure, "")

	last := login(t, ts, bob)
	expectAlive(t, last)
	if n := queuedCount(t, ts, bob); n != 0 {
		t.Fatalf("%d messages still stored after acknowledgement", n)
	}
}

func TestAckOnlyDeletesOwnMessages(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	carolConn := online(t, ts, carol)
	registerOffline(t, ts, bob)
	sendAccepted(t, aliceConn, 1, bob.id(), "for bob")
	sendAccepted(t, aliceConn, 2, carol.id(), "for carol")
	carolQID := expectDeliver(t, carolConn, alice.id(), []byte("for carol"))

	ack(t, carolConn, carolQID-1)
	ack(t, aliceConn, carolQID-1)
	expectAlive(t, carolConn)
	expectAlive(t, aliceConn)

	anonymous := openSession(t, ts)
	sendFrame(t, anonymous, protocol.TypeAck, 3, protocol.Ack{QueueID: carolQID - 1})
	expectReject(t, anonymous, 3, protocol.ErrCodeUnauthorized)

	bobConn := login(t, ts, bob)
	if got := expectDeliver(t, bobConn, alice.id(), []byte("for bob")); got != carolQID-1 {
		t.Fatalf("bob's message has queue ID %d, want %d", got, carolQID-1)
	}
	if n := queuedCount(t, ts, carol); n != 1 {
		t.Fatalf("carol has %d stored messages, want 1", n)
	}
}

// TestBacklogIsPushedInWindows stores more messages than backlogWindow and
// checks that the backlog is pushed in order as the client acknowledges.
func TestBacklogIsPushedInWindows(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	alice, bob := newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	registerOffline(t, ts, bob)
	const total = backlogWindow + 5
	for i := range total {
		sendAccepted(t, aliceConn, uint64(i+1), bob.id(), fmt.Sprintf("m%d", i))
	}

	bobConn := login(t, ts, bob)
	var qids []uint64
	for i := range backlogWindow {
		qids = append(qids, expectDeliver(t, bobConn, alice.id(), []byte(fmt.Sprintf("m%d", i))))
	}
	expectAlive(t, bobConn)

	ack(t, bobConn, qids[0])
	qids = append(qids, expectDeliver(t, bobConn, alice.id(), []byte(fmt.Sprintf("m%d", backlogWindow))))
	expectAlive(t, bobConn)

	sendAccepted(t, aliceConn, 100, bob.id(), "live")
	live := expectDeliver(t, bobConn, alice.id(), []byte("live"))

	for _, qid := range qids[1:5] {
		ack(t, bobConn, qid)
	}
	for i := backlogWindow + 1; i < total; i++ {
		qids = append(qids, expectDeliver(t, bobConn, alice.id(), []byte(fmt.Sprintf("m%d", i))))
	}
	for i := 1; i < len(qids); i++ {
		if qids[i] <= qids[i-1] || qids[i] >= live {
			t.Fatalf("backlog out of order: %v (live %d)", qids, live)
		}
	}
	expectAlive(t, bobConn)
	for _, qid := range append(qids[5:], live) {
		ack(t, bobConn, qid)
	}
	expectAlive(t, bobConn)
	if n := queuedCount(t, ts, bob); n != 0 {
		t.Fatalf("%d messages left after acknowledging all", n)
	}
}

func TestSendQueueFull(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		fastFrames(c)
		c.Limits.MaxQueuedMessages = 2
	}})
	alice, bob := newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	registerOffline(t, ts, bob)
	sendAccepted(t, aliceConn, 1, bob.id(), "one")
	sendAccepted(t, aliceConn, 2, bob.id(), "two")
	sendMessage(t, aliceConn, 3, bob.id(), []byte("three"))
	expectReject(t, aliceConn, 3, protocol.ErrCodeQueueFull)

	bobConn := login(t, ts, bob)
	first := expectDeliver(t, bobConn, alice.id(), []byte("one"))
	expectDeliver(t, bobConn, alice.id(), []byte("two"))
	ack(t, bobConn, first)
	expectAlive(t, bobConn)
	sendAccepted(t, aliceConn, 4, bob.id(), "three")
	expectDeliver(t, bobConn, alice.id(), []byte("three"))
}

func TestSendToUnknownOrSelf(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	alice := newUser(t)
	aliceConn := online(t, ts, alice)
	sendMessage(t, aliceConn, 1, newUser(t).id(), []byte("nobody"))
	expectReject(t, aliceConn, 1, protocol.ErrCodeNotFound)
	sendMessage(t, aliceConn, 2, alice.id(), []byte("self"))
	expectReject(t, aliceConn, 2, protocol.ErrCodeBadRequest)
	if n := queuedCount(t, ts, alice); n != 0 {
		t.Fatalf("%d messages stored", n)
	}
}

func TestUndeliveredMessagesExpire(t *testing.T) {
	clock := newTestClock()
	ts := startServer(t, serverOptions{
		config: func(c *Config) {
			fastFrames(c)
			c.UndeliveredTTL = DurationOf(time.Hour)
		},
		tweak: func(s *Server) {
			s.now = clock.now
			s.pruneInterval = 10 * time.Millisecond
		},
	})
	alice, bob := newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	registerOffline(t, ts, bob)
	clock.alignToHour()
	sendAccepted(t, aliceConn, 1, bob.id(), "expires")
	clock.advance(30 * time.Minute)
	sendAccepted(t, aliceConn, 2, bob.id(), "survives")

	clock.advance(31 * time.Minute)
	waitFor(t, "the expired message to be pruned", func() bool {
		stored, err := ts.srv.db.QueuedFor(context.Background(), bob.ident.ID(), 0, 10, time.Unix(0, 0))
		return err == nil && len(stored) == 1
	})
	bobConn := login(t, ts, bob)
	expectDeliver(t, bobConn, alice.id(), []byte("survives"))
	expectAlive(t, bobConn)
	bobConn.Close(websocket.StatusNormalClosure, "")

	clock.advance(60 * time.Minute)
	again := login(t, ts, bob)
	expectAlive(t, again)
}

// TestOfflineLogsContainNoClientData drives prekeys and offline delivery
// and checks that the debug log mentions no ID, payload or prekey.
func TestOfflineLogsContainNoClientData(t *testing.T) {
	logs := &syncBuffer{}
	ts := startServer(t, serverOptions{logs: logs, config: func(c *Config) {
		fastFrames(c)
		c.Limits.MaxQueuedMessages = 1
	}})
	alice, bob := newUser(t), newUser(t)
	payload := "secret offline payload"
	aliceConn := online(t, ts, alice)
	registerOffline(t, ts, bob)

	signer := newPrekeySigner(t, alice)
	signed := signedPrekey(t, signer, time.Now())
	oneTime := oneTimePrekeys(t, signer, 1)
	uploadPrekeys(t, aliceConn, 1, protocol.PrekeyUpload{SignedPrekey: signed.Raw, OneTimePrekeys: oneTime})
	sendFrame(t, aliceConn, protocol.TypePrekeyUpload, 2, protocol.PrekeyUpload{SignedPrekey: tamper(signed.Raw)})
	expectError(t, aliceConn, protocol.ErrCodeBadRequest)

	sendAccepted(t, aliceConn, 3, bob.id(), payload)
	sendMessage(t, aliceConn, 4, bob.id(), []byte(payload))
	expectReject(t, aliceConn, 4, protocol.ErrCodeQueueFull)

	bobConn := login(t, ts, bob)
	qid := expectDeliver(t, bobConn, alice.id(), []byte(payload))
	requestPrekeys(t, bobConn, 5, alice.id())
	ack(t, bobConn, qid)
	expectAlive(t, bobConn)
	aliceConn.Close(websocket.StatusNormalClosure, "")
	bobConn.Close(websocket.StatusNormalClosure, "")
	if err := ts.stop(t); err != nil {
		t.Fatal(err)
	}

	output := logs.String()
	var forbidden []string
	for _, u := range []testUser{alice, bob} {
		id := u.ident.ID()
		forbidden = append(forbidden, hex.EncodeToString(id[:]), id.String(), id.ShortString())
	}
	forbidden = append(forbidden, payload, hex.EncodeToString([]byte(payload)),
		hex.EncodeToString(signed.Raw[len(signed.Raw)-32:]), hex.EncodeToString(oneTime[0][len(oneTime[0])-32:]))
	for _, s := range forbidden {
		if strings.Contains(output, s) {
			t.Errorf("log contains %q:\n%s", s, output)
		}
	}
}
