package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/craguS/qchat/internal/protocol"
)

func sendMulti(t *testing.T, conn *websocket.Conn, id uint64, to [][]byte, payload []byte) {
	t.Helper()
	sendFrame(t, conn, protocol.TypeSendMulti, id, protocol.SendMulti{To: to, Payload: payload})
}

// strangers returns n random IDs that no test registers.
func strangers(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = make([]byte, protocol.IDSize)
		rand.Read(out[i])
	}
	return out
}

func TestSendMultiDelivers(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	alice, bob, carol, dave := newUser(t), newUser(t), newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	bobConn := online(t, ts, bob)
	carolConn := online(t, ts, carol)
	registerOffline(t, ts, dave)
	payload := []byte("group envelope")

	sendMulti(t, aliceConn, 7, [][]byte{bob.id(), carol.id(), dave.id()}, payload)
	expectSendResult(t, aliceConn, 7, protocol.SendAccepted)
	bobQID := expectDeliver(t, bobConn, alice.id(), payload)
	carolQID := expectDeliver(t, carolConn, alice.id(), payload)
	expectAlive(t, aliceConn)
	expectAlive(t, bobConn)
	expectAlive(t, carolConn)

	daveConn := login(t, ts, dave)
	daveQID := expectDeliver(t, daveConn, alice.id(), payload)
	expectAlive(t, daveConn)
	if bobQID == carolQID || bobQID == daveQID || carolQID == daveQID {
		t.Fatalf("queue IDs not distinct: %d %d %d", bobQID, carolQID, daveQID)
	}
	if !(bobQID < carolQID && carolQID < daveQID) {
		t.Fatalf("queue IDs not in recipient order: %d %d %d", bobQID, carolQID, daveQID)
	}

	ack(t, bobConn, bobQID)
	expectAlive(t, bobConn)
	if n := queuedCount(t, ts, bob); n != 0 {
		t.Fatalf("%d messages left for bob after ack", n)
	}
	for _, u := range []testUser{carol, dave} {
		if n := queuedCount(t, ts, u); n != 1 {
			t.Fatalf("bob's ack changed another recipient's queue: %d messages", n)
		}
	}
}

func TestSendMultiUnknownRecipientStoresNothing(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	registerOffline(t, ts, bob)
	registerOffline(t, ts, carol)

	sendMulti(t, aliceConn, 1, [][]byte{bob.id(), strangers(1)[0], carol.id()}, []byte("x"))
	frame := expectError(t, aliceConn, protocol.ErrCodeNotFound)
	if frame.ID != 1 {
		t.Fatalf("Error ID %d", frame.ID)
	}
	body, err := protocol.DecodeBody[protocol.ErrorBody](frame, protocol.TypeError)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range [][]byte{bob.id(), carol.id()} {
		if strings.Contains(body.Message, hex.EncodeToString(id)) {
			t.Fatalf("error names a recipient: %q", body.Message)
		}
	}
	expectAlive(t, aliceConn)
	for _, u := range []testUser{bob, carol} {
		if n := queuedCount(t, ts, u); n != 0 {
			t.Fatalf("%d messages stored despite NotFound", n)
		}
	}
}

func TestSendMultiRejectsSelf(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	alice, bob := newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	registerOffline(t, ts, bob)

	sendMulti(t, aliceConn, 1, [][]byte{bob.id(), alice.id()}, []byte("x"))
	expectReject(t, aliceConn, 1, protocol.ErrCodeBadRequest)
	sendMulti(t, aliceConn, 2, [][]byte{alice.id()}, []byte("x"))
	expectReject(t, aliceConn, 2, protocol.ErrCodeBadRequest)
	for _, u := range []testUser{alice, bob} {
		if n := queuedCount(t, ts, u); n != 0 {
			t.Fatalf("%d messages stored", n)
		}
	}
}

func TestSendMultiRequiresAuthAndSize(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		fastFrames(c)
		c.Limits.MaxMessageSize = MinMessageSize
	}})
	alice, bob := newUser(t), newUser(t)
	registerOffline(t, ts, bob)

	anon := openSession(t, ts)
	sendMulti(t, anon, 1, [][]byte{bob.id()}, []byte("x"))
	expectReject(t, anon, 1, protocol.ErrCodeUnauthorized)

	aliceConn := online(t, ts, alice)
	sendMulti(t, aliceConn, 2, [][]byte{bob.id()}, make([]byte, MinMessageSize+1))
	expectReject(t, aliceConn, 2, protocol.ErrCodeTooLarge)
	sendMulti(t, aliceConn, 3, [][]byte{bob.id()}, make([]byte, MinMessageSize))
	expectSendResult(t, aliceConn, 3, protocol.SendAccepted)
	if n := queuedCount(t, ts, bob); n != 1 {
		t.Fatalf("%d messages stored, want 1", n)
	}
}

// rawSendMulti encodes a SendMulti frame without validating its body.
func rawSendMulti(t *testing.T, id uint64, to [][]byte, payload []byte) []byte {
	t.Helper()
	var body bytes.Buffer
	body.WriteByte(0xa2)
	body.WriteByte(0x01)
	switch {
	case len(to) < 24:
		body.WriteByte(0x80 | byte(len(to)))
	case len(to) < 256:
		body.Write([]byte{0x98, byte(len(to))})
	default:
		body.Write([]byte{0x99, byte(len(to) >> 8), byte(len(to))})
	}
	for _, r := range to {
		body.Write([]byte{0x58, byte(len(r))})
		body.Write(r)
	}
	body.Write([]byte{0x02, 0x40 | byte(len(payload))})
	body.Write(payload)
	encoded, err := protocol.Encode(protocol.Frame{Version: protocol.Version, Type: protocol.TypeSendMulti, ID: id, Body: body.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestSendMultiMalformedIsFatal(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	alice, bob := newUser(t), newUser(t)
	registerOffline(t, ts, bob)

	t.Run("TooManyRecipients", func(t *testing.T) {
		conn := online(t, ts, alice)
		sendRaw(t, conn, rawSendMulti(t, 1, strangers(protocol.MaxMultiRecipients+1), []byte("x")))
		expectFatal(t, conn, protocol.ErrCodeBadRequest)
	})
	t.Run("Duplicate", func(t *testing.T) {
		conn := login(t, ts, alice)
		sendRaw(t, conn, rawSendMulti(t, 1, [][]byte{bob.id(), bob.id()}, []byte("x")))
		expectFatal(t, conn, protocol.ErrCodeBadRequest)
	})
	t.Run("Empty", func(t *testing.T) {
		conn := login(t, ts, alice)
		sendRaw(t, conn, rawSendMulti(t, 1, nil, []byte("x")))
		expectFatal(t, conn, protocol.ErrCodeBadRequest)
	})
	t.Run("MaxRecipientsAccepted", func(t *testing.T) {
		conn := login(t, ts, alice)
		sendRaw(t, conn, rawSendMulti(t, 1, strangers(protocol.MaxMultiRecipients), []byte("x")))
		expectReject(t, conn, 1, protocol.ErrCodeNotFound)
	})
	if n := queuedCount(t, ts, bob); n != 0 {
		t.Fatalf("%d messages stored", n)
	}
}

func TestSendMultiQueueFullStoresNothing(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		fastFrames(c)
		c.Limits.MaxQueuedMessages = 1
	}})
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	registerOffline(t, ts, bob)
	registerOffline(t, ts, carol)
	sendAccepted(t, aliceConn, 1, bob.id(), "fills bob")

	sendMulti(t, aliceConn, 2, [][]byte{carol.id(), bob.id()}, []byte("group"))
	expectReject(t, aliceConn, 2, protocol.ErrCodeQueueFull)
	if n := queuedCount(t, ts, carol); n != 0 {
		t.Fatalf("%d messages stored for carol despite QueueFull", n)
	}
	if n := queuedCount(t, ts, bob); n != 1 {
		t.Fatalf("%d messages stored for bob, want only the first", n)
	}

	bobConn := login(t, ts, bob)
	qid := expectDeliver(t, bobConn, alice.id(), []byte("fills bob"))
	ack(t, bobConn, qid)
	expectAlive(t, bobConn)
	sendMulti(t, aliceConn, 3, [][]byte{carol.id(), bob.id()}, []byte("group"))
	expectSendResult(t, aliceConn, 3, protocol.SendAccepted)
	expectDeliver(t, bobConn, alice.id(), []byte("group"))
}

// TestSendMultiCountsPerRecipient checks that a SendMulti spends one frame
// token per recipient and is refused, without ending the session, when the
// tokens do not arrive in time.
func TestSendMultiCountsPerRecipient(t *testing.T) {
	ts := startServer(t, serverOptions{
		config: func(c *Config) {
			c.Registration = RegistrationOpen
			c.Limits.FramesPerSecond = 0.2
			c.Limits.Burst = 10
		},
		tweak: func(s *Server) { s.multiSendWait = 50 * time.Millisecond },
	})
	alice := newUser(t)
	aliceConn := online(t, ts, alice)

	sendMulti(t, aliceConn, 1, strangers(protocol.MaxMultiRecipients), []byte("x"))
	expectReject(t, aliceConn, 1, protocol.ErrCodeRateLimited)
	sendMulti(t, aliceConn, 2, strangers(3), []byte("x"))
	expectError(t, aliceConn, protocol.ErrCodeNotFound)
	sendMulti(t, aliceConn, 3, strangers(3), []byte("x"))
	if frame := expectError(t, aliceConn, protocol.ErrCodeRateLimited); frame.ID != 3 {
		t.Fatalf("Error ID %d, want 3", frame.ID)
	}
}

func TestSpendFrameTokens(t *testing.T) {
	newTestSession := func(limiter *rate.Limiter, wait time.Duration) *session {
		return &session{srv: &Server{multiSendWait: wait}, limiter: limiter, closed: make(chan struct{})}
	}

	t.Run("BeyondBurst", func(t *testing.T) {
		s := newTestSession(rate.NewLimiter(2000, 5), 5*time.Second)
		if !s.spendFrameTokens(protocol.MaxMultiRecipients - 1) {
			t.Fatal("tokens beyond the burst were refused at a high sustained rate")
		}
	})
	t.Run("Exhausted", func(t *testing.T) {
		s := newTestSession(rate.NewLimiter(rate.Every(time.Hour), 5), time.Second)
		if !s.spendFrameTokens(0) || !s.spendFrameTokens(3) {
			t.Fatal("tokens within the burst refused")
		}
		start := time.Now()
		if s.spendFrameTokens(3) {
			t.Fatal("tokens granted beyond the bucket")
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatal("hopeless wait was not refused at once")
		}
		if !s.spendFrameTokens(2) {
			t.Fatal("a refused request spent tokens")
		}
	})
	t.Run("Closed", func(t *testing.T) {
		s := newTestSession(rate.NewLimiter(1, 1), 10*time.Second)
		if !s.spendFrameTokens(1) {
			t.Fatal("first token refused")
		}
		close(s.closed)
		start := time.Now()
		if s.spendFrameTokens(1) {
			t.Fatal("tokens granted to a closed session")
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatal("closed session kept waiting")
		}
	})
}

// TestSendMultiLogsContainNoClientData checks that the debug log mentions no
// ID or payload after successful and failed SendMulti requests.
func TestSendMultiLogsContainNoClientData(t *testing.T) {
	logs := &syncBuffer{}
	ts := startServer(t, serverOptions{logs: logs, config: func(c *Config) {
		fastFrames(c)
		c.Limits.MaxQueuedMessages = 1
	}})
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	payload := "secret group payload"
	stranger := strangers(1)[0]
	aliceConn := online(t, ts, alice)
	bobConn := online(t, ts, bob)
	registerOffline(t, ts, carol)

	sendMulti(t, aliceConn, 1, [][]byte{bob.id(), carol.id()}, []byte(payload))
	expectSendResult(t, aliceConn, 1, protocol.SendAccepted)
	qid := expectDeliver(t, bobConn, alice.id(), []byte(payload))
	ack(t, bobConn, qid)
	sendMulti(t, aliceConn, 2, [][]byte{bob.id(), carol.id()}, []byte(payload))
	expectReject(t, aliceConn, 2, protocol.ErrCodeQueueFull)
	sendMulti(t, aliceConn, 3, [][]byte{bob.id(), stranger}, []byte(payload))
	expectReject(t, aliceConn, 3, protocol.ErrCodeNotFound)
	sendMulti(t, aliceConn, 4, [][]byte{alice.id()}, []byte(payload))
	expectReject(t, aliceConn, 4, protocol.ErrCodeBadRequest)
	sendRaw(t, aliceConn, rawSendMulti(t, 5, [][]byte{bob.id(), bob.id()}, []byte(payload)))
	expectFatal(t, aliceConn, protocol.ErrCodeBadRequest)
	bobConn.Close(websocket.StatusNormalClosure, "")
	if err := ts.stop(t); err != nil {
		t.Fatal(err)
	}

	output := logs.String()
	forbidden := []string{payload, hex.EncodeToString([]byte(payload)), hex.EncodeToString(stranger)}
	for _, u := range []testUser{alice, bob, carol} {
		id := u.ident.ID()
		forbidden = append(forbidden, hex.EncodeToString(id[:]), id.String(), id.ShortString())
	}
	for _, s := range forbidden {
		if strings.Contains(output, s) {
			t.Errorf("log contains %q:\n%s", s, output)
		}
	}
}
