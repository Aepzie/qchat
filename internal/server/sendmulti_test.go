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

// expectMultiResult reads the SendMultiResult answering request id.
func expectMultiResult(t *testing.T, conn *websocket.Conn, id uint64) protocol.SendMultiResult {
	t.Helper()
	return expectBody[protocol.SendMultiResult](t, conn, protocol.TypeSendMultiResult, id)
}

// expectAllStored reads the SendMultiResult answering request id and
// checks that no recipient failed.
func expectAllStored(t *testing.T, conn *websocket.Conn, id uint64) {
	t.Helper()
	if result := expectMultiResult(t, conn, id); len(result.Failed) != 0 {
		t.Fatalf("SendMultiResult lists %d failed recipients, want none", len(result.Failed))
	}
}

// failedReasons maps the hex ID of every failed recipient of result to its
// reason.
func failedReasons(result protocol.SendMultiResult) map[string]protocol.ErrorCode {
	out := make(map[string]protocol.ErrorCode, len(result.Failed))
	for i, id := range result.Failed {
		out[hex.EncodeToString(id)] = result.Reasons[i]
	}
	return out
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
	expectAllStored(t, aliceConn, 7)
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

// TestSendMultiPartialSuccess checks that a full queue and an unknown
// recipient do not keep the message from the other recipients, and that
// the result names both with their reasons.
func TestSendMultiPartialSuccess(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		fastFrames(c)
		c.Limits.MaxQueuedMessages = 1
	}})
	alice, bob, carol, dave := newUser(t), newUser(t), newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	registerOffline(t, ts, bob)
	carolConn := online(t, ts, carol)
	registerOffline(t, ts, dave)
	stranger := strangers(1)[0]
	sendAccepted(t, aliceConn, 1, bob.id(), "fills bob")

	sendMulti(t, aliceConn, 2, [][]byte{carol.id(), bob.id(), stranger, dave.id()}, []byte("group"))
	result := expectMultiResult(t, aliceConn, 2)
	if result.Status != protocol.SendAccepted || len(result.Failed) != 2 {
		t.Fatalf("result %+v, want Accepted with two failed recipients", result)
	}
	if !bytes.Equal(result.Failed[0], bob.id()) || !bytes.Equal(result.Failed[1], stranger) {
		t.Fatal("failed recipients not in request order")
	}
	if result.Reasons[0] != protocol.ErrCodeQueueFull || result.Reasons[1] != protocol.ErrCodeNotFound {
		t.Fatalf("reasons %v, want [QueueFull NotFound]", result.Reasons)
	}
	expectDeliver(t, carolConn, alice.id(), []byte("group"))
	expectAlive(t, aliceConn)
	for _, u := range []testUser{carol, dave, bob} {
		if n := queuedCount(t, ts, u); n != 1 {
			t.Fatalf("%d messages stored, want 1", n)
		}
	}

	bobConn := login(t, ts, bob)
	qid := expectDeliver(t, bobConn, alice.id(), []byte("fills bob"))
	ack(t, bobConn, qid)
	expectAlive(t, bobConn)
	sendMulti(t, aliceConn, 3, [][]byte{bob.id(), carol.id()}, []byte("again"))
	result = expectMultiResult(t, aliceConn, 3)
	if reasons := failedReasons(result); len(reasons) != 1 || reasons[hex.EncodeToString(carol.id())] != protocol.ErrCodeQueueFull {
		t.Fatalf("second result %+v, want only carol failed with QueueFull", result)
	}
	expectDeliver(t, bobConn, alice.id(), []byte("again"))

	sendMulti(t, aliceConn, 4, strangers(3), []byte("nobody"))
	result = expectMultiResult(t, aliceConn, 4)
	if len(result.Failed) != 3 {
		t.Fatalf("result %+v, want every recipient failed", result)
	}
	for _, reason := range result.Reasons {
		if reason != protocol.ErrCodeNotFound {
			t.Fatalf("reasons %v, want NotFound", result.Reasons)
		}
	}
	expectAlive(t, aliceConn)
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
	expectAllStored(t, aliceConn, 3)
	if n := queuedCount(t, ts, bob); n != 1 {
		t.Fatalf("%d messages stored, want 1", n)
	}
}

// TestSendMultiFanOutCap checks that payload size times recipient count is
// capped at maxMultiSendBytes.
func TestSendMultiFanOutCap(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		fastFrames(c)
		c.Limits.MaxMessageSize = MaxMessageSize
	}})
	alice := newUser(t)
	aliceConn := online(t, ts, alice)
	perRecipient := maxMultiSendBytes / protocol.MaxMultiRecipients

	sendMulti(t, aliceConn, 1, strangers(protocol.MaxMultiRecipients), make([]byte, perRecipient+1))
	expectReject(t, aliceConn, 1, protocol.ErrCodeTooLarge)
	sendMulti(t, aliceConn, 2, strangers(protocol.MaxMultiRecipients), make([]byte, perRecipient))
	if result := expectMultiResult(t, aliceConn, 2); len(result.Failed) != protocol.MaxMultiRecipients {
		t.Fatalf("%d failed recipients, want %d", len(result.Failed), protocol.MaxMultiRecipients)
	}
	sendMulti(t, aliceConn, 3, strangers(3), make([]byte, perRecipient+1))
	if result := expectMultiResult(t, aliceConn, 3); len(result.Failed) != 3 {
		t.Fatalf("%d failed recipients, want 3", len(result.Failed))
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
	t.Run("ResultFromClient", func(t *testing.T) {
		conn := login(t, ts, alice)
		sendFrame(t, conn, protocol.TypeSendMultiResult, 1, protocol.SendMultiResult{Status: protocol.SendAccepted})
		expectFatal(t, conn, protocol.ErrCodeBadRequest)
	})
	t.Run("MaxRecipientsAccepted", func(t *testing.T) {
		conn := login(t, ts, alice)
		sendRaw(t, conn, rawSendMulti(t, 1, strangers(protocol.MaxMultiRecipients), []byte("x")))
		if result := expectMultiResult(t, conn, 1); len(result.Failed) != protocol.MaxMultiRecipients {
			t.Fatalf("%d failed recipients, want %d", len(result.Failed), protocol.MaxMultiRecipients)
		}
	})
	if n := queuedCount(t, ts, bob); n != 0 {
		t.Fatalf("%d messages stored", n)
	}
}

// TestSendMultiRecipientBudget checks, at the default limits, that a
// SendMulti counts as one frame against the frame bucket and as one token
// per recipient against the separate recipient budget, which refuses a
// request without ending the session once it is spent.
func TestSendMultiRecipientBudget(t *testing.T) {
	clock := newTestClock()
	ts := startServer(t, serverOptions{
		config: openMode,
		tweak: func(s *Server) {
			s.now = clock.now
			s.multiSendWait = 50 * time.Millisecond
		},
	})
	if ts.cfg.Limits.Burst != DefaultBurst || ts.cfg.Limits.MultiRecipientsPerMinute != DefaultMultiRecipientsPerMinute {
		t.Fatal("test expects the default limits")
	}
	alice, bob := newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	bobConn := online(t, ts, bob)
	const n = 255
	group := append(strangers(n-1), bob.id())

	for id := uint64(1); id <= 2; id++ {
		sendMulti(t, aliceConn, id, group, []byte("burst"))
		if result := expectMultiResult(t, aliceConn, id); len(result.Failed) != n-1 {
			t.Fatalf("request %d: %d failed recipients, want %d", id, len(result.Failed), n-1)
		}
		expectDeliver(t, bobConn, alice.id(), []byte("burst"))
	}
	sendMulti(t, aliceConn, 3, group, []byte("over budget"))
	expectReject(t, aliceConn, 3, protocol.ErrCodeRateLimited)
	if count := queuedCount(t, ts, bob); count != 2 {
		t.Fatalf("%d messages stored for bob, want 2", count)
	}

	sendMulti(t, aliceConn, 4, [][]byte{bob.id()}, []byte("small"))
	expectAllStored(t, aliceConn, 4)
	expectDeliver(t, bobConn, alice.id(), []byte("small"))

	clock.advance(time.Duration(n) * time.Minute / DefaultMultiRecipientsPerMinute)
	sendMulti(t, aliceConn, 5, group, []byte("refilled"))
	expectMultiResult(t, aliceConn, 5)
	expectDeliver(t, bobConn, alice.id(), []byte("refilled"))
	expectAlive(t, aliceConn)
}

func TestSpendRecipients(t *testing.T) {
	newTestSession := func(limiter *rate.Limiter, wait time.Duration) *session {
		return &session{srv: &Server{multiSendWait: wait, now: time.Now}, multiLimiter: limiter, closed: make(chan struct{})}
	}

	t.Run("WithinBurst", func(t *testing.T) {
		s := newTestSession(rate.NewLimiter(rate.Every(time.Hour), MultiRecipientsBurst), time.Second)
		if !s.spendRecipients(protocol.MaxMultiRecipients) {
			t.Fatal("first maximal request refused within the burst")
		}
		if !s.spendRecipients(protocol.MaxMultiRecipients) {
			t.Fatal("second maximal request refused within the burst")
		}
	})
	t.Run("ShortWait", func(t *testing.T) {
		s := newTestSession(rate.NewLimiter(1000, 10), time.Second)
		if !s.spendRecipients(10) {
			t.Fatal("burst refused")
		}
		start := time.Now()
		if !s.spendRecipients(10) {
			t.Fatal("tokens refused although they arrive within the wait")
		}
		if time.Since(start) < 5*time.Millisecond {
			t.Fatal("tokens granted without waiting for them")
		}
	})
	t.Run("Exhausted", func(t *testing.T) {
		s := newTestSession(rate.NewLimiter(rate.Every(time.Hour), 5), time.Second)
		if !s.spendRecipients(3) {
			t.Fatal("tokens within the burst refused")
		}
		start := time.Now()
		if s.spendRecipients(3) {
			t.Fatal("tokens granted beyond the bucket")
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatal("hopeless wait was not refused at once")
		}
		if !s.spendRecipients(2) {
			t.Fatal("a refused request spent tokens")
		}
	})
	t.Run("Closed", func(t *testing.T) {
		s := newTestSession(rate.NewLimiter(1, 1), 10*time.Second)
		if !s.spendRecipients(1) {
			t.Fatal("first token refused")
		}
		close(s.closed)
		start := time.Now()
		if s.spendRecipients(1) {
			t.Fatal("tokens granted to a closed session")
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatal("closed session kept waiting")
		}
	})
}

// TestSendMultiLogsContainNoClientData checks that the debug log mentions no
// ID or payload after successful, partial and failed SendMulti requests.
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
	expectAllStored(t, aliceConn, 1)
	qid := expectDeliver(t, bobConn, alice.id(), []byte(payload))
	ack(t, bobConn, qid)
	sendMulti(t, aliceConn, 2, [][]byte{bob.id(), carol.id(), stranger}, []byte(payload))
	if result := expectMultiResult(t, aliceConn, 2); len(result.Failed) != 2 {
		t.Fatalf("%d failed recipients, want 2", len(result.Failed))
	}
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
