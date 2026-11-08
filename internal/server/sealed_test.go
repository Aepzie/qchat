package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/sealed"
)

// newAccessKey returns a fresh access key.
func newAccessKey(t *testing.T) sealed.AccessKey {
	t.Helper()
	key, err := sealed.NewAccessKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// proofOf returns the access proof for key.
func proofOf(key sealed.AccessKey) []byte {
	verifier := key.Verifier()
	return verifier[:]
}

// setAccessKey uploads the verifier of key on an authenticated session.
func setAccessKey(t *testing.T, conn *websocket.Conn, id uint64, key sealed.AccessKey, allowUnidentified bool) {
	t.Helper()
	sendFrame(t, conn, protocol.TypeSetAccessKey, id, protocol.SetAccessKey{Verifier: proofOf(key), AllowUnidentified: allowUnidentified})
	expectBody[protocol.AccessKeySet](t, conn, protocol.TypeAccessKeySet, id)
}

// sealedUser registers u, uploads a fresh access key and returns its
// authenticated session and the key.
func sealedUser(t *testing.T, ts *testServer, u testUser) (*websocket.Conn, sealed.AccessKey) {
	t.Helper()
	conn := online(t, ts, u)
	key := newAccessKey(t)
	setAccessKey(t, conn, 30, key, false)
	return conn, key
}

func sealedSend(t *testing.T, conn *websocket.Conn, id uint64, to, proof, payload []byte) {
	t.Helper()
	sendFrame(t, conn, protocol.TypeSealedSend, id, protocol.SealedSend{To: to, AccessProof: proof, Payload: payload})
}

func sealedSendMulti(t *testing.T, conn *websocket.Conn, id uint64, entries []protocol.SealedRecipient, payload []byte) {
	t.Helper()
	sendFrame(t, conn, protocol.TypeSealedSendMulti, id, protocol.SealedSendMulti{Entries: entries, Payload: payload})
}

// randomProof returns a proof that matches no verifier.
func randomProof() []byte { return strangers(1)[0] }

// strangerEntries returns n entries for unknown recipients.
func strangerEntries(n int) []protocol.SealedRecipient {
	out := make([]protocol.SealedRecipient, n)
	for i, id := range strangers(n) {
		out[i] = protocol.SealedRecipient{To: id, AccessProof: randomProof()}
	}
	return out
}

// expectSealedDeliver reads a Deliver frame, checks that it is sealed and
// carries payload, and returns its queue ID.
func expectSealedDeliver(t *testing.T, conn *websocket.Conn, payload []byte) uint64 {
	t.Helper()
	return expectDeliver(t, conn, make([]byte, protocol.IDSize), payload)
}

// expectStoredSealed checks that every message stored for u is sealed.
func expectStoredSealed(t *testing.T, ts *testServer, u testUser, want int) {
	t.Helper()
	stored, err := ts.srv.db.QueuedFor(context.Background(), u.ident.ID(), 0, 100, ts.srv.now())
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != want {
		t.Fatalf("%d messages stored, want %d", len(stored), want)
	}
	for _, msg := range stored {
		if !msg.Sealed || msg.Sender != ([32]byte{}) {
			t.Fatalf("stored message %d keeps a sender: %+v", msg.QID, msg)
		}
	}
}

func TestSealedSendDelivers(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	bob, carol := newUser(t), newUser(t)
	bobConn, bobKey := sealedUser(t, ts, bob)
	carolConn, carolKey := sealedUser(t, ts, carol)
	carolConn.Close(websocket.StatusNormalClosure, "")

	anon := openSession(t, ts)
	sealedSend(t, anon, 1, bob.id(), proofOf(bobKey), []byte("hello bob"))
	expectSendResult(t, anon, 1, protocol.SendAccepted)
	qid := expectSealedDeliver(t, bobConn, []byte("hello bob"))
	expectStoredSealed(t, ts, bob, 1)
	ack(t, bobConn, qid)
	expectAlive(t, bobConn)

	sealedSend(t, anon, 2, carol.id(), proofOf(carolKey), []byte("while offline"))
	expectSendResult(t, anon, 2, protocol.SendAccepted)
	expectStoredSealed(t, ts, carol, 1)
	carolAgain := login(t, ts, carol)
	expectSealedDeliver(t, carolAgain, []byte("while offline"))

	entries := []protocol.SealedRecipient{
		{To: bob.id(), AccessProof: proofOf(bobKey)},
		{To: carol.id(), AccessProof: proofOf(carolKey)},
	}
	sealedSendMulti(t, anon, 3, entries, []byte("group"))
	if result := expectMultiResult(t, anon, 3); len(result.Failed) != 0 {
		t.Fatalf("SealedSendMulti failed for %d recipients", len(result.Failed))
	}
	expectSealedDeliver(t, bobConn, []byte("group"))
	expectSealedDeliver(t, carolAgain, []byte("group"))
	expectStoredSealed(t, ts, carol, 2)
	expectAlive(t, anon)
}

func TestSealedSendNoOracle(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	bob, dave, erin := newUser(t), newUser(t), newUser(t)
	bobConn, bobKey := sealedUser(t, ts, bob)
	registerOffline(t, ts, dave)
	erinConn := online(t, ts, erin)
	setAccessKey(t, erinConn, 31, newAccessKey(t), true)

	anon := openSession(t, ts)
	var answers [][]byte
	for i, to := range [][]byte{bob.id(), strangers(1)[0], dave.id()} {
		id := uint64(10 + i)
		sealedSend(t, anon, id, to, randomProof(), []byte("probe"))
		frame := expectError(t, anon, protocol.ErrCodeNotFound)
		if frame.ID != id {
			t.Fatalf("Error ID %d, want %d", frame.ID, id)
		}
		answers = append(answers, frame.Body)
	}
	for _, body := range answers[1:] {
		if !bytes.Equal(body, answers[0]) {
			t.Fatal("wrong proof, unknown recipient and recipient without a key are answered differently")
		}
	}
	sealedSend(t, anon, 20, bob.id(), make([]byte, protocol.AccessVerifierSize), []byte("zero proof"))
	expectReject(t, anon, 20, protocol.ErrCodeNotFound)

	sealedSend(t, anon, 21, erin.id(), randomProof(), []byte("open door"))
	expectSendResult(t, anon, 21, protocol.SendAccepted)
	expectSealedDeliver(t, erinConn, []byte("open door"))

	unknown := strangers(1)[0]
	entries := []protocol.SealedRecipient{
		{To: bob.id(), AccessProof: randomProof()},
		{To: unknown, AccessProof: randomProof()},
		{To: dave.id(), AccessProof: proofOf(bobKey)},
		{To: erin.id(), AccessProof: randomProof()},
	}
	sealedSendMulti(t, anon, 22, entries, []byte("mixed"))
	reasons := failedReasons(expectMultiResult(t, anon, 22))
	want := map[string]protocol.ErrorCode{
		hex.EncodeToString(bob.id()):  protocol.ErrCodeNotFound,
		hex.EncodeToString(unknown):   protocol.ErrCodeNotFound,
		hex.EncodeToString(dave.id()): protocol.ErrCodeNotFound,
	}
	if len(reasons) != len(want) {
		t.Fatalf("failed recipients %v, want %v", reasons, want)
	}
	for id, code := range want {
		if reasons[id] != code {
			t.Fatalf("failed recipients %v, want %v", reasons, want)
		}
	}
	expectSealedDeliver(t, erinConn, []byte("mixed"))
	expectAlive(t, bobConn)
	if n := queuedCount(t, ts, bob); n != 0 {
		t.Fatalf("%d messages stored for bob without a valid proof", n)
	}
}

func TestSealedSendQueueFullAfterAccess(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		fastFrames(c)
		c.Limits.MaxQueuedMessages = 1
	}})
	bob := newUser(t)
	bobConn, bobKey := sealedUser(t, ts, bob)
	bobConn.Close(websocket.StatusNormalClosure, "")
	anon := openSession(t, ts)
	sealedSend(t, anon, 1, bob.id(), proofOf(bobKey), []byte("first"))
	expectSendResult(t, anon, 1, protocol.SendAccepted)
	sealedSend(t, anon, 2, bob.id(), proofOf(bobKey), []byte("second"))
	expectReject(t, anon, 2, protocol.ErrCodeQueueFull)
	sealedSend(t, anon, 3, bob.id(), randomProof(), []byte("third"))
	expectReject(t, anon, 3, protocol.ErrCodeNotFound)
	sealedSendMulti(t, anon, 4, []protocol.SealedRecipient{{To: bob.id(), AccessProof: proofOf(bobKey)}}, []byte("fourth"))
	if reasons := failedReasons(expectMultiResult(t, anon, 4)); reasons[hex.EncodeToString(bob.id())] != protocol.ErrCodeQueueFull {
		t.Fatalf("SealedSendMulti to a full queue: %v", reasons)
	}
}

func TestSealedSendTooLarge(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		fastFrames(c)
		c.Limits.MaxMessageSize = MinMessageSize
	}})
	bob := newUser(t)
	_, bobKey := sealedUser(t, ts, bob)
	anon := openSession(t, ts)
	big := bytes.Repeat([]byte{1}, MinMessageSize+1)
	sealedSend(t, anon, 1, bob.id(), proofOf(bobKey), big)
	expectReject(t, anon, 1, protocol.ErrCodeTooLarge)
	sealedSendMulti(t, anon, 2, []protocol.SealedRecipient{{To: bob.id(), AccessProof: proofOf(bobKey)}}, big)
	expectReject(t, anon, 2, protocol.ErrCodeTooLarge)
	if n := queuedCount(t, ts, bob); n != 0 {
		t.Fatalf("%d oversized messages stored", n)
	}
}

func TestSealedFramesRejectedOnIdentifiedSessions(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	alice, bob := newUser(t), newUser(t)
	_, bobKey := sealedUser(t, ts, bob)
	single := protocol.SealedSend{To: bob.id(), AccessProof: proofOf(bobKey), Payload: []byte("linkable")}
	multi := protocol.SealedSendMulti{Entries: []protocol.SealedRecipient{{To: bob.id(), AccessProof: proofOf(bobKey)}}, Payload: []byte("linkable")}

	authenticated := online(t, ts, alice)
	sendFrame(t, authenticated, protocol.TypeSealedSend, 1, single)
	expectFatal(t, authenticated, protocol.ErrCodeBadRequest)

	authenticated = login(t, ts, alice)
	sendFrame(t, authenticated, protocol.TypeSealedSendMulti, 1, multi)
	expectFatal(t, authenticated, protocol.ErrCodeBadRequest)

	registered := openSession(t, ts)
	mustRegister(t, registered, alice.bundle, "")
	sendFrame(t, registered, protocol.TypeSealedSend, 1, single)
	expectFatal(t, registered, protocol.ErrCodeBadRequest)

	challenged := openSession(t, ts)
	beginAuth(t, challenged, alice.id())
	sendFrame(t, challenged, protocol.TypeSealedSend, 1, single)
	expectFatal(t, challenged, protocol.ErrCodeBadRequest)

	if n := queuedCount(t, ts, bob); n != 0 {
		t.Fatalf("%d messages stored from identified sessions", n)
	}
}

func TestIdentifiedFramesRejectedOnAnonymousSessions(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	alice, bob := newUser(t), newUser(t)
	_, bobKey := sealedUser(t, ts, bob)
	registerOffline(t, ts, alice)

	anonymous := func() *websocket.Conn {
		conn := openSession(t, ts)
		sealedSend(t, conn, 1, bob.id(), proofOf(bobKey), []byte("sealed"))
		expectSendResult(t, conn, 1, protocol.SendAccepted)
		return conn
	}

	conn := anonymous()
	for i, frame := range []struct {
		typ  protocol.FrameType
		body any
	}{
		{protocol.TypeKeyRequest, protocol.KeyRequest{ID: bob.id()}},
		{protocol.TypePrekeyRequest, protocol.PrekeyRequest{ID: bob.id()}},
		{protocol.TypeSend, protocol.Send{To: bob.id(), Payload: []byte("x")}},
		{protocol.TypeSendMulti, protocol.SendMulti{To: [][]byte{bob.id()}, Payload: []byte("x")}},
		{protocol.TypeSetAccessKey, protocol.SetAccessKey{Verifier: proofOf(bobKey)}},
		{protocol.TypeAck, protocol.Ack{QueueID: 1}},
	} {
		id := uint64(10 + i)
		sendFrame(t, conn, frame.typ, id, frame.body)
		expectReject(t, conn, id, protocol.ErrCodeUnauthorized)
	}

	conn = anonymous()
	register(t, conn, 2, alice.bundle, "")
	expectFatal(t, conn, protocol.ErrCodeBadRequest)

	conn = anonymous()
	sendFrame(t, conn, protocol.TypeAuthBegin, 2, protocol.AuthBegin{ID: alice.id()})
	expectFatal(t, conn, protocol.ErrCodeBadRequest)

	conn = anonymous()
	sendFrame(t, conn, protocol.TypeAuthProof, 2, protocol.AuthProof{Sig: []byte("sig")})
	expectFatal(t, conn, protocol.ErrCodeBadRequest)
}

func TestSetAccessKeyRules(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames})
	bob := newUser(t)
	fresh := openSession(t, ts)
	sendFrame(t, fresh, protocol.TypeSetAccessKey, 1, protocol.SetAccessKey{Verifier: proofOf(newAccessKey(t))})
	expectReject(t, fresh, 1, protocol.ErrCodeUnauthorized)
	sendRaw(t, fresh, mustEncodeFrame(t, protocol.Frame{Version: protocol.Version, Type: protocol.TypeSetAccessKey, ID: 2, Body: []byte{0xa0}}))
	expectFatal(t, fresh, protocol.ErrCodeBadRequest)

	bobConn, oldKey := sealedUser(t, ts, bob)
	newKey := newAccessKey(t)
	setAccessKey(t, bobConn, 32, newKey, false)
	anon := openSession(t, ts)
	sealedSend(t, anon, 1, bob.id(), proofOf(oldKey), []byte("revoked"))
	expectReject(t, anon, 1, protocol.ErrCodeNotFound)
	sealedSend(t, anon, 2, bob.id(), proofOf(newKey), []byte("current"))
	expectSendResult(t, anon, 2, protocol.SendAccepted)
	expectSealedDeliver(t, bobConn, []byte("current"))
}

func mustEncodeFrame(t *testing.T, frame protocol.Frame) []byte {
	t.Helper()
	encoded, err := protocol.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestSealedRateLimits(t *testing.T) {
	clock := newTestClock()
	ts := startServer(t, serverOptions{
		config: fastFrames,
		tweak: func(s *Server) {
			s.now = clock.now
			s.multiSendWait = time.Millisecond
		},
	})
	bob := newUser(t)
	bobConn, bobKey := sealedUser(t, ts, bob)
	full := protocol.MaxMultiRecipients

	first := openSession(t, ts)
	for id := uint64(1); id <= SealedRecipientsBurst/uint64(full); id++ {
		sealedSendMulti(t, first, id, strangerEntries(full), []byte("burst"))
		if result := expectMultiResult(t, first, id); len(result.Failed) != full {
			t.Fatalf("request %d: %d failed recipients, want %d", id, len(result.Failed), full)
		}
	}
	sealedSend(t, first, 9, bob.id(), proofOf(bobKey), []byte("over session budget"))
	expectReject(t, first, 9, protocol.ErrCodeRateLimited)

	second := openSession(t, ts)
	for id := uint64(1); id <= (SealedRecipientsBurstPerIP-SealedRecipientsBurst)/uint64(full); id++ {
		sealedSendMulti(t, second, id, strangerEntries(full), []byte("burst"))
		expectMultiResult(t, second, id)
	}
	third := openSession(t, ts)
	sealedSend(t, third, 1, bob.id(), proofOf(bobKey), []byte("over address budget"))
	expectReject(t, third, 1, protocol.ErrCodeRateLimited)
	if n := queuedCount(t, ts, bob); n != 0 {
		t.Fatalf("%d rate-limited messages stored", n)
	}

	clock.advance(time.Minute)
	sealedSend(t, third, 2, bob.id(), proofOf(bobKey), []byte("refilled"))
	expectSendResult(t, third, 2, protocol.SendAccepted)
	expectSealedDeliver(t, bobConn, []byte("refilled"))
	expectAlive(t, first)
}

func TestIPBuckets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	buckets := newIPBuckets(60, 2, 2)
	a, b, c := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
	if r := buckets.reserve(a, 2, now); r == nil || !r.OK() || r.DelayFrom(now) != 0 {
		t.Fatal("first reservation not granted at once")
	}
	if r := buckets.reserve(a, 1, now); r == nil || r.DelayFrom(now) <= 0 {
		t.Fatal("empty bucket granted a token at once")
	}
	if r := buckets.reserve(b, 1, now); r == nil || !r.OK() {
		t.Fatal("second address refused")
	}
	if r := buckets.reserve(c, 1, now); r != nil {
		t.Fatal("bucket created beyond the cap")
	}
	later := now.Add(1500 * time.Millisecond)
	if r := buckets.reserve(c, 1, later); r == nil || !r.OK() {
		t.Fatal("refilled bucket of b was not dropped to make room")
	}
	if got := buckets.size(); got != 2 {
		t.Fatalf("%d buckets, want 2", got)
	}
	buckets.reserve(c, 0, later.Add(time.Hour))
	if got := buckets.size(); got != 1 {
		t.Fatalf("%d buckets after refilling, want only the one just used", got)
	}
	if r := newIPBuckets(60, 2, 2).reserve(a, 3, now); r == nil || r.OK() {
		t.Fatal("reservation above the burst granted")
	}
}

// TestSealedLogsContainNoClientData drives sealed sending, including
// failures, and checks that the debug log mentions no ID, address, access
// key, proof or payload.
func TestSealedLogsContainNoClientData(t *testing.T) {
	logs := &syncBuffer{}
	ts := startServer(t, serverOptions{logs: logs, config: fastFrames})
	bob := newUser(t)
	bobConn, bobKey := sealedUser(t, ts, bob)
	payload := "sealed secret payload"
	wrong := randomProof()

	anon := openSession(t, ts)
	sealedSend(t, anon, 1, bob.id(), proofOf(bobKey), []byte(payload))
	expectSendResult(t, anon, 1, protocol.SendAccepted)
	expectSealedDeliver(t, bobConn, []byte(payload))
	sealedSend(t, anon, 2, bob.id(), wrong, []byte(payload))
	expectReject(t, anon, 2, protocol.ErrCodeNotFound)
	register(t, anon, 3, bob.bundle, "")
	expectFatal(t, anon, protocol.ErrCodeBadRequest)
	bobConn.Close(websocket.StatusNormalClosure, "")
	if err := ts.stop(t); err != nil {
		t.Fatal(err)
	}

	output := logs.String()
	id := bob.ident.ID()
	forbidden := []string{
		hex.EncodeToString(id[:]), id.String(), id.ShortString(),
		payload, hex.EncodeToString([]byte(payload)),
		hex.EncodeToString(bobKey[:]), hex.EncodeToString(proofOf(bobKey)), hex.EncodeToString(wrong),
		"127.0.0.1",
	}
	for _, s := range forbidden {
		if strings.Contains(output, s) {
			t.Errorf("log contains %q:\n%s", s, output)
		}
	}
}
