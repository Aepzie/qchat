package server

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/sealed"
)

// loopback is the per-IP bucket key of every test connection.
var loopback = netip.MustParseAddr("127.0.0.1")

// prekeyUser registers u, uploads a fresh access key, a signed prekey and
// n one-time prekeys, and returns its authenticated session and key.
func prekeyUser(t *testing.T, ts *testServer, u testUser, n int) (*websocket.Conn, sealed.AccessKey) {
	t.Helper()
	conn, key := sealedUser(t, ts, u)
	signer := newPrekeySigner(t, u)
	uploadPrekeys(t, conn, 40, protocol.PrekeyUpload{SignedPrekey: signedPrekey(t, signer, time.Now()).Raw, OneTimePrekeys: oneTimePrekeys(t, signer, n)})
	return conn, key
}

func TestAnonymousLookups(t *testing.T) {
	ts := startServer(t, serverOptions{config: fastFrames, tweak: func(s *Server) { s.uploadBurst = 1000 }})
	alice, bob, dave := newUser(t), newUser(t), newUser(t)
	bobConn, bobKey := prekeyUser(t, ts, bob, 2)
	registerOffline(t, ts, dave)

	anon := openSession(t, ts)
	sendFrame(t, anon, protocol.TypeKeyRequest, 1, protocol.KeyRequest{ID: bob.id(), AccessProof: proofOf(bobKey)})
	if got := expectBody[protocol.KeyResponse](t, anon, protocol.TypeKeyResponse, 1); !bytes.Equal(got.Bundle, bob.bundle) {
		t.Fatal("anonymous KeyRequest returned another bundle")
	}
	sendFrame(t, anon, protocol.TypePrekeyRequest, 2, protocol.PrekeyRequest{ID: bob.id(), AccessProof: proofOf(bobKey)})
	got := expectBody[protocol.PrekeyResponse](t, anon, protocol.TypePrekeyResponse, 2)
	if !bytes.Equal(got.Bundle, bob.bundle) || got.OneTimePrekey == nil {
		t.Fatal("anonymous PrekeyRequest returned no one-time prekey")
	}

	var answers [][]byte
	for i, probe := range []struct {
		typ  protocol.FrameType
		body any
	}{
		{protocol.TypeKeyRequest, protocol.KeyRequest{ID: bob.id(), AccessProof: randomProof()}},
		{protocol.TypeKeyRequest, protocol.KeyRequest{ID: strangers(1)[0], AccessProof: randomProof()}},
		{protocol.TypeKeyRequest, protocol.KeyRequest{ID: dave.id(), AccessProof: proofOf(bobKey)}},
		{protocol.TypePrekeyRequest, protocol.PrekeyRequest{ID: bob.id(), AccessProof: randomProof()}},
		{protocol.TypePrekeyRequest, protocol.PrekeyRequest{ID: strangers(1)[0], AccessProof: randomProof()}},
	} {
		id := uint64(10 + i)
		sendFrame(t, anon, probe.typ, id, probe.body)
		frame := expectError(t, anon, protocol.ErrCodeNotFound)
		if frame.ID != id {
			t.Fatalf("Error ID %d, want %d", frame.ID, id)
		}
		answers = append(answers, frame.Body)
	}
	for _, body := range answers[1:] {
		if !bytes.Equal(body, answers[0]) {
			t.Fatal("refused proofs and unknown IDs are answered differently")
		}
	}

	sendFrame(t, anon, protocol.TypeKeyRequest, 20, protocol.KeyRequest{ID: bob.id()})
	expectReject(t, anon, 20, protocol.ErrCodeUnauthorized)
	sealedSend(t, anon, 21, bob.id(), proofOf(bobKey), []byte("after lookup"))
	expectSendResult(t, anon, 21, protocol.SendAccepted)
	expectSealedDeliver(t, bobConn, []byte("after lookup"))
	register(t, anon, 22, alice.bundle, "")
	expectFatal(t, anon, protocol.ErrCodeBadRequest)

	locked := openSession(t, ts)
	sendFrame(t, locked, protocol.TypePrekeyRequest, 1, protocol.PrekeyRequest{ID: bob.id(), AccessProof: proofOf(bobKey)})
	expectBody[protocol.PrekeyResponse](t, locked, protocol.TypePrekeyResponse, 1)
	sendFrame(t, locked, protocol.TypeAuthBegin, 2, protocol.AuthBegin{ID: alice.id()})
	expectFatal(t, locked, protocol.ErrCodeBadRequest)

	identified := online(t, ts, alice)
	sendFrame(t, identified, protocol.TypeKeyRequest, 1, protocol.KeyRequest{ID: bob.id(), AccessProof: proofOf(bobKey)})
	expectFatal(t, identified, protocol.ErrCodeBadRequest)
	identified = login(t, ts, alice)
	sendFrame(t, identified, protocol.TypePrekeyRequest, 1, protocol.PrekeyRequest{ID: bob.id(), AccessProof: proofOf(bobKey)})
	expectFatal(t, identified, protocol.ErrCodeBadRequest)

	identified = login(t, ts, alice)
	sendFrame(t, identified, protocol.TypeKeyRequest, 2, protocol.KeyRequest{ID: bob.id()})
	expectBody[protocol.KeyResponse](t, identified, protocol.TypeKeyResponse, 2)
}

func TestAnonymousLookupRateLimits(t *testing.T) {
	clock := newTestClock()
	ts := startServer(t, serverOptions{
		config: func(c *Config) {
			fastFrames(c)
			c.Limits.PrekeyRequestsPerHour = 3
		},
		tweak: func(s *Server) {
			s.now = clock.now
			s.multiSendWait = time.Millisecond
			s.uploadBurst = 1000
		},
	})
	bob := newUser(t)
	_, bobKey := prekeyUser(t, ts, bob, 1)
	lookup := protocol.KeyRequest{ID: bob.id(), AccessProof: proofOf(bobKey)}

	perConnection := openSession(t, ts)
	for id := uint64(1); id <= 3; id++ {
		sendFrame(t, perConnection, protocol.TypeKeyRequest, id, lookup)
		expectBody[protocol.KeyResponse](t, perConnection, protocol.TypeKeyResponse, id)
	}
	sendFrame(t, perConnection, protocol.TypeKeyRequest, 4, lookup)
	expectReject(t, perConnection, 4, protocol.ErrCodeRateLimited)

	drained := openSession(t, ts)
	if r := ts.srv.lookupIP.reserve(loopback, AnonymousLookupsBurstPerIP, clock.now()); r == nil || !r.OK() {
		t.Fatal("cannot drain the address's lookup bucket")
	}
	sendFrame(t, drained, protocol.TypeKeyRequest, 1, lookup)
	expectReject(t, drained, 1, protocol.ErrCodeRateLimited)
	sendFrame(t, drained, protocol.TypeKeyRequest, 2, protocol.KeyRequest{ID: bob.id(), AccessProof: randomProof()})
	expectReject(t, drained, 2, protocol.ErrCodeNotFound)

	clock.advance(time.Hour)
	sendFrame(t, drained, protocol.TypePrekeyRequest, 3, protocol.PrekeyRequest{ID: bob.id(), AccessProof: proofOf(bobKey)})
	expectBody[protocol.PrekeyResponse](t, drained, protocol.TypePrekeyResponse, 3)

	junk := openSession(t, ts)
	sealedSendMulti(t, junk, 1, strangerEntries(SealedRefusalsBurst), []byte("junk"))
	expectMultiResult(t, junk, 1)
	sendFrame(t, junk, protocol.TypeKeyRequest, 2, protocol.KeyRequest{ID: bob.id(), AccessProof: randomProof()})
	expectReject(t, junk, 2, protocol.ErrCodeRateLimited)
	sendFrame(t, junk, protocol.TypeKeyRequest, 3, lookup)
	expectBody[protocol.KeyResponse](t, junk, protocol.TypeKeyResponse, 3)
}

func TestSealedQueueCap(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		fastFrames(c)
		c.Limits.MaxQueuedMessages = 4
		c.Limits.MaxQueuedSealedMessages = 2
	}})
	alice, bob := newUser(t), newUser(t)
	bobConn, bobKey := sealedUser(t, ts, bob)
	bobConn.Close(websocket.StatusNormalClosure, "")
	anon := openSession(t, ts)
	for id := uint64(1); id <= 2; id++ {
		sealedSend(t, anon, id, bob.id(), proofOf(bobKey), []byte("junk"))
		expectSendResult(t, anon, id, protocol.SendAccepted)
	}
	sealedSend(t, anon, 3, bob.id(), proofOf(bobKey), []byte("junk"))
	expectReject(t, anon, 3, protocol.ErrCodeQueueFull)

	aliceConn := online(t, ts, alice)
	sendAccepted(t, aliceConn, 1, bob.id(), "identified")
	sendAccepted(t, aliceConn, 2, bob.id(), "identified")
	sendMessage(t, aliceConn, 3, bob.id(), []byte("over the total"))
	expectReject(t, aliceConn, 3, protocol.ErrCodeQueueFull)
	if n := queuedCount(t, ts, bob); n != 4 {
		t.Fatalf("%d messages stored, want 4", n)
	}
	if got := ts.srv.queueLimits(); got.MaxSealedMessages != 2 || got.MaxSealedBytes != DefaultMaxQueuedBytes/2 {
		t.Fatalf("queue limits %+v", got)
	}
}

func TestRoundUpToHour(t *testing.T) {
	hour := time.Date(2026, 3, 1, 14, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ in, want time.Time }{
		{hour, hour},
		{hour.Add(time.Nanosecond), hour.Add(time.Hour)},
		{hour.Add(59 * time.Minute), hour.Add(time.Hour)},
		{hour.Add(-time.Second), hour},
	} {
		if got := roundUpToHour(tc.in); !got.Equal(tc.want) {
			t.Errorf("roundUpToHour(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
	offset := time.FixedZone("half", 30*60)
	if got := roundUpToHour(hour.Add(10 * time.Minute).In(offset)); got.Unix()%3600 != 0 {
		t.Fatalf("rounding depends on the zone: %v", got)
	}
}

func TestQueueExpiryRoundedForBothKinds(t *testing.T) {
	clock := newTestClock()
	clock.alignToHour()
	clock.advance(10 * time.Minute)
	ts := startServer(t, serverOptions{
		config: func(c *Config) {
			fastFrames(c)
			c.UndeliveredTTL = DurationOf(time.Hour)
		},
		tweak: func(s *Server) { s.now = clock.now },
	})
	alice, bob := newUser(t), newUser(t)
	bobConn, bobKey := sealedUser(t, ts, bob)
	bobConn.Close(websocket.StatusNormalClosure, "")
	aliceConn := online(t, ts, alice)
	sendAccepted(t, aliceConn, 1, bob.id(), "identified")
	anon := openSession(t, ts)
	sealedSend(t, anon, 1, bob.id(), proofOf(bobKey), []byte("sealed"))
	expectSendResult(t, anon, 1, protocol.SendAccepted)

	stored := clock.now()
	expiry := stored.Truncate(time.Hour).Add(2 * time.Hour)
	for _, tc := range []struct {
		at   time.Time
		want int
	}{
		{stored.Add(time.Hour), 2},
		{expiry.Add(-time.Second), 2},
		{expiry, 0},
	} {
		msgs, err := ts.srv.db.QueuedFor(context.Background(), bob.ident.ID(), 0, 10, tc.at)
		if err != nil {
			t.Fatal(err)
		}
		if len(msgs) != tc.want {
			t.Fatalf("at %v: %d messages, want %d (expiry rounded up to %v)", tc.at, len(msgs), tc.want, expiry)
		}
	}
}

// TestLargestSealedEnvelopeFitsDefaults sends a sealed envelope of the
// largest size package sealed produces through a relay with the default
// message size limit.
func TestLargestSealedEnvelopeFitsDefaults(t *testing.T) {
	if DefaultMaxMessageSize < sealed.MaxEnvelopeSize || DefaultMaxMessageSize > MaxMessageSize {
		t.Fatalf("default max_message_size %d does not hold the largest sealed envelope (%d bytes)", DefaultMaxMessageSize, sealed.MaxEnvelopeSize)
	}
	ts := startServer(t, serverOptions{config: fastFrames})
	alice, bob := newUser(t), newUser(t)
	bobConn, bobKey := sealedUser(t, ts, bob)
	bundle, err := identity.ParseBundle(bob.bundle)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := sealed.Seal(alice.ident.ID(), bundle, bytes.Repeat([]byte{7}, 200_000))
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope) != sealed.MaxEnvelopeSize {
		t.Fatalf("envelope of %d bytes, want %d", len(envelope), sealed.MaxEnvelopeSize)
	}
	anon := openSession(t, ts)
	sealedSend(t, anon, 1, bob.id(), proofOf(bobKey), envelope)
	expectSendResult(t, anon, 1, protocol.SendAccepted)
	expectSealedDeliver(t, bobConn, envelope)
}
