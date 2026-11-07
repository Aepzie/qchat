package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/store/serverdb"
	"github.com/craguS/qchat/internal/transport"
)

// testUser is an identity with the bundle it registers.
type testUser struct {
	ident  *identity.Identity
	bundle []byte
}

func newUser(t *testing.T) testUser {
	t.Helper()
	ident, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ident.Destroy)
	return testUser{ident: ident, bundle: userBundle(t, ident, 1)}
}

func userBundle(t *testing.T, ident *identity.Identity, serial uint64) []byte {
	t.Helper()
	bundle, err := ident.Bundle(serial, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func (u testUser) id() []byte {
	id := u.ident.ID()
	return id[:]
}

func openMode(c *Config) { c.Registration = RegistrationOpen }

// expectBody reads the next frame and decodes it as the wanted type.
func expectBody[T any](t *testing.T, conn *websocket.Conn, want protocol.FrameType, id uint64) T {
	t.Helper()
	frame := readFrame(t, conn)
	if frame.Type == protocol.TypeError {
		body, _ := protocol.DecodeBody[protocol.ErrorBody](frame, protocol.TypeError)
		t.Fatalf("got Error %v, want %v", body.Code, want)
	}
	body, err := protocol.DecodeBody[T](frame, want)
	if err != nil {
		t.Fatalf("expected %v: %v", want, err)
	}
	if frame.ID != id {
		t.Fatalf("%v ID %d, want %d", want, frame.ID, id)
	}
	return body
}

// expectReject reads a non-fatal Error frame for request id and checks that
// the session is still usable.
func expectReject(t *testing.T, conn *websocket.Conn, id uint64, code protocol.ErrorCode) {
	t.Helper()
	frame := expectError(t, conn, code)
	if frame.ID != id {
		t.Fatalf("Error ID %d, want %d", frame.ID, id)
	}
	expectAlive(t, conn)
}

// expectFatal reads a fatal Error frame and the close that follows it.
func expectFatal(t *testing.T, conn *websocket.Conn, code protocol.ErrorCode) {
	t.Helper()
	expectError(t, conn, code)
	expectClose(t, conn, websocket.StatusPolicyViolation)
}

func expectAlive(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	sendFrame(t, conn, protocol.TypePing, 999, protocol.Ping{Nonce: 4242})
	pong := expectBody[protocol.Pong](t, conn, protocol.TypePong, 999)
	if pong.Nonce != 4242 {
		t.Fatalf("Pong nonce %d", pong.Nonce)
	}
}

// openSession dials and completes the handshake.
func openSession(t *testing.T, ts *testServer) *websocket.Conn {
	t.Helper()
	conn := dial(t, ts)
	handshake(t, conn, 1)
	return conn
}

func register(t *testing.T, conn *websocket.Conn, id uint64, bundle []byte, invite string) {
	t.Helper()
	sendFrame(t, conn, protocol.TypeRegister, id, protocol.Register{Bundle: bundle, Invite: invite})
}

func mustRegister(t *testing.T, conn *websocket.Conn, bundle []byte, invite string) {
	t.Helper()
	register(t, conn, 10, bundle, invite)
	expectBody[protocol.Registered](t, conn, protocol.TypeRegistered, 10)
}

// beginAuth sends AuthBegin and returns the challenge nonce.
func beginAuth(t *testing.T, conn *websocket.Conn, id []byte) []byte {
	t.Helper()
	sendFrame(t, conn, protocol.TypeAuthBegin, 20, protocol.AuthBegin{ID: id})
	return expectBody[protocol.AuthChallenge](t, conn, protocol.TypeAuthChallenge, 20).Nonce
}

func signAuth(t *testing.T, ident *identity.Identity, fp transport.Fingerprint, nonce []byte) []byte {
	t.Helper()
	sig, err := ident.SignAuth(fp, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func authenticate(t *testing.T, ts *testServer, conn *websocket.Conn, u testUser) {
	t.Helper()
	nonce := beginAuth(t, conn, u.id())
	sendFrame(t, conn, protocol.TypeAuthProof, 21, protocol.AuthProof{Sig: signAuth(t, u.ident, ts.pin, nonce)})
	expectBody[protocol.AuthOK](t, conn, protocol.TypeAuthOK, 21)
}

// online registers u and returns an authenticated session for it.
func online(t *testing.T, ts *testServer, u testUser) *websocket.Conn {
	t.Helper()
	conn := openSession(t, ts)
	mustRegister(t, conn, u.bundle, "")
	authenticate(t, ts, conn, u)
	return conn
}

func createInvite(t *testing.T, ts *testServer, uses int) string {
	t.Helper()
	db, err := serverdb.Open(ts.cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	code, err := db.CreateInvite(context.Background(), time.Hour, uses)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestRegisterOpen(t *testing.T) {
	ts := startServer(t, serverOptions{config: openMode})
	alice := newUser(t)
	conn := openSession(t, ts)

	register(t, conn, 5, alice.bundle, "")
	expectBody[protocol.Registered](t, conn, protocol.TypeRegistered, 5)
	register(t, conn, 6, alice.bundle, "")
	expectBody[protocol.Registered](t, conn, protocol.TypeRegistered, 6)

	register(t, conn, 7, userBundle(t, alice.ident, 1), "")
	expectReject(t, conn, 7, protocol.ErrCodeConflict)

	register(t, conn, 8, userBundle(t, alice.ident, 2), "")
	expectBody[protocol.Registered](t, conn, protocol.TypeRegistered, 8)
	register(t, conn, 9, alice.bundle, "")
	expectReject(t, conn, 9, protocol.ErrCodeConflict)

	tampered := bytes.Clone(alice.bundle)
	tampered[len(tampered)-1] ^= 1
	register(t, conn, 11, tampered, "")
	expectReject(t, conn, 11, protocol.ErrCodeBadRequest)
	register(t, conn, 12, []byte("not a bundle"), "")
	expectReject(t, conn, 12, protocol.ErrCodeBadRequest)
}

func TestRegisterInvite(t *testing.T) {
	ts := startServer(t, serverOptions{})
	code := createInvite(t, ts, 1)
	alice, bob := newUser(t), newUser(t)
	conn := openSession(t, ts)

	register(t, conn, 5, alice.bundle, "")
	expectReject(t, conn, 5, protocol.ErrCodeRegistrationDenied)
	register(t, conn, 6, alice.bundle, "AAAAAAAAAAAAAAAAAAAAAAAAAA")
	expectReject(t, conn, 6, protocol.ErrCodeRegistrationDenied)

	register(t, conn, 7, alice.bundle, code)
	expectBody[protocol.Registered](t, conn, protocol.TypeRegistered, 7)

	other := openSession(t, ts)
	register(t, other, 8, bob.bundle, code)
	expectReject(t, other, 8, protocol.ErrCodeRegistrationDenied)

	register(t, other, 9, alice.bundle, "")
	expectBody[protocol.Registered](t, other, protocol.TypeRegistered, 9)
	register(t, other, 10, userBundle(t, alice.ident, 2), "")
	expectBody[protocol.Registered](t, other, protocol.TypeRegistered, 10)

	second := createInvite(t, ts, 1)
	register(t, other, 11, bob.bundle, strings.ToLower(second))
	expectBody[protocol.Registered](t, other, protocol.TypeRegistered, 11)
}

func TestAuthenticateAndKeyRequest(t *testing.T) {
	ts := startServer(t, serverOptions{config: openMode})
	alice, bob := newUser(t), newUser(t)
	conn := openSession(t, ts)
	mustRegister(t, conn, alice.bundle, "")
	setup := openSession(t, ts)
	mustRegister(t, setup, bob.bundle, "")

	sendFrame(t, conn, protocol.TypeKeyRequest, 30, protocol.KeyRequest{ID: bob.id()})
	expectReject(t, conn, 30, protocol.ErrCodeUnauthorized)
	sendFrame(t, conn, protocol.TypeSend, 31, protocol.Send{To: bob.id(), Payload: []byte{1}})
	expectReject(t, conn, 31, protocol.ErrCodeUnauthorized)

	authenticate(t, ts, conn, alice)

	sendFrame(t, conn, protocol.TypeKeyRequest, 32, protocol.KeyRequest{ID: bob.id()})
	resp := expectBody[protocol.KeyResponse](t, conn, protocol.TypeKeyResponse, 32)
	if !bytes.Equal(resp.Bundle, bob.bundle) {
		t.Fatal("KeyResponse does not return the registered bundle")
	}
	if _, err := identity.ParseBundleForID(resp.Bundle, bob.ident.ID()); err != nil {
		t.Fatalf("KeyResponse bundle does not verify: %v", err)
	}
	unknown := make([]byte, protocol.IDSize)
	sendFrame(t, conn, protocol.TypeKeyRequest, 33, protocol.KeyRequest{ID: unknown})
	expectReject(t, conn, 33, protocol.ErrCodeNotFound)

	sendFrame(t, conn, protocol.TypeAuthBegin, 34, protocol.AuthBegin{ID: bob.id()})
	expectFatal(t, conn, protocol.ErrCodeBadRequest)
}

func TestAuthFailures(t *testing.T) {
	ts := startServer(t, serverOptions{config: openMode})
	alice, mallory := newUser(t), newUser(t)
	setup := openSession(t, ts)
	mustRegister(t, setup, alice.bundle, "")
	mustRegister(t, setup, mallory.bundle, "")
	otherFP := ts.pin
	otherFP[0] ^= 1

	t.Run("unknown ID", func(t *testing.T) {
		conn := openSession(t, ts)
		sendFrame(t, conn, protocol.TypeAuthBegin, 20, protocol.AuthBegin{ID: newUser(t).id()})
		expectReject(t, conn, 20, protocol.ErrCodeNotFound)
		authenticate(t, ts, conn, alice)
	})
	t.Run("no challenge", func(t *testing.T) {
		conn := openSession(t, ts)
		sendFrame(t, conn, protocol.TypeAuthProof, 21, protocol.AuthProof{Sig: []byte{1, 2, 3}})
		expectFatal(t, conn, protocol.ErrCodeUnauthorized)
	})
	cases := []struct {
		name string
		sig  func(nonce []byte) []byte
	}{
		{"wrong key", func(nonce []byte) []byte { return signAuth(t, mallory.ident, ts.pin, nonce) }},
		{"wrong nonce", func(nonce []byte) []byte {
			other := bytes.Clone(nonce)
			other[0] ^= 1
			return signAuth(t, alice.ident, ts.pin, other)
		}},
		{"wrong server", func(nonce []byte) []byte { return signAuth(t, alice.ident, otherFP, nonce) }},
		{"garbage", func([]byte) []byte { return []byte("signature") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := openSession(t, ts)
			nonce := beginAuth(t, conn, alice.id())
			sendFrame(t, conn, protocol.TypeAuthProof, 21, protocol.AuthProof{Sig: tc.sig(nonce)})
			expectFatal(t, conn, protocol.ErrCodeUnauthorized)
		})
	}
	t.Run("replaced challenge", func(t *testing.T) {
		conn := openSession(t, ts)
		first := beginAuth(t, conn, alice.id())
		beginAuth(t, conn, alice.id())
		sendFrame(t, conn, protocol.TypeAuthProof, 21, protocol.AuthProof{Sig: signAuth(t, alice.ident, ts.pin, first)})
		expectFatal(t, conn, protocol.ErrCodeUnauthorized)
	})
	t.Run("proof reused", func(t *testing.T) {
		conn := openSession(t, ts)
		nonce := beginAuth(t, conn, alice.id())
		sig := signAuth(t, alice.ident, ts.pin, nonce)
		sendFrame(t, conn, protocol.TypeAuthProof, 21, protocol.AuthProof{Sig: sig})
		expectBody[protocol.AuthOK](t, conn, protocol.TypeAuthOK, 21)
		sendFrame(t, conn, protocol.TypeAuthProof, 22, protocol.AuthProof{Sig: sig})
		expectFatal(t, conn, protocol.ErrCodeBadRequest)

		replay := openSession(t, ts)
		beginAuth(t, replay, alice.id())
		sendFrame(t, replay, protocol.TypeAuthProof, 21, protocol.AuthProof{Sig: sig})
		expectFatal(t, replay, protocol.ErrCodeUnauthorized)
	})
}

func TestAuthChallengeExpires(t *testing.T) {
	ts := startServer(t, serverOptions{config: openMode, tweak: func(s *Server) { s.challengeTTL = 50 * time.Millisecond }})
	alice := newUser(t)
	conn := openSession(t, ts)
	mustRegister(t, conn, alice.bundle, "")
	nonce := beginAuth(t, conn, alice.id())
	time.Sleep(100 * time.Millisecond)
	sendFrame(t, conn, protocol.TypeAuthProof, 21, protocol.AuthProof{Sig: signAuth(t, alice.ident, ts.pin, nonce)})
	expectFatal(t, conn, protocol.ErrCodeUnauthorized)
}

func TestAuthRateLimit(t *testing.T) {
	ts := startServer(t, serverOptions{config: openMode, tweak: func(s *Server) { s.authBurst = authBurst }})
	alice := newUser(t)
	conn := openSession(t, ts)
	for i := range uint64(authBurst) {
		register(t, conn, 40+i, alice.bundle, "")
		expectBody[protocol.Registered](t, conn, protocol.TypeRegistered, 40+i)
	}
	register(t, conn, 50, alice.bundle, "")
	expectReject(t, conn, 50, protocol.ErrCodeRateLimited)
	sendFrame(t, conn, protocol.TypeAuthBegin, 51, protocol.AuthBegin{ID: alice.id()})
	expectReject(t, conn, 51, protocol.ErrCodeRateLimited)
}

func sendMessage(t *testing.T, conn *websocket.Conn, id uint64, to []byte, payload []byte) {
	t.Helper()
	sendFrame(t, conn, protocol.TypeSend, id, protocol.Send{To: to, Payload: payload})
}

func expectDeliver(t *testing.T, conn *websocket.Conn, from []byte, payload []byte) {
	t.Helper()
	deliver := expectBody[protocol.Deliver](t, conn, protocol.TypeDeliver, 0)
	if !bytes.Equal(deliver.From, from) || !bytes.Equal(deliver.Payload, payload) {
		t.Fatalf("Deliver from %x payload %q, want %x and %q", deliver.From, deliver.Payload, from, payload)
	}
}

func expectSendResult(t *testing.T, conn *websocket.Conn, id uint64, want protocol.SendStatus) {
	t.Helper()
	result := expectBody[protocol.SendResult](t, conn, protocol.TypeSendResult, id)
	if result.Status != want {
		t.Fatalf("SendResult %v, want %v", result.Status, want)
	}
}

func TestSendAndDeliver(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		c.Registration = RegistrationOpen
		c.Limits.MaxMessageSize = MinMessageSize
	}})
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	aliceConn := online(t, ts, alice)
	bobConn := online(t, ts, bob)
	bobSecond := openSession(t, ts)
	authenticate(t, ts, bobSecond, bob)
	setup := openSession(t, ts)
	mustRegister(t, setup, carol.bundle, "")

	payload := []byte("ciphertext for bob")
	sendMessage(t, aliceConn, 60, bob.id(), payload)
	expectSendResult(t, aliceConn, 60, protocol.SendDelivered)
	expectDeliver(t, bobConn, alice.id(), payload)
	expectDeliver(t, bobSecond, alice.id(), payload)

	sendMessage(t, bobConn, 61, alice.id(), []byte("reply"))
	expectSendResult(t, bobConn, 61, protocol.SendDelivered)
	expectDeliver(t, aliceConn, bob.id(), []byte("reply"))

	sendMessage(t, aliceConn, 62, carol.id(), []byte("offline"))
	expectSendResult(t, aliceConn, 62, protocol.SendRecipientOffline)

	sendMessage(t, aliceConn, 63, newUser(t).id(), []byte("nobody"))
	expectReject(t, aliceConn, 63, protocol.ErrCodeNotFound)

	sendMessage(t, aliceConn, 64, alice.id(), []byte("self"))
	expectReject(t, aliceConn, 64, protocol.ErrCodeBadRequest)

	sendMessage(t, aliceConn, 65, bob.id(), make([]byte, MinMessageSize+1))
	expectReject(t, aliceConn, 65, protocol.ErrCodeTooLarge)
	sendMessage(t, aliceConn, 66, bob.id(), make([]byte, MinMessageSize))
	expectSendResult(t, aliceConn, 66, protocol.SendDelivered)
	expectDeliver(t, bobConn, alice.id(), make([]byte, MinMessageSize))
	expectDeliver(t, bobSecond, alice.id(), make([]byte, MinMessageSize))

	bobConn.Close(websocket.StatusNormalClosure, "")
	bobSecond.Close(websocket.StatusNormalClosure, "")
	waitFor(t, "bob to go offline", func() bool {
		ts.srv.routesMu.Lock()
		defer ts.srv.routesMu.Unlock()
		return len(ts.srv.routes) == 1
	})
	sendMessage(t, aliceConn, 67, bob.id(), []byte("gone"))
	expectSendResult(t, aliceConn, 67, protocol.SendRecipientOffline)
}

func TestDeliveryDoesNotBlock(t *testing.T) {
	cert, _ := testIdentity(t)
	cfg := DefaultConfig()
	srv, err := New(cfg, cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	var to identity.ID
	to[0] = 7
	full := &session{id: to, out: make(chan []byte, 1), stopping: make(chan struct{})}
	stopped := &session{id: to, out: make(chan []byte, 1), stopping: make(chan struct{})}
	close(stopped.stopping)
	srv.route(full)
	srv.route(stopped)

	if !srv.deliver(to, []byte{1}) {
		t.Fatal("delivery to a session with room was not accepted")
	}
	if srv.deliver(to, []byte{2}) {
		t.Fatal("delivery to full and stopping sessions was accepted")
	}
	if got := <-full.out; !bytes.Equal(got, []byte{1}) {
		t.Fatalf("queued frame %x", got)
	}
	full.authenticated, stopped.authenticated = true, true
	srv.unroute(full)
	srv.unroute(stopped)
	if len(srv.routes) != 0 {
		t.Fatalf("routes not cleaned up: %d", len(srv.routes))
	}
}

func TestServeFailsWithoutDatabaseDirectory(t *testing.T) {
	cert, _ := testIdentity(t)
	cfg := DefaultConfig()
	cfg.Database = filepath.Join(t.TempDir(), "missing", "qchat.db")
	srv, err := New(cfg, cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Serve(context.Background(), ln); err == nil {
		t.Fatal("Serve succeeded without a database directory")
	}
}

// TestRelayLogsContainNoClientData drives registration, authentication and
// messaging, including failures, and checks that the debug log mentions no
// ID, payload, nonce or invite.
func TestRelayLogsContainNoClientData(t *testing.T) {
	logs := &syncBuffer{}
	ts := startServer(t, serverOptions{logs: logs})
	code := createInvite(t, ts, 2)
	alice, bob := newUser(t), newUser(t)
	payload := []byte("top secret payload")

	aliceConn := openSession(t, ts)
	register(t, aliceConn, 1, alice.bundle, "")
	expectReject(t, aliceConn, 1, protocol.ErrCodeRegistrationDenied)
	mustRegister(t, aliceConn, alice.bundle, code)
	authenticate(t, ts, aliceConn, alice)
	bobConn := openSession(t, ts)
	mustRegister(t, bobConn, bob.bundle, code)
	nonce := beginAuth(t, bobConn, bob.id())
	sendFrame(t, bobConn, protocol.TypeAuthProof, 21, protocol.AuthProof{Sig: signAuth(t, bob.ident, ts.pin, nonce)})
	expectBody[protocol.AuthOK](t, bobConn, protocol.TypeAuthOK, 21)

	sendMessage(t, aliceConn, 2, bob.id(), payload)
	expectSendResult(t, aliceConn, 2, protocol.SendDelivered)
	expectDeliver(t, bobConn, alice.id(), payload)
	sendMessage(t, aliceConn, 3, alice.id(), payload)
	expectReject(t, aliceConn, 3, protocol.ErrCodeBadRequest)

	failing := openSession(t, ts)
	beginAuth(t, failing, alice.id())
	sendFrame(t, failing, protocol.TypeAuthProof, 21, protocol.AuthProof{Sig: payload})
	expectFatal(t, failing, protocol.ErrCodeUnauthorized)
	aliceConn.Close(websocket.StatusNormalClosure, "")
	bobConn.Close(websocket.StatusNormalClosure, "")
	if err := ts.stop(t); err != nil {
		t.Fatal(err)
	}

	output := logs.String()
	if !strings.Contains(output, "reason=unauthorized") {
		t.Errorf("log lacks the unauthorized close reason:\n%s", output)
	}
	var forbidden []string
	for _, u := range []testUser{alice, bob} {
		id := u.ident.ID()
		forbidden = append(forbidden, hex.EncodeToString(id[:]), id.String(), id.ShortString(), hex.EncodeToString(u.bundle[:16]))
	}
	forbidden = append(forbidden, string(payload), hex.EncodeToString(payload), hex.EncodeToString(nonce), code, strings.ReplaceAll(code, "-", ""))
	for _, s := range forbidden {
		if s != "" && strings.Contains(output, s) {
			t.Errorf("log contains %q:\n%s", s, output)
		}
	}
}
