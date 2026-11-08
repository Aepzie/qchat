package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Aepzie/qchat/internal/protocol"
	"github.com/Aepzie/qchat/internal/transport"
)

var (
	identityOnce sync.Once
	identityCert tls.Certificate
	identityPin  transport.Fingerprint
	identityErr  error
)

// testIdentity returns one server identity shared by all tests.
func testIdentity(t *testing.T) (tls.Certificate, transport.Fingerprint) {
	t.Helper()
	identityOnce.Do(func() {
		certPEM, keyPEM, err := transport.GenerateServerIdentity([]string{"127.0.0.1", "::1", "localhost"})
		if err != nil {
			identityErr = err
			return
		}
		identityCert, identityErr = tls.X509KeyPair(certPEM, keyPEM)
		if identityErr == nil {
			identityPin, identityErr = transport.FingerprintOfTLS(identityCert)
		}
	})
	if identityErr != nil {
		t.Fatal(identityErr)
	}
	return identityCert, identityPin
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type testServer struct {
	srv    *Server
	addr   string
	pin    transport.Fingerprint
	cfg    Config
	cancel context.CancelFunc
	done   chan error
}

type serverOptions struct {
	listen string
	logs   *syncBuffer
	config func(*Config)
	tweak  func(*Server)
}

func startServer(t *testing.T, opts serverOptions) *testServer {
	t.Helper()
	cert, pin := testIdentity(t)
	cfg := DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Limits.HandshakeTimeout = DurationOf(5 * time.Second)
	cfg.Database = filepath.Join(t.TempDir(), "qchat.db")
	if opts.config != nil {
		opts.config(&cfg)
	}
	logs := opts.logs
	if logs == nil {
		logs = &syncBuffer{}
	}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := New(cfg, cert, logger)
	if err != nil {
		t.Fatal(err)
	}
	srv.authBurst = 1000
	if opts.tweak != nil {
		opts.tweak(srv)
	}
	listen := opts.listen
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ts := &testServer{srv: srv, addr: ln.Addr().String(), pin: pin, cfg: cfg, cancel: cancel, done: make(chan error, 1)}
	go func() { ts.done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() { ts.stop(t) })
	waitFor(t, "server to open its database", func() bool { return srv.Addr() != nil })
	return ts
}

// stop shuts the server down and waits for Serve to return. It may be
// called more than once.
func (ts *testServer) stop(t *testing.T) error {
	t.Helper()
	ts.cancel()
	select {
	case err, ok := <-ts.done:
		if ok {
			close(ts.done)
		}
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("Serve did not return after cancellation")
		return nil
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// bindings maps every connection opened by dial to its TLS channel binding.
var bindings sync.Map

func dial(t *testing.T, ts *testServer) *websocket.Conn {
	t.Helper()
	conn, state, err := transport.DialWithState(testContext(t), ts.addr, ts.pin, transport.DialOptions{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	binding, err := transport.AuthBinding(&state)
	if err != nil {
		t.Fatalf("AuthBinding: %v", err)
	}
	bindings.Store(conn, binding)
	t.Cleanup(func() {
		bindings.Delete(conn)
		conn.CloseNow()
	})
	return conn
}

// bindingOf returns the client side channel binding of a connection opened
// by dial.
func bindingOf(t *testing.T, conn *websocket.Conn) []byte {
	t.Helper()
	binding, ok := bindings.Load(conn)
	if !ok {
		t.Fatal("connection was not opened by dial")
	}
	return binding.([]byte)
}

func sendFrame[T any](t *testing.T, conn *websocket.Conn, frameType protocol.FrameType, id uint64, body T) {
	t.Helper()
	frame, err := protocol.NewFrame(frameType, id, body)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := protocol.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	sendRaw(t, conn, encoded)
}

func sendRaw(t *testing.T, conn *websocket.Conn, msg []byte) {
	t.Helper()
	if err := conn.Write(testContext(t), websocket.MessageBinary, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readFrame(t *testing.T, conn *websocket.Conn) protocol.Frame {
	t.Helper()
	msgType, msg, err := conn.Read(testContext(t))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if msgType != websocket.MessageBinary {
		t.Fatalf("server sent message type %v", msgType)
	}
	frame, err := protocol.Decode(msg)
	if err != nil {
		t.Fatalf("decode server frame: %v", err)
	}
	return frame
}

func handshake(t *testing.T, conn *websocket.Conn, id uint64) protocol.Welcome {
	t.Helper()
	sendFrame(t, conn, protocol.TypeHello, id, protocol.ClientHello())
	frame := readFrame(t, conn)
	if frame.ID != id {
		t.Fatalf("Welcome ID %d, want %d", frame.ID, id)
	}
	welcome, err := protocol.DecodeBody[protocol.Welcome](frame, protocol.TypeWelcome)
	if err != nil {
		t.Fatalf("expected Welcome: %v", err)
	}
	return welcome
}

func expectError(t *testing.T, conn *websocket.Conn, want protocol.ErrorCode) protocol.Frame {
	t.Helper()
	frame := readFrame(t, conn)
	body, err := protocol.DecodeBody[protocol.ErrorBody](frame, protocol.TypeError)
	if err != nil {
		t.Fatalf("expected Error frame, got %v: %v", frame.Type, err)
	}
	if body.Code != want {
		t.Fatalf("error code %v, want %v", body.Code, want)
	}
	if body.Message != errorMessages[want] {
		t.Fatalf("error message %q, want %q", body.Message, errorMessages[want])
	}
	return frame
}

func expectClose(t *testing.T, conn *websocket.Conn, want websocket.StatusCode) {
	t.Helper()
	_, _, err := conn.Read(testContext(t))
	if err == nil {
		t.Fatal("expected the connection to close, got a message")
	}
	if got := websocket.CloseStatus(err); got != want {
		t.Fatalf("close status %v (err %v), want %v", got, err, want)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNewRejectsInvalidInput(t *testing.T) {
	cert, _ := testIdentity(t)
	bad := DefaultConfig()
	bad.Limits.Burst = 0
	if _, err := New(bad, cert, nil); err == nil {
		t.Error("New accepted an invalid config")
	}
	if _, err := New(DefaultConfig(), tls.Certificate{}, nil); err == nil {
		t.Error("New accepted an empty certificate")
	}
	srv, err := New(DefaultConfig(), cert, nil)
	if err != nil {
		t.Fatalf("New with nil logger: %v", err)
	}
	if srv.Addr() != nil {
		t.Error("Addr is set before Serve")
	}
}

func TestHelloWelcomePingPong(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		c.Limits.MaxFrameSize = 4096
		c.Limits.PingInterval = DurationOf(45 * time.Second)
	}})
	conn := dial(t, ts)

	welcome := handshake(t, conn, 7)
	want := protocol.Welcome{Version: protocol.Version, MaxFrameSize: 4096, PingInterval: 45}
	if welcome != want {
		t.Fatalf("Welcome = %+v, want %+v", welcome, want)
	}

	for _, ping := range []struct {
		id    uint64
		nonce uint64
	}{{42, 0xdeadbeef}, {0, 0}, {1<<64 - 1, 1<<64 - 1}, {42, 1}} {
		sendFrame(t, conn, protocol.TypePing, ping.id, protocol.Ping{Nonce: ping.nonce})
		frame := readFrame(t, conn)
		pong, err := protocol.DecodeBody[protocol.Pong](frame, protocol.TypePong)
		if err != nil {
			t.Fatalf("expected Pong: %v", err)
		}
		if frame.ID != ping.id || pong.Nonce != ping.nonce {
			t.Fatalf("Pong ID %d nonce %d, want %d and %d", frame.ID, pong.Nonce, ping.id, ping.nonce)
		}
	}

	if got := ts.srv.Stats().ActiveSessions; got != 1 {
		t.Fatalf("ActiveSessions = %d, want 1", got)
	}
	if addr := ts.srv.Addr(); addr == nil || addr.String() != ts.addr {
		t.Fatalf("Addr() = %v, want %s", addr, ts.addr)
	}
	conn.Close(websocket.StatusNormalClosure, "")
	waitFor(t, "session to end", func() bool {
		stats := ts.srv.Stats()
		return stats.Connections == 0 && stats.ActiveSessions == 0
	})
	if stats := ts.srv.Stats(); stats.ActiveSessions != 0 || stats.TotalSessions != 1 {
		t.Fatalf("stats after close = %+v", stats)
	}
}

func TestUnsupportedVersion(t *testing.T) {
	ts := startServer(t, serverOptions{})

	t.Run("hello range", func(t *testing.T) {
		conn := dial(t, ts)
		sendFrame(t, conn, protocol.TypeHello, 3, protocol.Hello{MinVersion: 2, MaxVersion: 9})
		frame := expectError(t, conn, protocol.ErrCodeUnsupportedVersion)
		if frame.ID != 3 {
			t.Fatalf("Error ID %d, want 3", frame.ID)
		}
		expectClose(t, conn, websocket.StatusPolicyViolation)
	})

	t.Run("frame version", func(t *testing.T) {
		conn := dial(t, ts)
		sendRaw(t, conn, []byte{0xa2, 0x01, 0x09, 0x02, 0x01})
		expectError(t, conn, protocol.ErrCodeUnsupportedVersion)
		expectClose(t, conn, websocket.StatusPolicyViolation)
	})
}

func TestBadRequests(t *testing.T) {
	ts := startServer(t, serverOptions{})
	hello := func(t *testing.T, conn *websocket.Conn) { handshake(t, conn, 1) }
	none := func(*testing.T, *websocket.Conn) {}

	cases := []struct {
		name   string
		before func(*testing.T, *websocket.Conn)
		send   func(*testing.T, *websocket.Conn)
	}{
		{"garbage", none, func(t *testing.T, c *websocket.Conn) { sendRaw(t, c, []byte{0xff, 0x00, 0x13, 0x37}) }},
		{"empty message", none, func(t *testing.T, c *websocket.Conn) { sendRaw(t, c, nil) }},
		{"unknown type", none, func(t *testing.T, c *websocket.Conn) { sendRaw(t, c, []byte{0xa2, 0x01, 0x01, 0x02, 0x18, 0x63}) }},
		{"ping before hello", none, func(t *testing.T, c *websocket.Conn) {
			sendFrame(t, c, protocol.TypePing, 1, protocol.Ping{Nonce: 1})
		}},
		{"inverted hello range", none, func(t *testing.T, c *websocket.Conn) {
			sendRaw(t, c, []byte{0xa3, 0x01, 0x01, 0x02, 0x01, 0x04, 0x45, 0xa2, 0x01, 0x02, 0x02, 0x01})
		}},
		{"garbage after hello", hello, func(t *testing.T, c *websocket.Conn) { sendRaw(t, c, []byte("not cbor")) }},
		{"second hello", hello, func(t *testing.T, c *websocket.Conn) {
			sendFrame(t, c, protocol.TypeHello, 2, protocol.ClientHello())
		}},
		{"welcome from client", hello, func(t *testing.T, c *websocket.Conn) {
			sendFrame(t, c, protocol.TypeWelcome, 2, protocol.Welcome{Version: 1, MaxFrameSize: 1024, PingInterval: 1})
		}},
		{"pong from client", hello, func(t *testing.T, c *websocket.Conn) {
			sendFrame(t, c, protocol.TypePong, 2, protocol.Pong{Nonce: 5})
		}},
		{"error from client", hello, func(t *testing.T, c *websocket.Conn) {
			sendFrame(t, c, protocol.TypeError, 2, protocol.ErrorBody{Code: protocol.ErrCodeInternal, Message: "x"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := dial(t, ts)
			tc.before(t, conn)
			tc.send(t, conn)
			expectError(t, conn, protocol.ErrCodeBadRequest)
			expectClose(t, conn, websocket.StatusPolicyViolation)
		})
	}
}

func TestTextMessageClosesSession(t *testing.T) {
	ts := startServer(t, serverOptions{})
	for _, afterHello := range []bool{false, true} {
		conn := dial(t, ts)
		if afterHello {
			handshake(t, conn, 1)
		}
		if err := conn.Write(testContext(t), websocket.MessageText, []byte("hello")); err != nil {
			t.Fatal(err)
		}
		expectClose(t, conn, websocket.StatusUnsupportedData)
	}
}

func TestOversizedMessage(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) { c.Limits.MaxFrameSize = 1024 }})
	conn := dial(t, ts)
	handshake(t, conn, 1)
	sendRaw(t, conn, make([]byte, 1025))
	expectClose(t, conn, websocket.StatusMessageTooBig)
}

func TestHandshakeTimeout(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		c.Limits.HandshakeTimeout = DurationOf(200 * time.Millisecond)
	}})
	conn := dial(t, ts)
	start := time.Now()
	expectClose(t, conn, websocket.StatusPolicyViolation)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("handshake timeout took %v", elapsed)
	}
}

func TestIdleTimeout(t *testing.T) {
	ts := startServer(t, serverOptions{tweak: func(s *Server) { s.idleTimeout = 400 * time.Millisecond }})
	conn := dial(t, ts)
	handshake(t, conn, 1)
	for i := range 4 {
		time.Sleep(150 * time.Millisecond)
		sendFrame(t, conn, protocol.TypePing, uint64(i), protocol.Ping{Nonce: uint64(i)})
		if frame := readFrame(t, conn); frame.Type != protocol.TypePong {
			t.Fatalf("got %v, want Pong", frame.Type)
		}
	}
	expectClose(t, conn, websocket.StatusPolicyViolation)
}

func TestRateLimit(t *testing.T) {
	const burst = 3
	ts := startServer(t, serverOptions{config: func(c *Config) {
		c.Limits.FramesPerSecond = 0.5
		c.Limits.Burst = burst
	}})
	conn := dial(t, ts)
	handshake(t, conn, 1)
	for i := range 10 {
		frame, err := protocol.NewFrame(protocol.TypePing, uint64(i), protocol.Ping{Nonce: uint64(i)})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := protocol.Encode(frame)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Write(testContext(t), websocket.MessageBinary, encoded); err != nil {
			break
		}
	}
	pongs := 0
	for {
		frame := readFrame(t, conn)
		if frame.Type == protocol.TypePong {
			pongs++
			continue
		}
		body, err := protocol.DecodeBody[protocol.ErrorBody](frame, protocol.TypeError)
		if err != nil {
			t.Fatalf("expected Pong or Error, got %v", frame.Type)
		}
		if body.Code != protocol.ErrCodeRateLimited {
			t.Fatalf("error code %v, want RateLimited", body.Code)
		}
		break
	}
	if pongs >= burst {
		t.Fatalf("%d pongs before rate limiting; the Hello also spends a token, so want fewer than %d", pongs, burst)
	}
	expectClose(t, conn, websocket.StatusPolicyViolation)
}

func TestPerIPLimit(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		c.Limits.MaxConnections = 10
		c.Limits.MaxConnectionsPerIP = 2
	}})
	first := dial(t, ts)
	handshake(t, first, 1)
	second := dial(t, ts)
	handshake(t, second, 1)

	conn, err := transport.Dial(testContext(t), ts.addr, ts.pin, transport.DialOptions{})
	if err == nil {
		conn.CloseNow()
		t.Fatal("third connection from the same IP was accepted")
	}
	if got := ts.srv.Stats().RejectedConnections; got != 1 {
		t.Errorf("RejectedConnections = %d, want 1", got)
	}

	first.Close(websocket.StatusNormalClosure, "")
	waitFor(t, "slot release", func() bool { return ts.srv.Stats().Connections == 1 })
	third := dial(t, ts)
	handshake(t, third, 1)
}

func TestGlobalLimit(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		c.Limits.MaxConnections = 1
		c.Limits.MaxConnectionsPerIP = 1
	}})
	handshake(t, dial(t, ts), 1)
	if conn, err := transport.Dial(testContext(t), ts.addr, ts.pin, transport.DialOptions{}); err == nil {
		conn.CloseNow()
		t.Fatal("connection above the global limit was accepted")
	}
}

// rawDial opens a plain TCP connection to ts, optionally from a specific
// local IP, and returns it without starting TLS.
func rawDial(t *testing.T, ts *testServer, localIP string) (net.Conn, error) {
	t.Helper()
	dialer := net.Dialer{Timeout: 5 * time.Second}
	if localIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
	}
	conn, err := dialer.Dial("tcp", ts.addr)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { conn.Close() })
	return conn, nil
}

func mustRawDial(t *testing.T, ts *testServer) net.Conn {
	t.Helper()
	conn, err := rawDial(t, ts, "")
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// expectClosedByServer checks that the server closes conn without sending
// a single byte, which for a TLS server means it never started TLS.
func expectClosedByServer(t *testing.T, conn net.Conn, within time.Duration) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	n, err := conn.Read(buf[:])
	if n != 0 || err == nil {
		t.Fatalf("server sent %d bytes", n)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("server did not close the connection within %s", within)
	}
}

// expectOpen checks that the server keeps conn open for a short while.
func expectOpen(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	_, err := conn.Read(buf[:])
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("held connection was closed: %v", err)
	}
}

// TestLimitsAppliedBeforeTLS holds the per-IP quota with plain TCP
// connections that never start TLS, and checks that further connections
// are closed by the server before any TLS processing.
func TestLimitsAppliedBeforeTLS(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		c.Limits.MaxConnections = 10
		c.Limits.MaxConnectionsPerIP = 2
	}})
	held := []net.Conn{mustRawDial(t, ts), mustRawDial(t, ts)}
	waitFor(t, "raw connections to be accepted", func() bool {
		stats := ts.srv.Stats()
		return stats.Connections == 2 && stats.PendingConnections == 2
	})

	expectClosedByServer(t, mustRawDial(t, ts), 5*time.Second)
	if conn, err := transport.Dial(testContext(t), ts.addr, ts.pin, transport.DialOptions{}); err == nil {
		conn.CloseNow()
		t.Fatal("WebSocket dial above the per-IP limit succeeded")
	}
	if got := ts.srv.Stats().RejectedConnections; got != 2 {
		t.Errorf("RejectedConnections = %d, want 2", got)
	}
	for _, conn := range held {
		expectOpen(t, conn)
		conn.Close()
	}
	waitFor(t, "slot release", func() bool { return ts.srv.Stats().Connections == 0 })

	conn := dial(t, ts)
	handshake(t, conn, 1)
	if stats := ts.srv.Stats(); stats.Connections != 1 || stats.PendingConnections != 0 {
		t.Fatalf("stats with one session = %+v, want 1 connection, 0 pending", stats)
	}
}

// TestGlobalLimitAcrossAddresses uses several loopback source addresses so
// that the global limit, not the per-IP limit, is the one that applies.
func TestGlobalLimitAcrossAddresses(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		c.Limits.MaxConnections = 2
		c.Limits.MaxConnectionsPerIP = 1
	}})
	first, err := rawDial(t, ts, "127.0.0.2")
	if err != nil {
		t.Skipf("cannot dial from 127.0.0.2: %v", err)
	}
	second, err := rawDial(t, ts, "127.0.0.3")
	if err != nil {
		t.Skipf("cannot dial from 127.0.0.3: %v", err)
	}
	waitFor(t, "raw connections to be accepted", func() bool { return ts.srv.Stats().Connections == 2 })

	third, err := rawDial(t, ts, "127.0.0.4")
	if err != nil {
		t.Skipf("cannot dial from 127.0.0.4: %v", err)
	}
	expectClosedByServer(t, third, 5*time.Second)
	expectOpen(t, first)
	expectOpen(t, second)
	if got := ts.srv.Stats().RejectedConnections; got != 1 {
		t.Errorf("RejectedConnections = %d, want 1", got)
	}

	first.Close()
	waitFor(t, "slot release", func() bool { return ts.srv.Stats().Connections == 1 })
	handshake(t, dial(t, ts), 1)
}

// TestPendingHandshakeCap checks that connections which have not completed
// the upgrade are capped, and that established sessions do not count.
func TestPendingHandshakeCap(t *testing.T) {
	ts := startServer(t, serverOptions{config: func(c *Config) {
		c.Limits.MaxConnections = 10
		c.Limits.MaxConnectionsPerIP = 10
		c.Limits.MaxPendingHandshakes = 2
	}})
	first := mustRawDial(t, ts)
	mustRawDial(t, ts)
	waitFor(t, "pending connections", func() bool { return ts.srv.Stats().PendingConnections == 2 })

	expectClosedByServer(t, mustRawDial(t, ts), 5*time.Second)
	if conn, err := transport.Dial(testContext(t), ts.addr, ts.pin, transport.DialOptions{}); err == nil {
		conn.CloseNow()
		t.Fatal("WebSocket dial above the pending-handshake cap succeeded")
	}

	first.Close()
	waitFor(t, "pending slot release", func() bool { return ts.srv.Stats().PendingConnections == 1 })
	sessions := []*websocket.Conn{dial(t, ts)}
	handshake(t, sessions[0], 1)
	waitFor(t, "upgrade to free its pending slot", func() bool { return ts.srv.Stats().PendingConnections == 1 })
	mustRawDial(t, ts)
	waitFor(t, "another pending connection", func() bool { return ts.srv.Stats().PendingConnections == 2 })
	if stats := ts.srv.Stats(); stats.Connections != 3 || stats.ActiveSessions != 1 {
		t.Fatalf("stats = %+v, want 3 connections and 1 session", stats)
	}
	sendFrame(t, sessions[0], protocol.TypePing, 2, protocol.Ping{Nonce: 9})
	readFrame(t, sessions[0])
}

// TestSetupTimeout checks that a connection that never completes TLS is
// dropped after the setup deadline, while an established session outlives
// it.
func TestSetupTimeout(t *testing.T) {
	const setup = 300 * time.Millisecond
	ts := startServer(t, serverOptions{tweak: func(s *Server) { s.setupTimeout = setup }})
	session := dial(t, ts)
	handshake(t, session, 1)

	silent := mustRawDial(t, ts)
	trickle := mustRawDial(t, ts)
	if _, err := trickle.Write([]byte{0x16, 0x03, 0x01}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	expectClosedByServer(t, silent, 5*time.Second)
	expectClosedByServer(t, trickle, 5*time.Second)
	if elapsed := time.Since(start); elapsed < setup/2 {
		t.Fatalf("connection closed after %s, before the setup deadline", elapsed)
	}
	waitFor(t, "slot release", func() bool {
		stats := ts.srv.Stats()
		return stats.Connections == 1 && stats.PendingConnections == 0
	})

	time.Sleep(2 * setup)
	sendFrame(t, session, protocol.TypePing, 2, protocol.Ping{Nonce: 3})
	pong, err := protocol.DecodeBody[protocol.Pong](readFrame(t, session), protocol.TypePong)
	if err != nil || pong.Nonce != 3 {
		t.Fatalf("session did not survive the setup deadline: %+v, %v", pong, err)
	}
}

// TestOneRequestPerConnection checks that a response other than an upgrade
// closes the connection and frees its slot.
func TestOneRequestPerConnection(t *testing.T) {
	ts := startServer(t, serverOptions{})
	conn, err := tls.Dial("tcp", ts.addr, transport.ClientTLSConfig(ts.pin))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	const request = "GET /missing HTTP/1.1\r\nHost: qchat\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || !resp.Close {
		t.Fatalf("status %d, close %v; want 404 with Connection: close", resp.StatusCode, resp.Close)
	}
	_, _ = io.WriteString(conn, request)
	if second, err := http.ReadResponse(reader, nil); err == nil {
		second.Body.Close()
		t.Fatal("server answered a second request on the same connection")
	}
	waitFor(t, "slot release", func() bool { return ts.srv.Stats().Connections == 0 })
}

func pinnedHTTPClient(pin transport.Fingerprint) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   transport.ClientTLSConfig(pin),
			DisableKeepAlives: true,
			Proxy:             nil,
		},
	}
}

func TestOtherPathsNotFound(t *testing.T) {
	ts := startServer(t, serverOptions{})
	client := pinnedHTTPClient(ts.pin)
	for _, path := range []string{"/", "/v1", "/v1/ws/", "/v1/WS", "//v1/ws", "/v1/ws/../ws2", "/favicon.ico"} {
		resp, err := client.Get("https://" + ts.addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, resp.StatusCode)
		}
	}
	resp, err := client.Get("https://" + ts.addr + transport.WebSocketPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatalf("plain GET of the WebSocket path returned %d", resp.StatusCode)
	}
}

func TestGracefulShutdown(t *testing.T) {
	ts := startServer(t, serverOptions{})
	first := dial(t, ts)
	handshake(t, first, 1)
	second := dial(t, ts)
	handshake(t, second, 1)
	pending := dial(t, ts)
	waitFor(t, "sessions to register", func() bool { return ts.srv.Stats().ActiveSessions == 3 })

	stopped := make(chan error, 1)
	go func() { stopped <- ts.stop(t) }()

	for _, conn := range []*websocket.Conn{first, second, pending} {
		expectClose(t, conn, websocket.StatusGoingAway)
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("Serve returned %v after graceful shutdown", err)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("Serve did not return")
	}
	if stats := ts.srv.Stats(); stats.ActiveSessions != 0 || stats.Connections != 0 {
		t.Fatalf("stats after shutdown = %+v", stats)
	}
	if conn, err := transport.Dial(testContext(t), ts.addr, ts.pin, transport.DialOptions{}); err == nil {
		conn.CloseNow()
		t.Fatal("dial succeeded after shutdown")
	}
}

func TestServeTwice(t *testing.T) {
	ts := startServer(t, serverOptions{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.srv.Serve(context.Background(), ln); err == nil {
		t.Fatal("second Serve succeeded")
	}
}

func TestListenAndServe(t *testing.T) {
	cert, pin := testIdentity(t)
	cfg := DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Database = filepath.Join(t.TempDir(), "qchat.db")
	srv, err := New(cfg, cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	waitFor(t, "listener", func() bool { return srv.Addr() != nil })
	conn, err := transport.Dial(testContext(t), srv.Addr().String(), pin, transport.DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	handshake(t, conn, 1)
	cancel()
	expectClose(t, conn, websocket.StatusGoingAway)
	if err := <-done; err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}

	busy := DefaultConfig()
	busy.Listen = srv.Addr().String()
	ln, err := net.Listen("tcp", busy.Listen)
	if err != nil {
		t.Skipf("cannot re-listen on %s: %v", busy.Listen, err)
	}
	defer ln.Close()
	srv2, err := New(busy, cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv2.ListenAndServe(context.Background()); err == nil {
		t.Fatal("ListenAndServe on a busy port succeeded")
	}
}

// TestLogsContainNoAddresses drives every session outcome against servers
// on the IPv4 and (if available) IPv6 loopback addresses and checks that
// the debug log never mentions a client address or client data.
func TestLogsContainNoAddresses(t *testing.T) {
	const secretNonce = 17_293_822_569_102_704_642
	logs := &syncBuffer{}
	listens := []string{"127.0.0.1:0"}
	if ln, err := net.Listen("tcp", "[::1]:0"); err == nil {
		ln.Close()
		listens = append(listens, "[::1]:0")
	} else {
		t.Logf("IPv6 loopback unavailable, testing IPv4 only: %v", err)
	}

	for _, listen := range listens {
		ts := startServer(t, serverOptions{listen: listen, logs: logs, config: func(c *Config) {
			c.Limits.MaxConnectionsPerIP = 3
			c.Limits.HandshakeTimeout = DurationOf(300 * time.Millisecond)
			c.Limits.Burst = 5
		}})

		conn := dial(t, ts)
		handshake(t, conn, 1)
		sendFrame(t, conn, protocol.TypePing, secretNonce, protocol.Ping{Nonce: secretNonce})
		readFrame(t, conn)
		conn.Close(websocket.StatusNormalClosure, "bye 127.0.0.1 ::1")

		garbage := dial(t, ts)
		sendRaw(t, garbage, []byte("127.0.0.1 ::1 garbage"))
		expectError(t, garbage, protocol.ErrCodeBadRequest)
		expectClose(t, garbage, websocket.StatusPolicyViolation)

		text := dial(t, ts)
		if err := text.Write(testContext(t), websocket.MessageText, []byte("::1")); err != nil {
			t.Fatal(err)
		}
		expectClose(t, text, websocket.StatusUnsupportedData)

		silent := dial(t, ts)
		expectClose(t, silent, websocket.StatusPolicyViolation)

		waitFor(t, "sessions to end", func() bool { return ts.srv.Stats().Connections == 0 })
		held := []*websocket.Conn{dial(t, ts), dial(t, ts), dial(t, ts)}
		for _, c := range held {
			handshake(t, c, 1)
		}
		if c, err := transport.Dial(testContext(t), ts.addr, ts.pin, transport.DialOptions{}); err == nil {
			c.CloseNow()
			t.Fatal("connection above the per-IP limit accepted")
		}
		client := pinnedHTTPClient(ts.pin)
		if resp, err := client.Get("https://" + ts.addr + "/127.0.0.1"); err == nil {
			resp.Body.Close()
		}
		var readers sync.WaitGroup
		for _, c := range held {
			readers.Go(func() { _, _, _ = c.Read(testContext(t)) })
		}
		if err := ts.stop(t); err != nil {
			t.Fatal(err)
		}
		readers.Wait()
	}

	output := logs.String()
	for _, want := range []string{"session opened", "session closed", "reason=handshake_timeout", "reason=bad_request", "reason=shutdown", "connection rejected", "server stopped"} {
		if !strings.Contains(output, want) {
			t.Errorf("log lacks %q", want)
		}
	}
	for _, forbidden := range []string{"127.0.0.1", "::1", "[::", strconv.FormatUint(secretNonce, 10), "garbage", "bye"} {
		if strings.Contains(output, forbidden) {
			t.Errorf("log contains %q:\n%s", forbidden, output)
		}
	}
	if t.Failed() {
		t.Logf("log output:\n%s", output)
	}
}

func TestRequestErrorCode(t *testing.T) {
	if got := requestErrorCode(errors.New("other")); got != protocol.ErrCodeBadRequest {
		t.Fatalf("unclassified error mapped to %v", got)
	}
	if got := requestErrorCode(protocol.ErrUnsupportedVersion); got != protocol.ErrCodeUnsupportedVersion {
		t.Fatalf("ErrUnsupportedVersion mapped to %v", got)
	}
}
