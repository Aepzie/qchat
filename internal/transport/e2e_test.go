package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// testServer is a real TLS server on 127.0.0.1 running the qchat endpoint
// with an echo handler.
type testServer struct {
	addr      string
	pin       Fingerprint
	tlsStates chan tls.ConnectionState
	acceptErr chan error
}

func startTestServer(t *testing.T, readLimit int64) *testServer {
	t.Helper()
	certPEM, keyPEM, err := GenerateServerIdentity([]string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeIdentity(t, certPEM, keyPEM)
	cert, err := LoadServerCertificate(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := FingerprintOfTLS(cert)
	if err != nil {
		t.Fatal(err)
	}

	ts := &testServer{
		pin:       pin,
		tlsStates: make(chan tls.ConnectionState, 16),
		acceptErr: make(chan error, 16),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(WebSocketPath, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			ts.tlsStates <- *r.TLS
		}
		conn, err := Accept(w, r, readLimit)
		ts.acceptErr <- err
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx := context.Background()
		for {
			typ, msg, err := conn.Read(ctx)
			if err != nil {
				return
			}
			if err := conn.Write(ctx, typ, msg); err != nil {
				return
			}
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTPServer(ln.Addr().String(), mux, ServerTLSConfig(cert))
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	ts.addr = ln.Addr().String()
	return ts
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestDialEcho(t *testing.T) {
	ts := startTestServer(t, 0)
	ctx := testContext(t)

	var dialed int
	opts := DialOptions{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed++
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	conn, err := Dial(ctx, ts.addr, ts.pin, opts)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.CloseNow()

	if dialed != 1 {
		t.Fatalf("custom NetDialContext called %d times, want 1", dialed)
	}
	if conn.Subprotocol() != Subprotocol {
		t.Fatalf("subprotocol %q, want %q", conn.Subprotocol(), Subprotocol)
	}

	for _, msg := range [][]byte{[]byte("hello"), bytes.Repeat([]byte{0xAB}, 64<<10)} {
		if err := conn.Write(ctx, websocket.MessageBinary, msg); err != nil {
			t.Fatal(err)
		}
		typ, got, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if typ != websocket.MessageBinary || !bytes.Equal(got, msg) {
			t.Fatalf("echo mismatch: type %v, %d bytes", typ, len(got))
		}
	}

	select {
	case cs := <-ts.tlsStates:
		if cs.Version != tls.VersionTLS13 {
			t.Errorf("TLS version 0x%04x, want TLS 1.3", cs.Version)
		}
		if cs.CurveID != tls.X25519MLKEM768 {
			t.Errorf("key exchange %v, want X25519MLKEM768", cs.CurveID)
		}
		if cs.NegotiatedProtocol == "h2" {
			t.Errorf("ALPN negotiated h2; HTTP/2 must be disabled")
		}
		if cs.DidResume {
			t.Error("session was resumed; resumption should be disabled")
		}
	default:
		t.Fatal("server did not observe a TLS connection state")
	}
	conn.Close(websocket.StatusNormalClosure, "")
}

// TestDialIgnoresMLKEMGodebug checks that GODEBUG=tlsmlkem=0, which removes
// ML-KEM from Go's default key exchange list, does not weaken or break the
// explicitly configured hybrid key exchange.
func TestDialIgnoresMLKEMGodebug(t *testing.T) {
	t.Setenv("GODEBUG", "tlsmlkem=0,tlssecpmlkem=0")
	ts := startTestServer(t, 0)
	conn, err := Dial(testContext(t), ts.addr, ts.pin, DialOptions{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.CloseNow()
	cs := <-ts.tlsStates
	if cs.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("key exchange %v, want X25519MLKEM768", cs.CurveID)
	}
}

func TestDialWrongPin(t *testing.T) {
	ts := startTestServer(t, 0)
	wrong := ts.pin
	wrong[0] ^= 0xFF

	conn, err := Dial(testContext(t), ts.addr, wrong, DialOptions{})
	if err == nil {
		conn.CloseNow()
		t.Fatal("Dial with wrong pin succeeded")
	}
	t.Logf("wrong pin error: %v", err)
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("error %v does not wrap ErrPinMismatch", err)
	}
	var mismatch *PinMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error %v is not a *PinMismatchError", err)
	}
	if !mismatch.Presented.Equal(ts.pin) || !mismatch.Expected.Equal(wrong) {
		t.Fatalf("mismatch details wrong: %+v", mismatch)
	}
	select {
	case <-ts.acceptErr:
		t.Fatal("handler ran although the TLS handshake should have failed")
	default:
	}
}

func TestDialZeroPin(t *testing.T) {
	ts := startTestServer(t, 0)
	called := false
	opts := DialOptions{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			called = true
			return nil, errors.New("must not dial")
		},
	}
	if _, err := Dial(testContext(t), ts.addr, Fingerprint{}, opts); err == nil {
		t.Fatal("Dial with zero pin succeeded")
	}
	if called {
		t.Fatal("Dial with zero pin touched the network")
	}

	cfg := ClientTLSConfig(Fingerprint{})
	raw, err := tls.Dial("tcp", ts.addr, cfg)
	if err == nil {
		raw.Close()
		t.Fatal("ClientTLSConfig with zero pin completed a handshake")
	}
}

func TestDialBadAddress(t *testing.T) {
	pin := abcFingerprint(t)
	for _, addr := range []string{"", "host", "host:", ":443", "host:0", "host:70000", "ho/st:443", "a@b:443", "h st:443"} {
		if _, err := Dial(testContext(t), addr, pin, DialOptions{}); err == nil {
			t.Errorf("Dial(%q) succeeded, want error", addr)
		}
	}
}

func TestServerRejectsClassicalKeyExchange(t *testing.T) {
	ts := startTestServer(t, 0)
	for _, curves := range [][]tls.CurveID{
		{tls.X25519},
		{tls.CurveP256, tls.CurveP384},
		{tls.SecP256r1MLKEM768},
	} {
		raw, err := tls.Dial("tcp", ts.addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			CurvePreferences:   curves,
		})
		if err == nil {
			raw.Close()
			t.Errorf("handshake with curves %v succeeded, want failure", curves)
		}
	}
}

func TestServerRejectsTLS12(t *testing.T) {
	ts := startTestServer(t, 0)
	raw, err := tls.Dial("tcp", ts.addr, &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	})
	if err == nil {
		raw.Close()
		t.Fatal("TLS 1.2 handshake succeeded")
	}
}

// TestServerHybridViaHelloRetry checks that a client which prefers X25519
// but also supports the hybrid group is moved to the hybrid group rather
// than allowed to use X25519.
func TestServerHybridViaHelloRetry(t *testing.T) {
	ts := startTestServer(t, 0)
	raw, err := tls.Dial("tcp", ts.addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
	})
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer raw.Close()
	if got := raw.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
		t.Fatalf("key exchange %v, want X25519MLKEM768", got)
	}
}

func TestVerifyPinnedConnection(t *testing.T) {
	leaf := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("abc")}
	pin := FingerprintOf(leaf)
	good := tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CurveID:          tls.X25519MLKEM768,
		PeerCertificates: []*x509.Certificate{leaf},
	}
	if err := verifyPinnedConnection(good, pin); err != nil {
		t.Fatalf("good connection rejected: %v", err)
	}

	tls12 := good
	tls12.Version = tls.VersionTLS12
	if err := verifyPinnedConnection(tls12, pin); !errors.Is(err, ErrWeakHandshake) {
		t.Errorf("TLS 1.2: got %v, want ErrWeakHandshake", err)
	}

	classical := good
	classical.CurveID = tls.X25519
	if err := verifyPinnedConnection(classical, pin); !errors.Is(err, ErrWeakHandshake) {
		t.Errorf("X25519: got %v, want ErrWeakHandshake", err)
	}

	noCerts := good
	noCerts.PeerCertificates = nil
	if err := verifyPinnedConnection(noCerts, pin); !errors.Is(err, ErrPinMismatch) {
		t.Errorf("no certs: got %v, want ErrPinMismatch", err)
	}

	other := pin
	other[5] ^= 1
	if err := verifyPinnedConnection(good, other); !errors.Is(err, ErrPinMismatch) {
		t.Errorf("wrong pin: got %v, want ErrPinMismatch", err)
	}

	if err := verifyPinnedConnection(good, Fingerprint{}); err == nil {
		t.Error("zero pin accepted")
	}
}

// rawWebSocketDial performs a WebSocket handshake with the pinned client but
// full control over headers and offered subprotocols.
func rawWebSocketDial(ctx context.Context, ts *testServer, header http.Header, subprotocols []string) error {
	client := newPinnedHTTPClient(ts.pin, nil)
	defer client.CloseIdleConnections()
	conn, _, err := websocket.Dial(ctx, "wss://"+ts.addr+WebSocketPath, &websocket.DialOptions{
		HTTPClient:   client,
		HTTPHeader:   header,
		Subprotocols: subprotocols,
	})
	if err == nil {
		conn.CloseNow()
	}
	return err
}

func TestAcceptRejectsOrigin(t *testing.T) {
	ts := startTestServer(t, 0)
	ctx := testContext(t)
	for _, origin := range []string{"https://evil.example", "https://" + ts.addr, "null", ""} {
		err := rawWebSocketDial(ctx, ts, http.Header{"Origin": []string{origin}}, []string{Subprotocol})
		if err == nil {
			t.Errorf("handshake with Origin %q succeeded", origin)
			continue
		}
		if acceptErr := <-ts.acceptErr; acceptErr == nil {
			t.Errorf("Accept returned nil error for Origin %q", origin)
		}
	}
}

func TestAcceptRequiresSubprotocol(t *testing.T) {
	ts := startTestServer(t, 0)
	ctx := testContext(t)
	for _, protos := range [][]string{nil, {"qchat.v2"}, {"QCHAT.V1"}} {
		if err := rawWebSocketDial(ctx, ts, nil, protos); err == nil {
			t.Errorf("handshake offering %v succeeded", protos)
			continue
		}
		if acceptErr := <-ts.acceptErr; acceptErr == nil {
			t.Errorf("Accept returned nil error when offered %v", protos)
		}
	}
	if err := rawWebSocketDial(ctx, ts, nil, []string{"other", Subprotocol}); err != nil {
		t.Fatalf("handshake offering our subprotocol among others failed: %v", err)
	}
	if acceptErr := <-ts.acceptErr; acceptErr != nil {
		t.Fatalf("Accept failed: %v", acceptErr)
	}
}

func TestAcceptRejectsPlaintext(t *testing.T) {
	errs := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := Accept(w, r, 0)
		if conn != nil {
			conn.CloseNow()
		}
		errs <- err
	}))
	defer srv.Close()

	url := "ws://" + strings.TrimPrefix(srv.URL, "http://") + WebSocketPath
	conn, _, err := websocket.Dial(testContext(t), url, &websocket.DialOptions{Subprotocols: []string{Subprotocol}})
	if err == nil {
		conn.CloseNow()
		t.Fatal("plaintext WebSocket accepted")
	}
	if acceptErr := <-errs; acceptErr == nil {
		t.Fatal("Accept returned nil error over plaintext")
	}
}

func TestReadLimitEnforced(t *testing.T) {
	ts := startTestServer(t, 16)
	ctx := testContext(t)
	conn, err := Dial(ctx, ts.addr, ts.pin, DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	if err := conn.Write(ctx, websocket.MessageBinary, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("message at the limit was rejected: %v", err)
	}

	if err := conn.Write(ctx, websocket.MessageBinary, make([]byte, 17)); err != nil {
		t.Fatal(err)
	}
	_, _, err = conn.Read(ctx)
	if got := websocket.CloseStatus(err); got != websocket.StatusMessageTooBig {
		t.Fatalf("close status %v (err %v), want StatusMessageTooBig", got, err)
	}
}

func TestEffectiveReadLimit(t *testing.T) {
	for in, want := range map[int64]int64{0: DefaultReadLimit, -1: DefaultReadLimit, -100: DefaultReadLimit, 1: 1, 4096: 4096} {
		if got := effectiveReadLimit(in); got != want {
			t.Errorf("effectiveReadLimit(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestNewHTTPServerHardening(t *testing.T) {
	srv := NewHTTPServer("127.0.0.1:0", http.NotFoundHandler(), &tls.Config{})
	if srv.ReadHeaderTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Error("timeouts not set")
	}
	if srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes > 64<<10 {
		t.Errorf("MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
	if srv.TLSNextProto == nil || len(srv.TLSNextProto) != 0 {
		t.Error("TLSNextProto must be a non-nil empty map")
	}
	if srv.Protocols == nil || srv.Protocols.HTTP2() {
		t.Error("HTTP/2 must be disabled")
	}
	if srv.ErrorLog == nil {
		t.Fatal("ErrorLog must be set to a discarding logger")
	}
	if srv.ErrorLog.Writer() != io.Discard {
		t.Error("ErrorLog must write to io.Discard")
	}
}
