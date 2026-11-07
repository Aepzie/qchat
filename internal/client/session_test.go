package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/transport"
)

// fakeServer is a minimal qchat server on 127.0.0.1 for exercising the
// session against the real transport.
type fakeServer struct {
	addr  string
	pin   transport.Fingerprint
	conns atomic.Int32

	mu sync.Mutex
	// binding is the server side TLS channel binding of the most recently
	// accepted connection.
	binding []byte
}

// lastBinding returns the server side channel binding of the most recently
// accepted connection.
func (fs *fakeServer) lastBinding() []byte {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.binding
}

// serverHandler runs one accepted connection. n is the 1-based connection
// number.
type serverHandler func(ctx context.Context, conn *websocket.Conn, n int)

func startFakeServer(t *testing.T, handle serverHandler) *fakeServer {
	t.Helper()
	certPEM, keyPEM, err := transport.GenerateServerIdentity([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := transport.FingerprintOfTLS(cert)
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeServer{pin: pin}
	ctx, cancel := context.WithCancel(context.Background())
	mux := http.NewServeMux()
	mux.HandleFunc(transport.WebSocketPath, func(w http.ResponseWriter, r *http.Request) {
		binding, err := transport.AuthBinding(r.TLS)
		if err != nil {
			t.Errorf("AuthBinding: %v", err)
			return
		}
		conn, err := transport.Accept(w, r, 0)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		fs.mu.Lock()
		fs.binding = binding
		fs.mu.Unlock()
		handle(ctx, conn, int(fs.conns.Add(1)))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := transport.NewHTTPServer(ln.Addr().String(), mux, transport.ServerTLSConfig(cert))
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
	})
	fs.addr = ln.Addr().String()
	return fs
}

func readFrame(ctx context.Context, conn *websocket.Conn) (protocol.Frame, error) {
	_, msg, err := conn.Read(ctx)
	if err != nil {
		return protocol.Frame{}, err
	}
	return protocol.Decode(msg)
}

func writeFrame[T any](ctx context.Context, conn *websocket.Conn, typ protocol.FrameType, id uint64, body T) error {
	f, err := protocol.NewFrame(typ, id, body)
	if err != nil {
		return err
	}
	raw, err := protocol.Encode(f)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageBinary, raw)
}

// welcome reads the Hello and answers it with a Welcome.
func welcome(ctx context.Context, t *testing.T, conn *websocket.Conn) bool {
	f, err := readFrame(ctx, conn)
	if err != nil {
		return false
	}
	if f.Type != protocol.TypeHello || f.ID != helloID {
		t.Errorf("first frame: type %v id %d, want Hello id 1", f.Type, f.ID)
		return false
	}
	hello, err := protocol.DecodeBody[protocol.Hello](f, protocol.TypeHello)
	if err != nil {
		t.Errorf("decode Hello: %v", err)
		return false
	}
	if hello != protocol.ClientHello() {
		t.Errorf("Hello = %+v", hello)
	}
	w := protocol.Welcome{Version: protocol.Version, MaxFrameSize: protocol.MaxFrameSize, PingInterval: 1}
	return writeFrame(ctx, conn, protocol.TypeWelcome, f.ID, w) == nil
}

// servePongs answers pings until the connection ends or limit pongs have
// been sent (limit <= 0 means no limit). It reports whether the limit was
// reached.
func servePongs(ctx context.Context, conn *websocket.Conn, limit int) bool {
	sent := 0
	for {
		f, err := readFrame(ctx, conn)
		if err != nil {
			return false
		}
		if f.Type != protocol.TypePing {
			continue
		}
		ping, err := protocol.DecodeBody[protocol.Ping](f, protocol.TypePing)
		if err != nil {
			return false
		}
		if writeFrame(ctx, conn, protocol.TypePong, f.ID, protocol.Pong(ping)) != nil {
			return false
		}
		sent++
		if limit > 0 && sent >= limit {
			return true
		}
	}
}

func newTestSession(t *testing.T, opts Options) *Session {
	t.Helper()
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	s.backoffMin = 20 * time.Millisecond
	s.backoffMax = 100 * time.Millisecond
	return s
}

// runResult receives the result of Run.
type runResult struct {
	done chan struct{}
	err  error
}

// wait returns Run's result, failing the test if Run does not return.
func (r *runResult) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-r.done:
		return r.err
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

// runSession starts Run in the background. Cleanup cancels it and waits.
func runSession(t *testing.T, s *Session) (context.CancelFunc, *runResult) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	res := &runResult{done: make(chan struct{})}
	go func() {
		res.err = s.Run(ctx)
		close(res.done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-res.done:
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
	return cancel, res
}

// waitFor reads events until match returns true, failing after a timeout.
// It returns every event seen, including the matching one.
func waitFor(t *testing.T, s *Session, what string, match func(Event) bool) []Event {
	t.Helper()
	var seen []Event
	timeout := time.After(15 * time.Second)
	for {
		select {
		case ev, ok := <-s.Events():
			if !ok {
				t.Fatalf("event channel closed while waiting for %s; saw %v", what, seen)
			}
			seen = append(seen, ev)
			if match(ev) {
				return seen
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %s; saw %v", what, seen)
		}
	}
}

func isState(want State) func(Event) bool {
	return func(ev Event) bool {
		sc, ok := ev.(StateChanged)
		return ok && sc.State == want
	}
}

func TestNewValidates(t *testing.T) {
	var pin transport.Fingerprint
	pin[0] = 1
	if _, err := New(Options{Addr: "example.org:443"}); err == nil {
		t.Error("New without pin succeeded")
	}
	if _, err := New(Options{Addr: "example.org", Pin: pin}); err == nil {
		t.Error("New with bad address succeeded")
	}
	if _, err := New(Options{Addr: "example.org:443", Pin: pin}); err != nil {
		t.Errorf("New with valid options: %v", err)
	}
	for _, bad := range []string{"user@example.org:443", "exa mple.org:443", "example.org/x:443", "bücher.example:443"} {
		if _, err := New(Options{Addr: bad, Pin: pin}); !errors.Is(err, transport.ErrInvalidAddress) {
			t.Errorf("New(Addr: %q) error = %v, want ErrInvalidAddress", bad, err)
		}
	}
	s, err := New(Options{Addr: "example.org:0443", Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	if s.Addr() != "example.org:443" {
		t.Errorf("Addr() = %q, want canonical example.org:443", s.Addr())
	}
}

func TestInvalidAddressIsPermanent(t *testing.T) {
	var pin transport.Fingerprint
	pin[0] = 1
	dialed := atomic.Int32{}
	dialer := func(context.Context, string, string) (net.Conn, error) {
		dialed.Add(1)
		return nil, errors.New("must not dial")
	}
	s := newTestSession(t, Options{Addr: "example.org:443", Pin: pin, Dialer: dialer})
	s.opts.Addr = "user@example.org:443"
	_, res := runSession(t, s)
	seen := waitFor(t, s, "Failed", isState(Failed))
	if err := seen[len(seen)-1].(StateChanged).Err; !errors.Is(err, transport.ErrInvalidAddress) {
		t.Fatalf("Failed.Err = %v, want ErrInvalidAddress", err)
	}
	if err := res.wait(t); !errors.Is(err, transport.ErrInvalidAddress) {
		t.Fatalf("Run = %v, want ErrInvalidAddress", err)
	}
	attempts := 0
	for _, ev := range seen {
		if sc, ok := ev.(StateChanged); ok && sc.State == Connecting {
			attempts++
		}
	}
	if attempts != 1 || dialed.Load() != 0 {
		t.Fatalf("attempts = %d, network dials = %d; want 1 attempt and no dial", attempts, dialed.Load())
	}
}

func TestConnectWelcomeAndRTT(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if welcome(ctx, t, conn) {
			servePongs(ctx, conn, 0)
		}
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin})
	cancel, done := runSession(t, s)

	seen := waitFor(t, s, "Connected", isState(Connected))
	first, ok := seen[0].(StateChanged)
	if !ok || first.State != Connecting || first.Attempt != 1 {
		t.Fatalf("first event %#v, want Connecting attempt 1", seen[0])
	}
	sc := seen[len(seen)-1].(StateChanged)
	if sc.Info.ProtocolVersion != protocol.Version || sc.Info.PingInterval != time.Second {
		t.Errorf("info = %+v", sc.Info)
	}
	if sc.Info.Transport != TransportDescription || !sc.Info.Fingerprint.Equal(fs.pin) || sc.Info.Addr != fs.addr {
		t.Errorf("info = %+v", sc.Info)
	}
	if info, ok := s.Info(); !ok || info.ProtocolVersion != protocol.Version {
		t.Errorf("Info() = %+v, %v", info, ok)
	}

	seen = waitFor(t, s, "RTT", func(ev Event) bool { _, ok := ev.(RTT); return ok })
	rtt := seen[len(seen)-1].(RTT)
	if rtt.Duration < 0 || rtt.Duration > 5*time.Second {
		t.Errorf("RTT = %v", rtt.Duration)
	}
	waitFor(t, s, "second RTT", func(ev Event) bool { _, ok := ev.(RTT); return ok })

	cancel()
	if err := done.wait(t); err != nil {
		t.Fatalf("Run after cancel = %v, want nil", err)
	}
	waitFor(t, s, "Disconnected", isState(Disconnected))
	for range s.Events() {
	}
	if _, ok := s.Info(); ok {
		t.Error("Info reports connected after Run returned")
	}
	if err := s.Run(context.Background()); err == nil {
		t.Error("second Run succeeded")
	}
}

func TestWrongPinRaisesAlertAndNeverRetries(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		t.Error("handler reached despite wrong pin")
	})
	wrong := fs.pin
	wrong[0] ^= 0xff
	var dials atomic.Int32
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	s := newTestSession(t, Options{Addr: fs.addr, Pin: wrong, Dialer: dialer})
	_, done := runSession(t, s)

	seen := waitFor(t, s, "SecurityAlert", func(ev Event) bool { _, ok := ev.(SecurityAlert); return ok })
	alert := seen[len(seen)-1].(SecurityAlert)
	if !alert.Expected.Equal(wrong) || !alert.Presented.Equal(fs.pin) {
		t.Fatalf("alert = %+v", alert)
	}
	seen = waitFor(t, s, "Failed", func(Event) bool { return true })
	failed, ok := seen[0].(StateChanged)
	if !ok || failed.State != Failed || !errors.Is(failed.Err, transport.ErrPinMismatch) {
		t.Fatalf("event after alert = %#v, want Failed with pin mismatch", seen[0])
	}

	if err := done.wait(t); !errors.Is(err, transport.ErrPinMismatch) {
		t.Fatalf("Run = %v, want pin mismatch", err)
	}
	for ev := range s.Events() {
		t.Errorf("unexpected event after Failed: %#v", ev)
	}
	time.Sleep(200 * time.Millisecond)
	if n := dials.Load(); n != 1 {
		t.Fatalf("dialed %d times, want exactly 1", n)
	}
}

func TestServerErrorFrame(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if _, err := readFrame(ctx, conn); err != nil {
			return
		}
		_ = writeFrame(ctx, conn, protocol.TypeError, helloID, protocol.ErrorBody{Code: protocol.ErrCodeRateLimited, Message: "slow down"})
		_ = conn.Close(websocket.StatusPolicyViolation, "")
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin})
	runSession(t, s)

	seen := waitFor(t, s, "ServerError", func(ev Event) bool { _, ok := ev.(ServerError); return ok })
	se := seen[len(seen)-1].(ServerError)
	if se.Code != protocol.ErrCodeRateLimited || se.Message != "slow down" {
		t.Fatalf("ServerError = %+v", se)
	}
	seen = waitFor(t, s, "Disconnected", isState(Disconnected))
	dis := seen[len(seen)-1].(StateChanged)
	var remote *RemoteError
	if !errors.As(dis.Err, &remote) || remote.Code != protocol.ErrCodeRateLimited {
		t.Fatalf("Disconnected.Err = %v", dis.Err)
	}
	if dis.RetryIn <= 0 {
		t.Errorf("RetryIn = %v", dis.RetryIn)
	}
	waitFor(t, s, "reconnect attempt", isState(Connecting))
}

func TestUnsupportedVersionErrorIsPermanent(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if _, err := readFrame(ctx, conn); err != nil {
			return
		}
		_ = writeFrame(ctx, conn, protocol.TypeError, helloID, protocol.ErrorBody{Code: protocol.ErrCodeUnsupportedVersion})
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin})
	_, done := runSession(t, s)
	seen := waitFor(t, s, "Failed", isState(Failed))
	if err := seen[len(seen)-1].(StateChanged).Err; !errors.Is(err, ErrIncompatibleVersion) {
		t.Fatalf("Failed.Err = %v", err)
	}
	if err := done.wait(t); !errors.Is(err, ErrIncompatibleVersion) {
		t.Fatalf("Run = %v", err)
	}
}

// futureWelcome mirrors protocol.Welcome but is not validated by the
// protocol package, so the test can announce a version the client lacks.
type futureWelcome struct {
	Version      uint8  `cbor:"1,keyasint"`
	MaxFrameSize uint32 `cbor:"2,keyasint"`
	PingInterval uint32 `cbor:"3,keyasint"`
}

func TestWelcomeWithUnknownVersionIsPermanent(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if _, err := readFrame(ctx, conn); err != nil {
			return
		}
		_ = writeFrame(ctx, conn, protocol.TypeWelcome, helloID, futureWelcome{Version: 9, MaxFrameSize: 1024, PingInterval: 5})
		_, _, _ = conn.Read(ctx)
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin})
	_, done := runSession(t, s)
	waitFor(t, s, "Failed", isState(Failed))
	if err := done.wait(t); !errors.Is(err, ErrIncompatibleVersion) {
		t.Fatalf("Run = %v", err)
	}
}

func TestServerGoesAwayThenReconnects(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if !welcome(ctx, t, conn) {
			return
		}
		if n == 1 {
			servePongs(ctx, conn, 1)
			conn.CloseNow()
			return
		}
		servePongs(ctx, conn, 0)
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin})
	runSession(t, s)

	waitFor(t, s, "first Connected", isState(Connected))
	seen := waitFor(t, s, "Disconnected", isState(Disconnected))
	dis := seen[len(seen)-1].(StateChanged)
	if !errors.Is(dis.Err, ErrConnectionLost) {
		t.Errorf("Disconnected.Err = %v, want ErrConnectionLost", dis.Err)
	}
	seen = waitFor(t, s, "Connecting again", isState(Connecting))
	if c := seen[len(seen)-1].(StateChanged); c.Attempt != 1 {
		t.Errorf("attempt after an established connection = %d, want 1", c.Attempt)
	}
	waitFor(t, s, "second Connected", isState(Connected))
	if n := fs.conns.Load(); n != 2 {
		t.Errorf("server saw %d connections, want 2", n)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin})
	s.handshake = 200 * time.Millisecond
	runSession(t, s)
	seen := waitFor(t, s, "Disconnected", isState(Disconnected))
	if err := seen[len(seen)-1].(StateChanged).Err; !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("Disconnected.Err = %v", err)
	}
}

func TestKeepaliveTimeout(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if !welcome(ctx, t, conn) {
			return
		}
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin})
	s.idleGrace = 0
	runSession(t, s)
	waitFor(t, s, "Connected", isState(Connected))
	seen := waitFor(t, s, "Disconnected", isState(Disconnected))
	if err := seen[len(seen)-1].(StateChanged).Err; !errors.Is(err, ErrKeepaliveTimeout) {
		t.Fatalf("Disconnected.Err = %v", err)
	}
}

func TestKeepaliveDeadlineIndependentOfPingTicks(t *testing.T) {
	const pongs = 3
	const grace = 50 * time.Millisecond
	lastPong := make(chan time.Time, 1)
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if n != 1 || !welcome(ctx, t, conn) {
			return
		}
		if !servePongs(ctx, conn, pongs) {
			return
		}
		lastPong <- time.Now()
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin})
	s.idleGrace = grace
	runSession(t, s)
	waitFor(t, s, "Connected", isState(Connected))
	seen := waitFor(t, s, "Disconnected", isState(Disconnected))
	detected := time.Now()
	if err := seen[len(seen)-1].(StateChanged).Err; !errors.Is(err, ErrKeepaliveTimeout) {
		t.Fatalf("Disconnected.Err = %v", err)
	}
	var silentSince time.Time
	select {
	case silentSince = <-lastPong:
	default:
		t.Fatal("server did not answer the expected pings before the timeout")
	}
	interval := time.Second
	want := 2*interval + grace
	if got := detected.Sub(silentSince); got < want-200*time.Millisecond || got > want+400*time.Millisecond {
		t.Fatalf("dead peer detected %v after the last frame, want about %v", got, want)
	}
}

func TestProtocolViolation(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if !welcome(ctx, t, conn) {
			return
		}
		_ = conn.Write(ctx, websocket.MessageBinary, []byte{0xff, 0x00})
		_, _, _ = conn.Read(ctx)
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin})
	runSession(t, s)
	seen := waitFor(t, s, "Disconnected", isState(Disconnected))
	if err := seen[len(seen)-1].(StateChanged).Err; !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("Disconnected.Err = %v", err)
	}
}

func TestBackoffDelay(t *testing.T) {
	for failures := 0; failures < 12; failures++ {
		want := time.Second << failures
		if want > time.Minute || want <= 0 {
			want = time.Minute
		}
		for range 50 {
			d := backoffDelay(time.Second, time.Minute, failures)
			if d < want/2 || d > want {
				t.Fatalf("failures=%d: delay %v outside [%v, %v]", failures, d, want/2, want)
			}
		}
	}
	if d := backoffDelay(time.Second, time.Minute, 1000); d > time.Minute {
		t.Fatalf("huge failure count gave %v", d)
	}
}

func TestEventQueueCoalescesRTTAndKeepsCriticalEvents(t *testing.T) {
	q := &eventQueue{out: make(chan Event, eventBuffer), notify: make(chan struct{}, 1)}
	q.push(StateChanged{State: Connected})
	for i := 1; i <= 100; i++ {
		q.push(RTT{time.Duration(i)})
	}
	if len(q.pending) != 2 {
		t.Fatalf("pending = %d events, want 2", len(q.pending))
	}
	if rtt := q.pending[1].(RTT); rtt.Duration != 100 {
		t.Fatalf("kept RTT %v, want the latest", rtt.Duration)
	}
	for i := 0; i < maxPendingEvents*2; i++ {
		q.push(StateChanged{State: Connecting})
		q.push(ServerError{Code: protocol.ErrCodeInternal})
	}
	q.push(SecurityAlert{})
	q.push(StateChanged{State: Failed})
	if len(q.pending) > maxPendingEvents+2 {
		t.Fatalf("queue grew to %d", len(q.pending))
	}
	n := len(q.pending)
	if _, ok := q.pending[n-2].(SecurityAlert); !ok {
		t.Fatalf("SecurityAlert dropped: %#v", q.pending[n-2])
	}
	if sc, ok := q.pending[n-1].(StateChanged); !ok || sc.State != Failed {
		t.Fatalf("Failed dropped: %#v", q.pending[n-1])
	}
}

func TestSanitizeASCII(t *testing.T) {
	got := SanitizeASCII("ok \x1b[31mred\x07 é", 0)
	if strings.ContainsAny(got, "\x1b\x07") || got != "ok ?[31mred? ??" {
		t.Fatalf("SanitizeASCII = %q", got)
	}
	if got := SanitizeASCII("abcdef", 3); got != "abc" {
		t.Fatalf("truncation = %q", got)
	}
}
