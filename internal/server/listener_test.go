package server

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pipeAddr is a net.Addr with a fixed "host:port" string.
type pipeAddr string

func (a pipeAddr) Network() string { return "tcp" }
func (a pipeAddr) String() string  { return string(a) }

// fakeConn is one end of a net.Pipe that reports a chosen remote address
// and counts how often it was closed.
type fakeConn struct {
	net.Conn
	remote net.Addr
	closed atomic.Int32
}

func newFakeConn(t *testing.T, remote string) *fakeConn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { client.Close() })
	var addr net.Addr = pipeAddr(remote)
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		addr = net.TCPAddrFromAddrPort(ap)
	}
	return &fakeConn{Conn: server, remote: addr}
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }

func (c *fakeConn) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

func (c *fakeConn) isClosed() bool { return c.closed.Load() > 0 }

// fakeListener hands out queued connections.
type fakeListener struct {
	conns     chan net.Conn
	closeOnce sync.Once
	done      chan struct{}
}

func newFakeListener() *fakeListener {
	return &fakeListener{conns: make(chan net.Conn, 64), done: make(chan struct{})}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *fakeListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *fakeListener) Addr() net.Addr { return pipeAddr("127.0.0.1:7443") }

type guardFixture struct {
	inner    *fakeListener
	guard    *guardedListener
	rejected atomic.Int32
}

func newGuardFixture(maxTotal, maxPerIP, maxPending int, setup time.Duration) *guardFixture {
	f := &guardFixture{inner: newFakeListener()}
	f.guard = &guardedListener{
		Listener:     f.inner,
		limiter:      newConnLimiter(maxTotal, maxPerIP),
		pending:      make(chan struct{}, maxPending),
		setupTimeout: setup,
		onReject:     func() { f.rejected.Add(1) },
	}
	return f
}

// offer queues a connection from remote and returns it.
func (f *guardFixture) offer(t *testing.T, remote string) *fakeConn {
	t.Helper()
	conn := newFakeConn(t, remote)
	f.inner.conns <- conn
	return conn
}

// accept returns the next admitted connection.
func (f *guardFixture) accept(t *testing.T) *guardedConn {
	t.Helper()
	conn, err := f.guard.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	guarded, ok := conn.(*guardedConn)
	if !ok {
		t.Fatalf("Accept returned %T", conn)
	}
	return guarded
}

// admitted offers a connection from remote and expects it to be admitted.
func (f *guardFixture) admitted(t *testing.T, remote string) *guardedConn {
	t.Helper()
	offered := f.offer(t, remote)
	got := f.accept(t)
	if got.Conn != offered {
		t.Fatalf("Accept returned another connection than the one from %s", remote)
	}
	return got
}

// refused offers a connection from remote followed by an admissible one
// from sentinel, and checks that Accept closes the first and returns the
// second.
func (f *guardFixture) refused(t *testing.T, remote, sentinel string) *guardedConn {
	t.Helper()
	before := f.rejected.Load()
	refused := f.offer(t, remote)
	admissible := f.offer(t, sentinel)
	got := f.accept(t)
	if got.Conn != admissible {
		t.Fatalf("connection from %s was admitted", remote)
	}
	if !refused.isClosed() {
		t.Fatalf("refused connection from %s was not closed", remote)
	}
	if f.rejected.Load() != before+1 {
		t.Fatalf("rejections = %d, want %d", f.rejected.Load(), before+1)
	}
	return got
}

func (f *guardFixture) counts() (total, pending int) {
	total, _ = f.guard.limiter.counts()
	return total, len(f.guard.pending)
}

func TestGuardedListenerPerIP(t *testing.T) {
	f := newGuardFixture(100, 2, 100, time.Minute)
	first := f.admitted(t, "192.0.2.1:1000")
	f.admitted(t, "192.0.2.1:1001")
	f.refused(t, "192.0.2.1:1002", "192.0.2.2:1000")

	f.admitted(t, "[2001:db8:1:1::1]:1000")
	f.admitted(t, "[2001:db8:1:1::2]:1000")
	f.refused(t, "[2001:db8:1:1:ffff::9]:1000", "[2001:db8:1:2::1]:1000")

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	f.admitted(t, "192.0.2.1:1003")
}

func TestGuardedListenerGlobal(t *testing.T) {
	f := newGuardFixture(2, 2, 100, time.Minute)
	first := f.admitted(t, "192.0.2.1:1000")
	f.admitted(t, "192.0.2.2:1000")

	refused := f.offer(t, "192.0.2.3:1000")
	acceptErr := make(chan error, 1)
	go func() {
		_, err := f.guard.Accept()
		acceptErr <- err
	}()
	waitFor(t, "refusal", func() bool { return f.rejected.Load() == 1 })
	if !refused.isClosed() {
		t.Fatal("connection above the global limit was not closed")
	}
	f.inner.Close()
	if err := <-acceptErr; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after close = %v, want net.ErrClosed", err)
	}

	first.Close()
	if total, _ := f.counts(); total != 1 {
		t.Fatalf("connections after close = %d, want 1", total)
	}
}

func TestGuardedListenerRejectsUnknownAddress(t *testing.T) {
	f := newGuardFixture(10, 10, 10, time.Minute)
	f.refused(t, "not-an-address", "192.0.2.1:1000")
	if total, pending := f.counts(); total != 1 || pending != 1 {
		t.Fatalf("counts = %d/%d, want 1/1", total, pending)
	}
}

func TestGuardedListenerPendingCap(t *testing.T) {
	f := newGuardFixture(100, 100, 2, time.Minute)
	first := f.admitted(t, "192.0.2.1:1000")
	second := f.admitted(t, "192.0.2.2:1000")

	refused := f.offer(t, "192.0.2.3:1000")
	next := make(chan net.Conn, 1)
	go func() {
		conn, _ := f.guard.Accept()
		next <- conn
	}()
	waitFor(t, "refusal", func() bool { return f.rejected.Load() == 1 })
	if !refused.isClosed() {
		t.Fatal("connection above the pending cap was not closed")
	}
	if total, pending := f.counts(); total != 2 || pending != 2 {
		t.Fatalf("counts = %d/%d, want 2/2: a refused connection must not keep a slot", total, pending)
	}

	if !first.established() {
		t.Fatal("established() = false on an open connection")
	}
	if total, pending := f.counts(); total != 2 || pending != 1 {
		t.Fatalf("counts after upgrade = %d/%d, want 2/1", total, pending)
	}
	f.offer(t, "192.0.2.4:1000")
	if conn := <-next; conn == nil {
		t.Fatal("connection below the pending cap was not admitted")
	}
	if total, pending := f.counts(); total != 3 || pending != 2 {
		t.Fatalf("counts = %d/%d, want 3/2", total, pending)
	}

	second.Close()
	first.Close()
	if total, pending := f.counts(); total != 1 || pending != 1 {
		t.Fatalf("counts after close = %d/%d, want 1/1", total, pending)
	}
}

func TestGuardedConnCloseIsIdempotent(t *testing.T) {
	f := newGuardFixture(10, 10, 10, time.Minute)
	held := f.admitted(t, "192.0.2.1:1000")
	conn := f.admitted(t, "192.0.2.1:1001")
	inner := conn.Conn.(*fakeConn)

	var closers sync.WaitGroup
	for range 8 {
		closers.Go(func() { _ = conn.Close() })
		closers.Go(func() { conn.established() })
	}
	closers.Wait()
	if total, pending := f.counts(); total != 1 || pending != 1 {
		t.Fatalf("counts = %d/%d, want 1/1 (only the other connection)", total, pending)
	}
	if got := inner.closed.Load(); got != 1 {
		t.Fatalf("underlying Close called %d times, want 1", got)
	}
	if conn.established() {
		t.Fatal("established() = true after Close")
	}
	held.Close()
	if total, pending := f.counts(); total != 0 || pending != 0 {
		t.Fatalf("counts = %d/%d, want 0/0", total, pending)
	}
}

func TestGuardedConnSetupTimeout(t *testing.T) {
	f := newGuardFixture(10, 10, 10, 100*time.Millisecond)
	slow := f.admitted(t, "192.0.2.1:1000")
	upgraded := f.admitted(t, "192.0.2.1:1001")
	if !upgraded.established() {
		t.Fatal("established() = false before the deadline")
	}

	waitFor(t, "setup deadline", func() bool { return slow.Conn.(*fakeConn).isClosed() })
	waitFor(t, "slot release", func() bool {
		total, pending := f.counts()
		return total == 1 && pending == 0
	})
	if slow.established() {
		t.Fatal("established() = true after the deadline fired")
	}
	time.Sleep(200 * time.Millisecond)
	if upgraded.Conn.(*fakeConn).isClosed() {
		t.Fatal("setup deadline closed an upgraded connection")
	}
}

func TestAddrKey(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want string
		ok   bool
	}{
		{&net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 1}, "192.0.2.7", true},
		{&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.7"), Port: 1}, "192.0.2.7", true},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:3:4:5:6"), Port: 1}, "2001:db8:1:2::", true},
		{&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 1, Zone: "eth0"}, "fe80::", true},
		{&net.TCPAddr{}, "", false},
		{pipeAddr("192.0.2.8:9"), "192.0.2.8", true},
		{pipeAddr("pipe"), "", false},
		{nil, "", false},
	}
	for _, tc := range cases {
		got, ok := addrKey(tc.addr)
		if ok != tc.ok {
			t.Errorf("addrKey(%v) ok = %v, want %v", tc.addr, ok, tc.ok)
			continue
		}
		if ok && got.String() != tc.want {
			t.Errorf("addrKey(%v) = %v, want %s", tc.addr, got, tc.want)
		}
	}
}
