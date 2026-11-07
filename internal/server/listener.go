package server

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// connSetupTimeout bounds the time from accepting a TCP connection to
// completing the WebSocket upgrade: the TLS handshake plus the single HTTP
// request. A connection still in setup when it expires is closed. Once the
// upgrade has succeeded the deadline no longer applies; the session's own
// handshake and idle timeouts take over.
const connSetupTimeout = 10 * time.Second

// guardedListener enforces the connection limits when a TCP connection is
// accepted, before any TLS processing:
//
//   - the global and per-IP limits of connLimiter, so a client over its
//     share cannot hold sockets, TLS state or goroutines;
//   - a cap on connections that have not completed the WebSocket upgrade
//     yet, which bounds concurrent TLS handshakes (each costs an
//     X25519MLKEM768 key exchange and an Ed25519 signature);
//   - a setup deadline, after which a connection that has not upgraded is
//     closed, however slowly it trickles bytes.
//
// A connection that would exceed a limit is closed at once with a TCP reset
// and never reaches TLS. Accept never blocks on a limit and does nothing per
// refused connection beyond closing it, so a flood of refused connections
// cannot stall the acceptance of others; errors from the wrapped listener
// are returned unchanged, so net/http's backoff for temporary errors still
// applies.
type guardedListener struct {
	net.Listener
	limiter      *connLimiter
	pending      chan struct{}
	setupTimeout time.Duration
	onReject     func()
}

// Accept returns the next connection that fits within the limits.
func (l *guardedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if guarded, ok := l.admit(conn); ok {
			return guarded, nil
		}
		l.onReject()
	}
}

// admit reserves a connection slot and a pending slot for conn, or closes
// conn if either is unavailable.
func (l *guardedListener) admit(conn net.Conn) (*guardedConn, bool) {
	key, ok := addrKey(conn.RemoteAddr())
	if !ok || !l.limiter.acquire(key) {
		discard(conn)
		return nil, false
	}
	select {
	case l.pending <- struct{}{}:
	default:
		l.limiter.release(key)
		discard(conn)
		return nil, false
	}
	guarded := &guardedConn{Conn: conn, key: key, limiter: l.limiter, pending: l.pending}
	guarded.mu.Lock()
	guarded.timer = time.AfterFunc(l.setupTimeout, func() { _ = guarded.Close() })
	guarded.mu.Unlock()
	return guarded, true
}

// discard closes a refused connection. Linger 0 makes the close a TCP
// reset, so the socket is freed immediately instead of lingering in
// TIME_WAIT on the server.
func discard(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = conn.Close()
}

// guardedConn is an accepted connection holding a slot in connLimiter and,
// until its WebSocket upgrade completes, a pending slot. Both are released
// exactly once, however many times Close is called.
type guardedConn struct {
	net.Conn
	key     netip.Addr
	limiter *connLimiter
	pending chan struct{}

	mu    sync.Mutex
	timer *time.Timer

	setupOnce sync.Once
	closeOnce sync.Once
	closeErr  error
}

// Close closes the connection and releases its slots. It is safe to call
// more than once and from several goroutines.
func (c *guardedConn) Close() error {
	c.closeOnce.Do(func() {
		c.stopTimer()
		c.closeErr = c.Conn.Close()
		c.endSetup()
		c.limiter.release(c.key)
	})
	return c.closeErr
}

// established ends the setup phase after a successful WebSocket upgrade:
// the setup deadline is cancelled and the pending slot freed. The
// connection slot is kept until Close. It reports false if the deadline
// had already fired or the connection was closed.
func (c *guardedConn) established() bool {
	if !c.stopTimer() {
		return false
	}
	c.endSetup()
	return true
}

func (c *guardedConn) stopTimer() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timer.Stop()
}

func (c *guardedConn) endSetup() {
	c.setupOnce.Do(func() { <-c.pending })
}

// guardedConnOf finds the guardedConn beneath conn, which net/http hands to
// its hooks wrapped in a *tls.Conn.
func guardedConnOf(conn net.Conn) (*guardedConn, bool) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	guarded, ok := conn.(*guardedConn)
	return guarded, ok
}

// trackConnState is the http.Server ConnState hook. A hijacked connection
// has completed the WebSocket upgrade (the handler is the only code that
// hijacks), so its setup phase ends there.
func trackConnState(conn net.Conn, state http.ConnState) {
	if state != http.StateHijacked {
		return
	}
	if guarded, ok := guardedConnOf(conn); ok {
		guarded.established()
	}
}

// addrKey derives the connection-limit key from a connection's remote
// address. Only the TCP peer address is used.
func addrKey(addr net.Addr) (netip.Addr, bool) {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		ip := tcp.AddrPort().Addr()
		if !ip.IsValid() {
			return netip.Addr{}, false
		}
		return limitKey(ip), true
	}
	if addr == nil {
		return netip.Addr{}, false
	}
	return clientKey(addr.String())
}
