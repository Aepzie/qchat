package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/craguS/qchat/internal/transport"
)

// Timeouts that are not part of the configuration file.
const (
	// writeTimeout bounds every frame write, so a client that stops reading
	// cannot pin a session goroutine and its buffers forever.
	writeTimeout = 10 * time.Second
	// shutdownTimeout bounds a graceful shutdown. Closing a WebSocket waits
	// at most 10 seconds for the peer, so this leaves some slack.
	shutdownTimeout = 15 * time.Second
)

// Stats is a snapshot of server counters. It contains no per-client data.
type Stats struct {
	// ActiveSessions is the number of upgraded WebSocket sessions.
	ActiveSessions int
	// Connections is the number of connection slots in use, including
	// requests that have not completed the WebSocket upgrade yet.
	Connections int
	// TotalSessions counts every session accepted since the server started.
	TotalSessions uint64
	// RejectedConnections counts requests refused by a connection limit or
	// because the server was shutting down.
	RejectedConnections uint64
}

// Server is the qchat relay server. Create it with New and start it with
// Serve or ListenAndServe; a Server can be started only once.
//
// Privacy: the server never logs client IP addresses, frame contents or
// any other client-controlled string. Session events are logged at debug
// level only, identified by a random per-process session number.
type Server struct {
	cfg       Config
	tlsConfig *tls.Config
	logger    *slog.Logger
	limiter   *connLimiter

	handshakeTimeout time.Duration
	idleTimeout      time.Duration
	shutdownTimeout  time.Duration

	started  atomic.Bool
	total    atomic.Uint64
	rejected atomic.Uint64

	mu       sync.Mutex
	closing  bool
	addr     net.Addr
	sessions map[*session]struct{}
	wg       sync.WaitGroup
}

// New validates cfg and returns a Server that presents cert. A nil logger
// discards all log output.
func New(cfg Config, cert tls.Certificate, logger *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("server: TLS certificate chain is empty")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Server{
		cfg:              cfg,
		tlsConfig:        transport.ServerTLSConfig(cert),
		logger:           logger,
		limiter:          newConnLimiter(cfg.Limits.MaxConnections, cfg.Limits.MaxConnectionsPerIP),
		handshakeTimeout: cfg.Limits.HandshakeTimeout.Std(),
		idleTimeout:      cfg.Limits.idleTimeout(),
		shutdownTimeout:  shutdownTimeout,
		sessions:         make(map[*session]struct{}),
	}, nil
}

// ListenAndServe listens on the configured address and calls Serve.
func (s *Server) ListenAndServe(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("server: listen: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts TLS connections on ln until ctx is cancelled, then shuts
// down gracefully: new connections are refused, open sessions are closed
// with WebSocket status 1001 (going away), and Serve waits for them, up to
// a bounded time. It returns nil after a shutdown triggered by ctx, and an
// error if the listener fails. Serve takes ownership of ln and closes it.
//
// Only transport.WebSocketPath is served; every other path gets 404.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if !s.started.CompareAndSwap(false, true) {
		_ = ln.Close()
		return errors.New("server: already started")
	}
	s.mu.Lock()
	s.addr = ln.Addr()
	s.mu.Unlock()

	httpServer := transport.NewHTTPServer(ln.Addr().String(), http.HandlerFunc(s.handle), s.tlsConfig)
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.ServeTLS(ln, "", "") }()

	s.logger.Info("server listening", "port", portOf(ln.Addr()))

	select {
	case err := <-serveErr:
		s.shutdown(httpServer)
		return fmt.Errorf("server: serve: %w", err)
	case <-ctx.Done():
	}

	s.logger.Info("server shutting down")
	s.shutdown(httpServer)
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server: serve: %w", err)
	}
	s.logger.Info("server stopped")
	return nil
}

// Addr returns the listening address, or nil before Serve has started.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// Stats returns a snapshot of the server counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	active := len(s.sessions)
	s.mu.Unlock()
	connections, _ := s.limiter.counts()
	return Stats{
		ActiveSessions:      active,
		Connections:         connections,
		TotalSessions:       s.total.Load(),
		RejectedConnections: s.rejected.Load(),
	}
}

// shutdown stops the HTTP server and closes every session, waiting at most
// s.shutdownTimeout before closing the remaining connections abruptly.
func (s *Server) shutdown(httpServer *http.Server) {
	s.mu.Lock()
	s.closing = true
	open := make([]*session, 0, len(s.sessions))
	for sess := range s.sessions {
		open = append(open, sess)
	}
	s.mu.Unlock()

	for _, sess := range open {
		go sess.terminate(reasonShutdown, websocket.StatusGoingAway, closeTextShutdown)
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		_ = httpServer.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-ctx.Done():
	}
	s.logger.Warn("shutdown timed out, closing remaining sessions")
	for _, sess := range open {
		_ = sess.conn.CloseNow()
	}
	<-done
}

// handle serves one HTTP request.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != transport.WebSocketPath {
		http.NotFound(w, r)
		return
	}

	key, ok := clientKey(r.RemoteAddr)
	if !ok || s.isClosing() || !s.limiter.acquire(key) {
		s.rejected.Add(1)
		s.logger.Debug("connection rejected")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer s.limiter.release(key)

	conn, err := transport.Accept(w, r, int64(s.cfg.Limits.MaxFrameSize))
	if err != nil {
		// The error is deliberately not logged: it can quote request
		// headers, which are client-controlled.
		s.logger.Debug("websocket upgrade refused")
		return
	}

	sess := newSession(s, conn)
	if !s.register(sess) {
		_ = conn.Close(websocket.StatusGoingAway, closeTextShutdown)
		return
	}
	defer s.unregister(sess)
	sess.run()
}

func (s *Server) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

// register adds sess to the set of open sessions, unless the server is
// shutting down. Checking s.closing under the same lock as wg.Add ensures
// that no session is added once shutdown has started waiting.
func (s *Server) register(sess *session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.sessions[sess] = struct{}{}
	s.wg.Add(1)
	s.total.Add(1)
	return true
}

func (s *Server) unregister(sess *session) {
	s.mu.Lock()
	delete(s.sessions, sess)
	s.mu.Unlock()
	s.wg.Done()
}

// clientKey derives the connection-limit key from r.RemoteAddr. Only the
// TCP peer address is used: forwarding headers such as X-Forwarded-For are
// client-controlled and would let anyone bypass the per-IP limit.
func clientKey(remoteAddr string) (netip.Addr, bool) {
	addrPort, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return limitKey(addrPort.Addr()), true
}

// portOf returns the port of a listener address, so the address itself
// (which may be a specific interface IP) does not end up in the log.
func portOf(addr net.Addr) int {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.Port
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return n
}
