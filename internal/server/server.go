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
	"golang.org/x/time/rate"

	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/store/serverdb"
	"github.com/Aepzie/qchat/internal/transport"
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
	// Connections is the number of open accepted TCP connections, whether
	// still in the TLS handshake, sending the upgrade request or carrying
	// an established session.
	Connections int
	// PendingConnections is the number of open connections that have not
	// completed the WebSocket upgrade yet.
	PendingConnections int
	// TotalSessions counts every session accepted since the server started.
	TotalSessions uint64
	// RejectedConnections counts connections refused by a connection limit
	// or the pending-handshake cap, and requests refused because the server
	// was shutting down.
	RejectedConnections uint64
}

// Server is the qchat relay server. Create it with New and start it with
// Serve or ListenAndServe; a Server can be started only once.
//
// Privacy: the server never logs client IP addresses, identity IDs, frame
// contents or any other client-controlled string. Session events are logged
// at debug level only, identified by a random per-process session number.
type Server struct {
	cfg         Config
	tlsConfig   *tls.Config
	fingerprint transport.Fingerprint
	logger      *slog.Logger
	limiter     *connLimiter
	pending     chan struct{}
	db          *serverdb.DB

	setupTimeout     time.Duration
	handshakeTimeout time.Duration
	idleTimeout      time.Duration
	shutdownTimeout  time.Duration
	challengeTTL     time.Duration
	authRate         rate.Limit
	authBurst        int
	prekeyRate       rate.Limit
	prekeyBurst      int
	uploadRate       rate.Limit
	uploadBurst      int
	pruneInterval    time.Duration
	multiSendWait    time.Duration
	now              func() time.Time

	routesMu sync.Mutex
	routes   map[identity.ID]map[*session]struct{}

	queueBudget *byteBudget

	// sealedIP holds the per-address buckets of sealed sends and lookupIP
	// those of anonymous key and prekey lookups.
	sealedIP *ipBuckets
	lookupIP *ipBuckets

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
	fingerprint, err := transport.FingerprintOfTLS(cert)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Server{
		cfg:              cfg,
		tlsConfig:        transport.ServerTLSConfig(cert),
		fingerprint:      fingerprint,
		logger:           logger,
		limiter:          newConnLimiter(cfg.Limits.MaxConnections, cfg.Limits.MaxConnectionsPerIP),
		pending:          make(chan struct{}, cfg.Limits.MaxPendingHandshakes),
		setupTimeout:     connSetupTimeout,
		handshakeTimeout: cfg.Limits.HandshakeTimeout.Std(),
		idleTimeout:      cfg.Limits.idleTimeout(),
		shutdownTimeout:  shutdownTimeout,
		challengeTTL:     challengeTTL,
		authRate:         rate.Every(authInterval),
		authBurst:        authBurst,
		prekeyRate:       rate.Every(time.Hour / time.Duration(cfg.Limits.PrekeyRequestsPerHour)),
		prekeyBurst:      cfg.Limits.PrekeyRequestsPerHour,
		uploadRate:       rate.Every(uploadInterval),
		uploadBurst:      uploadBurst,
		pruneInterval:    pruneInterval,
		multiSendWait:    min(multiSendMaxWait, cfg.Limits.idleTimeout()/2),
		now:              time.Now,
		routes:           make(map[identity.ID]map[*session]struct{}),
		queueBudget:      newByteBudget(cfg.Limits.MaxTotalQueueBytes),
		sealedIP:         newIPBuckets(float64(cfg.Limits.SealedRecipientsPerMinutePerIP), SealedRecipientsBurstPerIP, maxIPBuckets),
		lookupIP:         newIPBuckets(float64(cfg.Limits.AnonymousLookupsPerHourPerIP)/60, AnonymousLookupsBurstPerIP, maxIPBuckets),
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

// Serve opens the configured database, then accepts TLS connections on ln
// until ctx is cancelled and shuts down gracefully: new connections are
// refused, open sessions are closed with WebSocket status 1001 (going
// away), and Serve waits for them, up to a bounded time, before closing the
// database. It returns nil after a shutdown triggered by ctx, and an error
// if the database cannot be opened or the listener fails. Serve takes
// ownership of ln and closes it.
//
// Only transport.WebSocketPath is served; every other path gets 404. Each
// connection carries a single request.
//
// Connection limits are enforced on ln itself, before TLS (see
// guardedListener): connections over limits.max_connections,
// limits.max_connections_per_ip or limits.max_pending_handshakes are reset
// immediately, and a connection that has not completed the WebSocket
// upgrade within connSetupTimeout of being accepted is closed.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if !s.started.CompareAndSwap(false, true) {
		_ = ln.Close()
		return errors.New("server: already started")
	}
	db, err := serverdb.Open(s.cfg.Database)
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("server: %w", err)
	}
	s.db = db
	defer s.closeDatabase()
	pruneCtx, stopPrune := context.WithCancel(context.Background())
	pruneDone := make(chan struct{})
	go s.pruneLoop(pruneCtx, pruneDone)
	defer func() {
		stopPrune()
		<-pruneDone
	}()
	s.mu.Lock()
	s.addr = ln.Addr()
	s.mu.Unlock()

	guarded := &guardedListener{
		Listener:     ln,
		limiter:      s.limiter,
		pending:      s.pending,
		setupTimeout: s.setupTimeout,
		onReject:     s.reject,
	}
	httpServer := transport.NewHTTPServer(ln.Addr().String(), http.HandlerFunc(s.handle), s.tlsConfig)
	httpServer.ConnState = trackConnState
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.ServeTLS(guarded, "", "") }()

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

// closeDatabase closes the database once every session has ended.
func (s *Server) closeDatabase() {
	if err := s.db.Close(); err != nil {
		s.logger.Error("cannot close database", "err", err)
	}
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
		PendingConnections:  len(s.pending),
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
//
// Connection limits are not checked here: they were applied when the
// connection was accepted, and since keep-alives are disabled every request
// has a connection, and its slot, of its own. Acquiring a second slot per
// request would count each connection twice.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != transport.WebSocketPath {
		http.NotFound(w, r)
		return
	}
	if s.isClosing() {
		s.reject()
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	conn, err := transport.Accept(w, r, int64(s.cfg.Limits.MaxFrameSize))
	if err != nil {
		// The error is deliberately not logged: it can quote request
		// headers, which are client-controlled.
		s.logger.Debug("websocket upgrade refused")
		return
	}

	binding, err := transport.AuthBinding(r.TLS)
	if err != nil {
		s.logger.Debug("no channel binding for connection")
		_ = conn.Close(websocket.StatusInternalError, "")
		return
	}

	sess := newSession(s, conn, binding)
	if key, ok := clientKey(r.RemoteAddr); ok {
		sess.ipKey = key
	}
	if !s.register(sess) {
		_ = conn.Close(websocket.StatusGoingAway, closeTextShutdown)
		return
	}
	defer s.unregister(sess)
	sess.run()
}

// reject counts a refused connection or request. Nothing about the client
// is logged.
func (s *Server) reject() {
	s.rejected.Add(1)
	s.logger.Debug("connection rejected")
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

// clientKey derives the connection-limit key from a "host:port" peer
// address. Only the TCP peer address is ever used: forwarding headers such
// as X-Forwarded-For are client-controlled and would let anyone bypass the
// per-IP limit.
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
