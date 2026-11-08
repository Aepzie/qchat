package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// WebSocketPath is the HTTP path of the qchat WebSocket endpoint.
const WebSocketPath = "/v1/ws"

// Subprotocol is the WebSocket subprotocol both sides must negotiate. A
// mismatch means the peer speaks a different protocol version, and the
// connection is refused.
const Subprotocol = "qchat.v1"

// DefaultReadLimit is the default maximum size in bytes of one incoming
// WebSocket message. Bounding message size protects against memory
// exhaustion by a malicious peer.
const DefaultReadLimit = 1 << 20

// Timeouts used when the caller's context has no earlier deadline.
const (
	defaultTCPDialTimeout   = 30 * time.Second
	defaultHandshakeTimeout = 60 * time.Second
)

// DialOptions configures Dial.
type DialOptions struct {
	// NetDialContext, if non-nil, opens the underlying TCP connection, for
	// example through a SOCKS5 proxy such as Tor. TLS always runs end to end
	// on top of it, so the proxy cannot read or modify the traffic. If nil,
	// a net.Dialer with a 30 second timeout is used.
	NetDialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// ReadLimit is the maximum size in bytes of one incoming message.
	// Zero or negative means DefaultReadLimit; there is no way to disable
	// the limit.
	ReadLimit int64
}

// Dial opens a WebSocket connection to wss://hostport/v1/ws and
// authenticates the server by its pinned public key fingerprint.
//
// hostport must be accepted by ValidateHostPort; otherwise an error wrapping
// ErrInvalidAddress is returned before any network activity. The TLS handshake
// must use TLS 1.3 with X25519MLKEM768, the server key must match pin, and
// the server must select Subprotocol; otherwise the connection is closed and
// an error is returned. A zero pin is rejected before any network activity.
//
// Hardening applied:
//
//   - Proxy is nil, so HTTP_PROXY/HTTPS_PROXY environment variables cannot
//     silently route traffic (and the destination name) through a proxy.
//   - Redirects are never followed.
//   - No cookies, no User-Agent header: nothing that identifies the client
//     software or links sessions together is sent.
//   - WebSocket compression is disabled. Compressing attacker-influenced
//     data together with secrets before encryption leaks information through
//     ciphertext lengths (the CRIME/BREACH class of attacks).
func Dial(ctx context.Context, hostport string, pin Fingerprint, opts DialOptions) (*websocket.Conn, error) {
	conn, _, err := DialWithState(ctx, hostport, pin, opts)
	return conn, err
}

// DialWithState is like [Dial] but also returns the state of the TLS
// connection the WebSocket runs on, from which [AuthBinding] derives the
// channel binding of an authentication proof. The returned state is a copy;
// its ExportKeyingMaterial method stays usable after DialWithState returns.
func DialWithState(ctx context.Context, hostport string, pin Fingerprint, opts DialOptions) (*websocket.Conn, tls.ConnectionState, error) {
	if pin.IsZero() {
		return nil, tls.ConnectionState{}, errNoPin
	}
	host, err := ValidateHostPort(hostport)
	if err != nil {
		return nil, tls.ConnectionState{}, err
	}

	endpoint := url.URL{Scheme: "wss", Host: host, Path: WebSocketPath}
	client := newPinnedHTTPClient(pin, opts.NetDialContext)
	defer client.CloseIdleConnections()

	conn, resp, err := websocket.Dial(ctx, endpoint.String(), &websocket.DialOptions{
		HTTPClient:      client,
		HTTPHeader:      http.Header{"User-Agent": []string{""}},
		Subprotocols:    []string{Subprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, tls.ConnectionState{}, fmt.Errorf("transport: dial %s: %w", host, err)
	}

	if conn.Subprotocol() != Subprotocol {
		_ = conn.Close(websocket.StatusPolicyViolation, "unsupported subprotocol")
		return nil, tls.ConnectionState{}, fmt.Errorf("transport: dial %s: server did not select subprotocol %q", host, Subprotocol)
	}
	if resp == nil || resp.TLS == nil || !resp.TLS.HandshakeComplete {
		_ = conn.Close(websocket.StatusInternalError, "")
		return nil, tls.ConnectionState{}, fmt.Errorf("transport: dial %s: no TLS state for the connection", host)
	}
	conn.SetReadLimit(effectiveReadLimit(opts.ReadLimit))
	return conn, *resp.TLS, nil
}

// newPinnedHTTPClient builds a single-use HTTP client whose every TLS
// connection is verified against pin.
func newPinnedHTTPClient(pin Fingerprint, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	if dial == nil {
		dialer := &net.Dialer{Timeout: defaultTCPDialTimeout, KeepAlive: 30 * time.Second}
		dial = dialer.DialContext
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		TLSClientConfig:       ClientTLSConfig(pin),
		TLSHandshakeTimeout:   defaultHandshakeTimeout,
		ResponseHeaderTimeout: defaultHandshakeTimeout,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		DisableCompression:    true,
		MaxIdleConns:          1,
		IdleConnTimeout:       time.Second,
	}
	return &http.Client{
		Transport: transport,
		// websocket.Dial applies Timeout to the opening handshake only, not
		// to the lifetime of the WebSocket connection.
		Timeout: defaultHandshakeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// effectiveReadLimit maps "unset" (zero) and invalid negative values to
// DefaultReadLimit. Negative values must not reach SetReadLimit, where -1
// would disable the limit entirely.
func effectiveReadLimit(limit int64) int64 {
	if limit <= 0 {
		return DefaultReadLimit
	}
	return limit
}

// Accept upgrades an incoming HTTP request to a qchat WebSocket connection.
// On failure it writes an HTTP error response and returns an error; the
// caller must not write to w afterwards.
//
// Requests are refused unless all of the following hold:
//
//   - The request arrived over TLS. Plaintext WebSocket connections are
//     never accepted, even by mistake (for example a misconfigured listener).
//   - The request carries no Origin header. qchat clients are not browsers
//     and never send one, whereas browsers always do. Rejecting every
//     Origin blocks cross-site WebSocket hijacking, where a web page the
//     user visits tries to open a connection to the server from inside
//     their browser.
//   - The client offers Subprotocol. Peers speaking another protocol, or
//     generic WebSocket clients, are turned away before the upgrade.
//
// readLimit is the maximum incoming message size; zero or negative means
// DefaultReadLimit. Compression is disabled (see Dial for why).
func Accept(w http.ResponseWriter, r *http.Request, readLimit int64) (*websocket.Conn, error) {
	if r.TLS == nil {
		http.Error(w, "TLS required", http.StatusUpgradeRequired)
		return nil, errors.New("transport: refusing WebSocket over plaintext connection")
	}
	if _, present := r.Header["Origin"]; present {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return nil, errors.New("transport: refusing WebSocket request with Origin header")
	}
	if !offersSubprotocol(r.Header, Subprotocol) {
		http.Error(w, "unsupported subprotocol", http.StatusBadRequest)
		return nil, fmt.Errorf("transport: client did not offer subprotocol %q", Subprotocol)
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{Subprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("transport: accept WebSocket: %w", err)
	}
	if conn.Subprotocol() != Subprotocol {
		_ = conn.Close(websocket.StatusPolicyViolation, "unsupported subprotocol")
		return nil, fmt.Errorf("transport: negotiated subprotocol is not %q", Subprotocol)
	}
	conn.SetReadLimit(effectiveReadLimit(readLimit))
	return conn, nil
}

// offersSubprotocol reports whether the Sec-WebSocket-Protocol header lists
// want. Subprotocol tokens are compared case-sensitively (RFC 6455, 4.1).
func offersSubprotocol(h http.Header, want string) bool {
	for _, line := range h.Values("Sec-WebSocket-Protocol") {
		for _, token := range strings.Split(line, ",") {
			if strings.TrimSpace(token) == want {
				return true
			}
		}
	}
	return false
}
