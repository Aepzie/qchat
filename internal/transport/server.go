package transport

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"time"
)

// Server limits. WebSocket clients send one small upgrade request, so the
// header limits can be tight.
const (
	serverReadHeaderTimeout = 10 * time.Second
	serverIdleTimeout       = 60 * time.Second
	serverMaxHeaderBytes    = 8 << 10
)

// NewHTTPServer returns an *http.Server for the qchat endpoint, configured
// for TLS with tlsConfig (normally from ServerTLSConfig). Start it with
// ServeTLS(listener, "", "") or ListenAndServeTLS("", ""): the certificate
// comes from tlsConfig, so the file arguments are left empty.
//
// Hardening applied:
//
//   - HTTP keep-alives are disabled. A legitimate client sends exactly one
//     request per connection, the WebSocket upgrade, so every other
//     response (404, 503, a refused upgrade) closes the connection. This
//     stops a client from parking idle TLS connections between requests.
//     IdleTimeout is still set, as a backstop.
//   - ReadHeaderTimeout and a small MaxHeaderBytes bound how long and how
//     much a client may send before its request is handled (slowloris and
//     memory exhaustion). net/http also applies ReadHeaderTimeout to the
//     TLS handshake. No overall ReadTimeout/WriteTimeout is set, since
//     those deadlines would remain on hijacked WebSocket connections and
//     cut long-lived chats.
//   - HTTP/2 is disabled (TLSNextProto is an empty map and Protocols allows
//     HTTP/1 only), because the WebSocket upgrade requires HTTP/1.1.
//   - ErrorLog discards everything. By default net/http logs messages such
//     as "http: TLS handshake error from 203.0.113.7:51234: ...", which
//     would write client IP addresses to the server log. The qchat server
//     must never record client IPs, so this output is dropped entirely.
//
// What this function cannot do is left to the caller, which owns the
// listener and the handler: limiting the number of connections (overall,
// per client and still in the TLS handshake), bounding the whole time from
// accept to upgrade, and detecting dead WebSocket sessions. Neither
// net/http nor the WebSocket library does the last one by itself; the
// qchat server closes sessions that stop sending keepalives.
func NewHTTPServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)

	srv := &http.Server{
		Addr:                         addr,
		Handler:                      handler,
		TLSConfig:                    tlsConfig,
		ReadHeaderTimeout:            serverReadHeaderTimeout,
		IdleTimeout:                  serverIdleTimeout,
		MaxHeaderBytes:               serverMaxHeaderBytes,
		TLSNextProto:                 map[string]func(*http.Server, *tls.Conn, http.Handler){},
		Protocols:                    protocols,
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     log.New(io.Discard, "", 0),
	}
	srv.SetKeepAlivesEnabled(false)
	return srv
}
