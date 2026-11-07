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
//   - ReadHeaderTimeout and a small MaxHeaderBytes bound how long and how
//     much a client may send before its request is handled (slowloris and
//     memory exhaustion). No overall ReadTimeout/WriteTimeout is set, since
//     those deadlines would remain on hijacked WebSocket connections and cut
//     long-lived chats; per-connection liveness is handled at the WebSocket
//     layer.
//   - HTTP/2 is disabled (TLSNextProto is an empty map and Protocols allows
//     HTTP/1 only), because the WebSocket upgrade requires HTTP/1.1.
//   - ErrorLog discards everything. By default net/http logs messages such
//     as "http: TLS handshake error from 203.0.113.7:51234: ...", which
//     would write client IP addresses to the server log. The qchat server
//     must never record client IPs, so this output is dropped entirely.
func NewHTTPServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)

	return &http.Server{
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
}
