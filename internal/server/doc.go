// Package server implements the qchat relay server: configuration loading,
// connection limits and the per-connection session protocol.
//
// # Session protocol (wire version 1, phase 1)
//
//  1. The client opens a WebSocket over pinned TLS (see package transport).
//     It must send a binary message holding a Hello frame within
//     limits.handshake_timeout, or the connection is closed.
//  2. The server negotiates a version and answers with a Welcome frame that
//     echoes the Hello's frame ID. If no common version exists it sends an
//     Error frame with code UnsupportedVersion and closes.
//  3. The client then sends Ping frames; each is answered with a Pong that
//     carries the same frame ID and nonce. The server does not send pings.
//  4. A session that sends nothing for 2*ping_interval+10s is closed.
//  5. Text messages close the session with status 1003 (unsupported data).
//     Malformed, unknown or unexpected frames, including a second Hello,
//     produce an Error frame (BadRequest or the code chosen by
//     protocol.ErrorCodeFor) and a close with status 1008.
//  6. Each session has a token bucket (frames_per_second, burst). Exceeding
//     it produces an Error frame with code RateLimited and a close with
//     status 1008.
//
// Error frames and WebSocket close reasons are fixed ASCII strings; they
// never echo client data.
//
// # Connection limits
//
// limits.max_connections, limits.max_connections_per_ip and
// limits.max_pending_handshakes are enforced when a TCP connection is
// accepted, before the TLS handshake; a connection over a limit is reset
// at once. A connection must complete TLS and the WebSocket upgrade within
// 10 seconds of being accepted, and carries exactly one HTTP request.
//
// # Privacy
//
// The server never writes client IP addresses, frame bodies or any other
// client-controlled string to its log. Addresses are kept in memory only
// while a connection is open, to enforce the per-IP connection limit.
// Session events are logged at debug level with a random session number
// that is meaningless outside the running process.
package server
