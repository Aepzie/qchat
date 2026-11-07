// Package server implements the qchat relay server: configuration loading,
// connection limits, the per-connection session protocol, identity
// registration, authentication and message routing.
//
// # Session protocol (wire version 1)
//
//  1. The client opens a WebSocket over pinned TLS (see package transport).
//     It must send a binary message holding a Hello frame within
//     limits.handshake_timeout, or the connection is closed.
//  2. The server negotiates a version and answers with a Welcome frame that
//     echoes the Hello's frame ID. If no common version exists it sends an
//     Error frame with code UnsupportedVersion and closes.
//  3. The client then sends requests; every response echoes the request's
//     frame ID. Ping is answered with a Pong carrying the same nonce. The
//     server does not send pings.
//  4. A session that sends nothing for 2*ping_interval+10s is closed.
//  5. Text messages close the session with status 1003 (unsupported data).
//  6. Each session has a token bucket (frames_per_second, burst). Exceeding
//     it produces an Error frame with code RateLimited and a close with
//     status 1008.
//
// # Identities, authentication and routing
//
// A session starts unauthenticated. It may send Ping, Register and
// AuthBegin; KeyRequest and Send require authentication.
//
//   - Register{Bundle, Invite} verifies the bundle's self-signature and
//     stores it. With registration = "open" any valid bundle is accepted;
//     with "invite" a new ID needs a valid unused invite code, while a
//     known ID may update its bundle without one. The identical bundle is
//     accepted again, a higher serial replaces the stored bundle, anything
//     else fails with Conflict. Register is also allowed after
//     authentication, so a client can rotate its keys.
//   - AuthBegin{ID} answers with an AuthChallenge carrying 32 fresh random
//     bytes. A session has at most one outstanding challenge: a new
//     AuthBegin replaces it. The challenge expires after 30 seconds and is
//     consumed by the next AuthProof, whatever its outcome.
//   - AuthProof{Sig} must be a signature, made with identity.SignAuth, over
//     this relay's TLS fingerprint, the nonce and the ID. On success the
//     session is bound to that ID for its lifetime and answered with AuthOK.
//   - KeyRequest{ID} returns the stored bundle exactly as registered.
//   - Send{To, Payload} pushes Deliver{From, Payload} to every live
//     authenticated session of To, where From is the sender's authenticated
//     ID, and answers SendResult Delivered if at least one session took the
//     frame, RecipientOffline otherwise. Payloads are never stored.
//
// SendResult is a presence oracle: any authenticated user can learn whether
// a registered ID is online right now by sending it a message and reading
// Delivered or RecipientOffline. This is accepted until Phase 3, when the
// relay queues messages for offline recipients and stops telling the two
// cases apart.
//
// An identity may hold at most limits.max_sessions_per_identity
// authenticated sessions at once. An AuthProof beyond that is answered with
// a fatal RateLimited error and the session is closed unauthenticated.
//
// Register and AuthBegin also draw from a second, per-session token bucket
// (5 per minute, burst 5), which bounds the signature checks and database
// writes a session can cause.
//
// Each session has a single writer goroutine fed by a queue bounded to 64
// frames and to limits.max_queue_bytes of encoded frames. All queues
// together are bounded by limits.max_total_queue_bytes; bytes are released
// when a frame has been written or its session has ended. Responses to the
// session's own requests are never dropped: they wait for room in the
// queue and in both byte budgets. A Deliver pushed by another session never
// waits: if it does not fit, that delivery is dropped and, if no other
// session of the recipient took it, reported as RecipientOffline.
//
// # Fatal and non-fatal errors
//
// Errors caused by the request's content or by relay state are answered
// with an Error frame and the session continues:
//
//   - Unauthorized: KeyRequest or Send before authentication;
//   - NotFound: AuthBegin, KeyRequest or Send naming an unknown ID;
//   - RegistrationDenied: a new ID without a valid invite code;
//   - Conflict: a different bundle for a known ID without a higher serial;
//   - BadRequest: a Register bundle that does not verify, or Send to the
//     sender's own ID;
//   - TooLarge: a Send payload above limits.max_message_size;
//   - RateLimited: Register or AuthBegin over the per-session bucket;
//   - Internal: a database failure.
//
// Protocol violations are answered with an Error frame followed by a close
// with status 1008:
//
//   - BadRequest: malformed frames or bodies, unknown frame types, frame
//     types only the server sends, a second Hello, and AuthBegin or
//     AuthProof on an already authenticated session;
//   - UnsupportedVersion: no common wire version, or a frame of another
//     version;
//   - RateLimited: the per-session frame bucket is exhausted;
//   - Unauthorized: AuthProof without an outstanding challenge, after it
//     expired, or with a signature that does not verify;
//   - RateLimited: an AuthProof for an identity that already holds
//     limits.max_sessions_per_identity sessions.
//
// A message larger than limits.max_frame_size closes the session with
// status 1009 without an Error frame.
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
// The server never writes client IP addresses, identity IDs, payloads,
// frame bodies or any other client-controlled string to its log. Addresses
// are kept in memory only while a connection is open, to enforce the per-IP
// connection limit; IDs of authenticated sessions only while they are
// connected, to route messages. The database holds identity bundles and
// invite code hashes, never messages.
// Session events are logged at debug level with a random session number
// that is meaningless outside the running process.
package server
