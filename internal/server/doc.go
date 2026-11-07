// Package server implements the qchat relay server: configuration loading,
// connection limits, the per-connection session protocol, identity
// registration, authentication, prekey distribution, message routing and
// offline delivery.
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
// AuthBegin; KeyRequest, PrekeyUpload, PrekeyRequest, Send, SendMulti and
// Ack require authentication.
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
//     this relay's TLS fingerprint, the nonce, the ID and the TLS exporter
//     channel binding of this connection (transport.AuthBinding), so a proof
//     made on one TLS connection is useless on any other. On success the
//     session is bound to that ID for its lifetime and answered with AuthOK.
//   - KeyRequest{ID} returns the stored bundle exactly as registered.
//
// # Prekeys
//
//   - PrekeyUpload{SignedPrekey, OneTimePrekeys} verifies every prekey with
//     package prekey against the session identity's stored bundle (owner,
//     signature and, for the signed prekey, validity period). If any prekey
//     fails, the upload is answered with BadRequest and nothing is stored.
//     The relay keeps one signed prekey per identity, the one expiring last,
//     and up to 200 one-time prekeys; key IDs already stored and prekeys
//     beyond the cap are ignored. The answer is PrekeyStatus with the number
//     of one-time prekeys left and the signed prekey's expiry (0 if none).
//     An empty upload only asks for the status. Uploads draw from a
//     per-session token bucket (burst 10, then one per minute), because each
//     can cost 101 signature verifications.
//   - PrekeyRequest{ID} answers PrekeyResponse{Bundle, SignedPrekey,
//     OneTimePrekey}. The oldest one-time prekey is deleted in the same
//     transaction, so each is handed out exactly once; once none is left the
//     field is omitted. NotFound means the ID is unknown or has no unexpired
//     signed prekey. Requests draw from a per-session token bucket of
//     limits.prekey_requests_per_hour (burst of the same size), which slows
//     draining another user's one-time prekeys.
//
// # Messages and offline delivery
//
//   - Send{To, Payload} stores the payload for the registered recipient To
//     for undelivered_ttl, then pushes Deliver{From, Payload, QueueID} to
//     every live authenticated session of To, where From is the sender's
//     authenticated ID. It answers SendResult Accepted whether or not To is
//     online, so the answer reveals nothing about presence. If To already
//     has limits.max_queued_messages messages or limits.max_queued_bytes
//     payload bytes stored, the Send fails with QueueFull and nothing is
//     stored or pushed.
//   - SendMulti{To, Payload} does the same for up to 256 distinct
//     recipients at once, as group messaging needs: one copy of the payload
//     is stored per recipient, each with its own queue ID, and pushed as an
//     ordinary Deliver. All copies are stored in one transaction, so either
//     every recipient gets the message or none does: an unknown recipient
//     fails the request with NotFound and a full queue with QueueFull,
//     neither naming the recipient. The request counts as one send per
//     recipient: each copy counts toward its recipient's queue limits, and
//     the request spends one token of the frame bucket per recipient. When
//     the bucket lacks the extra tokens the session waits for them at the
//     sustained rate for at most 10 seconds (or half the idle timeout),
//     then answers a non-fatal RateLimited and stores nothing.
//   - After AuthOK the session pushes the identity's stored messages in
//     queue order, at most 32 awaiting acknowledgement at a time; each Ack
//     lets it push the next one. Messages that arrive while the backlog is
//     being pushed are delivered live and not pushed again by the backlog.
//   - Ack{QueueID} deletes the message if it was stored for the session's
//     identity; acknowledging anything else does nothing. Ack has no
//     response. A message that is not acknowledged is pushed again after the
//     identity's next authentication, so clients must tolerate duplicates.
//   - Every 10 minutes, and when the server starts, expired messages are
//     deleted. Expired messages are never delivered, even before that.
//
// Stored messages are ciphertext the relay cannot read. The sender ID is
// stored alongside, because the recipient needs it; hiding it from the
// relay (sealed sender) is left to a later phase.
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
// waits: if it does not fit, that delivery is dropped; the message stays
// stored and is pushed again after the recipient's next authentication.
// Stored messages pushed after authentication are queued like responses.
//
// # Fatal and non-fatal errors
//
// Errors caused by the request's content or by relay state are answered
// with an Error frame and the session continues:
//
//   - Unauthorized: KeyRequest, PrekeyUpload, PrekeyRequest, Send, SendMulti
//     or Ack before authentication;
//   - NotFound: AuthBegin, KeyRequest, Send or SendMulti naming an unknown
//     ID, or PrekeyRequest for an ID without an unexpired signed prekey;
//   - RegistrationDenied: a new ID without a valid invite code;
//   - Conflict: a different bundle for a known ID without a higher serial;
//   - BadRequest: a Register bundle or uploaded prekey that does not verify,
//     or Send or SendMulti to the sender's own ID;
//   - TooLarge: a Send or SendMulti payload above limits.max_message_size;
//   - QueueFull: a Send or SendMulti to a recipient whose stored messages
//     reached limits.max_queued_messages or limits.max_queued_bytes;
//   - RateLimited: Register, AuthBegin, PrekeyUpload or PrekeyRequest over
//     its per-session bucket, or SendMulti whose extra frame tokens do not
//     arrive in time;
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
// connected, to route messages. The database holds identity bundles,
// prekeys, invite code hashes and, until they are acknowledged or expire,
// end-to-end encrypted messages with their sender and recipient IDs; it
// holds no addresses and no delivery or read times.
// Session events are logged at debug level with a random session number
// that is meaningless outside the running process.
package server
