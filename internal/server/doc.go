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
// AuthBegin, or instead sealed sends (see Sealed sender); KeyRequest,
// PrekeyUpload, PrekeyRequest, Send, SendMulti, SetAccessKey and Ack
// require authentication.
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
//     draining another user's one-time prekeys. The default of 120 per
//     hour leaves room for a client joining a group to set up pairwise
//     sessions with its members.
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
//     recipients at once, as group messaging needs. The payload is stored
//     once, with one queue row per recipient that refers to it, and each
//     copy is pushed as an ordinary Deliver with its own queue ID; the
//     Deliver frame is encoded only for recipients with a live session.
//     The request succeeds partially: an unknown recipient or one whose
//     queue is full gets no copy but does not affect the others, and the
//     answer SendMultiResult{Status: Accepted, Failed, Reasons} lists those
//     recipients with NotFound or QueueFull for each. This tells the sender
//     which of the IDs it named are unknown or have a full queue, which a
//     KeyRequest or a Send to each of them would reveal as well. Each copy
//     counts toward its recipient's queue limits with the full payload
//     size. The payload size times the number of recipients may be at most
//     64 MiB, otherwise the request fails with TooLarge. The request counts
//     as one frame toward the frame bucket and spends one token per
//     recipient from a separate per-session bucket of
//     limits.multi_recipients_per_minute (burst 512). When that bucket
//     lacks the tokens, the session waits for them for at most 10 seconds
//     (or half the idle timeout) if they arrive by then, and otherwise
//     answers a non-fatal RateLimited at once and stores nothing.
//   - After AuthOK the session pushes the identity's stored messages in
//     queue order, at most 32 awaiting acknowledgement at a time; each Ack
//     lets it push the next one. Messages that arrive while the backlog is
//     being pushed are delivered live and not pushed again by the backlog.
//   - Ack{QueueID} deletes the message if it was stored for the session's
//     identity; acknowledging anything else does nothing. Ack has no
//     response. A message that is not acknowledged is pushed again after the
//     identity's next authentication, so clients must tolerate duplicates.
//   - A stored message expires undelivered_ttl after it was stored,
//     rounded up to the next full hour, sealed and identified alike.
//   - Every 10 minutes, and when the server starts, expired messages are
//     deleted. Expired messages are never delivered, even before that.
//
// Stored messages are ciphertext the relay cannot read. The sender ID of a
// message sent on an authenticated session is stored alongside, because the
// recipient needs it; sealed messages (below) are stored without one.
//
// # Sealed sender
//
// A session that completed the handshake and never sent Register,
// AuthBegin or AuthProof may send SealedSend{To, AccessProof, Payload} and
// SealedSendMulti{Entries, Payload}. The first sealed frame makes the
// session anonymous for good: Register and AuthBegin then close it with a
// fatal BadRequest, and a sealed frame on a session that registered or
// began authentication is closed the same way, so a sealed message and an
// identity are never seen on one connection. KeyRequest and PrekeyRequest
// carrying an AccessProof are anonymous lookups under the same rules.
//
//   - SetAccessKey{Verifier, AllowUnidentified} (authenticated sessions
//     only, sharing the Register/AuthBegin bucket) stores the SHA-256 hash
//     of the verifier of the identity's access key, replacing the previous
//     one, and answers AccessKeySet. An all-zero verifier is malformed.
//   - A sealed send is accepted for a recipient whose stored hash equals
//     the SHA-256 of the AccessProof (compared in constant time) or that
//     allows unidentified senders. Every other case, an unknown recipient
//     included, is NotFound: Error NotFound for SealedSend, a NotFound
//     entry in the SendMultiResult of SealedSendMulti. Each recipient costs
//     one lookup, one hash and one comparison whatever the outcome.
//     QueueFull is reported only after access was granted.
//   - An anonymous lookup is answered like an identified one if its proof
//     grants access to the ID in the same way, and NotFound otherwise.
//   - The payload is stored with a NULL sender and pushed as
//     Deliver{From: 32 zero bytes, Payload, QueueID}, live and from the
//     backlog alike.
//   - Each recipient spends one token from a per-session bucket of
//     limits.sealed_recipients_per_minute (burst 512). After the access
//     check, each granted recipient spends one token from a bucket shared
//     by all anonymous sessions of the client's IPv4 address or IPv6 /64,
//     of limits.sealed_recipients_per_minute_per_ip (burst 1024), and each
//     refused one a token from the session's refusal budget (burst 256,
//     256 per minute), so junk proofs never drain the shared per-address
//     bucket. Missing tokens are waited for like those of SendMulti, else
//     the request is answered RateLimited and nothing is stored.
//   - An anonymous lookup spends one token of the session's
//     limits.prekey_requests_per_hour bucket and, after the check, one of
//     the per-address bucket of limits.anonymous_lookups_per_hour_per_ip
//     (burst 120) if granted or one of the refusal budget if refused.
//   - The per-address buckets are held in memory only while not full, at
//     most 65536 at once per kind.
//   - limits.max_message_size, the 64 MiB fan-out cap and the recipients'
//     queue limits apply as for Send and SendMulti. Sealed messages may in
//     addition take at most limits.max_queued_sealed_messages rows and
//     half of limits.max_queued_bytes of a recipient's queue.
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
//   - Unauthorized: KeyRequest or PrekeyRequest without an AccessProof,
//     PrekeyUpload, Send, SendMulti, SetAccessKey or Ack before
//     authentication (on anonymous sessions too);
//   - NotFound: AuthBegin, KeyRequest or Send naming an unknown ID,
//     PrekeyRequest for an ID without an unexpired signed prekey, or a
//     SealedSend or anonymous lookup without access to its recipient;
//   - RegistrationDenied: a new ID without a valid invite code;
//   - Conflict: a different bundle for a known ID without a higher serial;
//   - BadRequest: a Register bundle or uploaded prekey that does not verify,
//     or Send or SendMulti to the sender's own ID;
//   - TooLarge: a Send, SendMulti, SealedSend or SealedSendMulti payload
//     above limits.max_message_size, or a SendMulti or SealedSendMulti
//     whose payload size times recipient count exceeds 64 MiB;
//   - QueueFull: a Send or SealedSend to a recipient whose stored messages
//     reached limits.max_queued_messages or limits.max_queued_bytes, or
//     for a SealedSend the sealed share of them;
//   - RateLimited: Register, AuthBegin, SetAccessKey, PrekeyUpload or
//     PrekeyRequest over its per-session bucket, or SendMulti,
//     SealedSend, SealedSendMulti or an anonymous lookup whose tokens do
//     not arrive in time;
//   - Internal: a database failure.
//
// Protocol violations are answered with an Error frame followed by a close
// with status 1008:
//
//   - BadRequest: malformed frames or bodies, unknown frame types, frame
//     types only the server sends, a second Hello, AuthBegin or AuthProof
//     on an already authenticated session, Register, AuthBegin or
//     AuthProof on an anonymous session, and SealedSend, SealedSendMulti
//     or a KeyRequest or PrekeyRequest with an AccessProof on a session
//     that registered or began authentication;
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
// connection limit, and while a sealed sender bucket is not full; IDs of
// authenticated sessions only while they are connected, to route messages.
// The database holds identity bundles, access key verifiers, prekeys,
// invite code hashes and, until they are acknowledged or expire, end-to-end
// encrypted messages with their recipient IDs and, unless they were sealed,
// their sender IDs; it holds no addresses and no delivery or read times.
// Session events are logged at debug level with a random session number
// that is meaningless outside the running process.
package server
