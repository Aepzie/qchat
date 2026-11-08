// Package protocol defines the wire format spoken between qchat clients and
// the qchat relay server.
//
// # Transport and framing
//
// Every WebSocket binary message carries exactly one [Frame]. A frame is a
// CBOR (RFC 8949) map with small integer keys:
//
//	key 1  Version  unsigned int  wire version, always present
//	key 2  Type     unsigned int  frame type (see [FrameType]), always present
//	key 3  ID       unsigned int  request/response correlation, omitted when 0
//	key 4  Body     byte string   CBOR-encoded type-specific body, omitted when empty
//
// The body is itself a CBOR map with integer keys, wrapped in a byte string so
// that the outer frame can be parsed, size-checked and routed without
// understanding the body. An encoded frame never exceeds [MaxFrameSize] bytes.
//
// # Versioning and crypto-agility
//
// Every frame carries its wire version. The version identifies not only the
// layout of frames and bodies but also, in later phases, the complete set of
// cryptographic algorithms in use. A future Version 2 can therefore replace
// algorithms wholesale without ambiguity: peers negotiate a version once,
// during the [Hello]/[Welcome] handshake (see [Negotiate]), and every
// subsequent frame states which version it was produced under.
//
// Unknown or unsupported versions are rejected with [ErrUnsupportedVersion];
// they are never guessed at or partially interpreted. Key 1 holding the
// version as an unsigned integer is the single invariant that every future
// version must preserve, so a receiver can always tell "a version I do not
// speak" apart from "garbage".
//
// # Strict decoding
//
// Frames arrive from the network and, on the server, from unauthenticated
// peers, so the decoder is deliberately unforgiving:
//
//   - the input size is checked against [MaxFrameSize] before any parsing;
//   - duplicate map keys, indefinite-length items, CBOR tags, invalid UTF-8,
//     unknown fields and trailing bytes are all errors;
//   - nesting depth and container sizes are bounded, so hostile input cannot
//     cause unbounded allocation or deep recursion;
//   - only the canonical (Core Deterministic, RFC 8949 Section 4.2.1) encoding
//     of a value is accepted. Every valid frame and body therefore has exactly
//     one byte representation, which rules out malleability, and every body
//     field must be present.
//
// Strictness removes whole classes of parser-differential and smuggling bugs:
// two implementations either agree on the exact meaning of a message or one of
// them rejects it. Malformed input yields an error wrapping [ErrMalformed];
// the decoder never panics.
//
// # Message flow
//
// A session starts with the [Hello]/[Welcome] handshake. Afterwards either
// side may send [Ping] at any time and the peer answers with [Pong]. A
// response always carries the frame ID of the request it answers, and any
// request may instead be answered with an [ErrorBody] carrying that ID.
//
// Identities are named by an ID of [IDSize] bytes derived from their public
// identity bundle. The client uses the following exchanges:
//
//	Registration (allowed before authentication)
//	  C→S  Register{Bundle, Invite}  self-signed bundle, optional invite code
//	  S→C  Registered{}              or Error RegistrationDenied / Conflict
//
//	Challenge-response authentication
//	  C→S  AuthBegin{ID}             the identity to authenticate as
//	  S→C  AuthChallenge{Nonce}      NonceSize fresh random bytes
//	  C→S  AuthProof{Sig}            signature binding the relay, nonce and ID
//	  S→C  AuthOK{}                  or Error Unauthorized
//
//	Key lookup (requires authentication, or an access proof)
//	  C→S  KeyRequest{ID, AccessProof}
//	                                 AccessProof absent when authenticated,
//	                                 required on an anonymous connection
//	  S→C  KeyResponse{Bundle}       or Error NotFound
//
//	Prekeys (upload requires authentication)
//	  C→S  PrekeyUpload{SignedPrekey, OneTimePrekeys}   both optional
//	  S→C  PrekeyStatus{OneTimeRemaining, SignedPrekeyExpires}
//	  C→S  PrekeyRequest{ID, AccessProof}
//	                                 AccessProof as for KeyRequest
//	  S→C  PrekeyResponse{Bundle, SignedPrekey, OneTimePrekey}
//	                                 or Error NotFound / RateLimited
//
//	Messaging (requires authentication)
//	  C→S  Send{To, Payload}
//	  S→C  SendResult{Status}        Accepted, or Error NotFound / QueueFull
//	  C→S  SendMulti{To, Payload}    one payload for up to MaxMultiRecipients IDs
//	  S→C  SendMultiResult{Status, Failed, Reasons}
//	                                 Accepted, listing the recipients the
//	                                 message was not stored for (NotFound /
//	                                 QueueFull each), or Error BadRequest /
//	                                 TooLarge / RateLimited, in which case
//	                                 none is stored
//	  S→C  Deliver{From, Payload, QueueID}
//	                                 pushed to every authenticated connection
//	                                 of the recipient, and again after each
//	                                 authentication until acknowledged
//	  C→S  Ack{QueueID}              no response; the relay deletes the message
//
//	Sealed sender access (requires authentication)
//	  C→S  SetAccessKey{Verifier, AllowUnidentified}
//	  S→C  AccessKeySet{}
//
//	Sealed sending (anonymous connection only)
//	  C→S  SealedSend{To, AccessProof, Payload}
//	  S→C  SendResult{Status}        Accepted, or Error NotFound (unknown
//	                                 recipient or wrong proof alike) /
//	                                 QueueFull
//	  C→S  SealedSendMulti{Entries[{To, AccessProof}], Payload}
//	  S→C  SendMultiResult{Status, Failed, Reasons}
//	  S→C  Deliver{From = SealedFrom, Payload, QueueID}
//
// The authentication signature covers the fingerprint of the relay's TLS
// public key as well as the nonce and the ID, so a proof cannot be replayed
// against another relay, and a connection is authenticated for exactly one
// ID. [Registered] and [AuthOK] carry no fields; their only valid body is the
// empty map. These frame types, and the prekey and acknowledgement frames,
// were added within wire version 1: a peer that predates them rejects them as
// unknown types, which is the intended, backwards compatible failure mode.
//
// [SendMulti] lets a client hand the relay one ciphertext for several
// recipients, as group messaging needs: the relay stores the message for
// every recipient that can take it and delivers one copy per recipient,
// each with its own queue ID, as an ordinary [Deliver], so recipients
// cannot tell it apart from a Send. One unknown recipient or full queue
// does not block the others: the [SendMultiResult] lists the recipients
// the message was not stored for, each with its reason. Each copy counts
// toward its recipient's queue limits. The relay sees the sender, the
// recipient list and the payload size, but no group ID, name or membership.
//
// # Sealed sender
//
// [SealedSend] and [SealedSendMulti] let a client send without telling the
// relay who it is. They are accepted only on an anonymous connection: one
// that completed Hello/Welcome and never sent Register, AuthBegin or
// AuthProof. The first sealed frame locks the connection into that mode, so
// a later Register or AuthBegin, like a sealed frame on a connection that
// registered or began authentication, is a fatal BadRequest; the relay
// never sees a sealed message and an identity on one connection. Instead of
// authenticating, the sender presents the recipient's access verifier
// (uploaded by the recipient with [SetAccessKey]) as its access proof, which
// the relay compares in constant time. Unknown recipients, recipients
// without a verifier and wrong proofs are all answered NotFound. Sealed
// messages are stored without a sender and delivered as a [Deliver] whose
// From is [SealedFrom]; the end-to-end payload names and authenticates the
// sender (see package sealed). These frame types were added within wire
// version 1 like the others above.
//
// A sealed sender also fetches its recipient's keys anonymously: a
// [KeyRequest] or [PrekeyRequest] carrying an AccessProof is an anonymous
// request, checked like a sealed send and answered NotFound when the proof
// does not grant access, so the relay does not learn who looked up whom.
// Such a request locks an undecided connection into anonymous mode; on a
// connection that registered or began authentication it is a fatal
// BadRequest. The optional field was added within wire version 1: older
// relays reject it as an unknown field.
//
// # Relay model
//
// The server is an untrusted relay. The handshake, keepalive, error,
// registration, authentication, key lookup and prekey bodies are plaintext
// and defined in this package. The Payload of [Send], [SendMulti],
// [SealedSend], [SealedSendMulti] and [Deliver] is end-to-end encrypted ciphertext: the relay routes and stores
// it by recipient ID and checks only its size, and it never needs, nor is
// able, to interpret its contents. Identity bundles returned by the relay are verified
// by the client, which checks that each bundle is validly self-signed and
// that its ID equals the requested ID, and prekeys are verified against that
// bundle, so the relay cannot substitute keys.
package protocol
