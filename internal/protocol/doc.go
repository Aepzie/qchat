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
// # Relay model
//
// The server is an untrusted relay. In phase 1 it only takes part in the
// handshake, keepalive and error reporting, all of which use the plaintext
// bodies defined in this package. In later phases the bodies of message
// frames will be end-to-end encrypted blobs: the server sees them as opaque
// ciphertext that it routes by frame type and size, and it never needs, nor
// is able, to interpret their contents.
package protocol
