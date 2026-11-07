// Package transport provides the network layer of qchat: a TLS 1.3 channel
// with mandatory hybrid post-quantum key exchange, authenticated by pinning
// the server's public key, carrying a WebSocket connection.
//
// # Threat model
//
// The transport defends against:
//
//   - Network attackers who can read, modify, drop or inject traffic
//     (machine-in-the-middle). The client never trusts public certificate
//     authorities or hostnames. Instead it pins the SHA-256 hash of the
//     server's SubjectPublicKeyInfo (SPKI), which users obtain out of band.
//   - "Harvest now, decrypt later" attackers who record traffic today and
//     hope to break it with a future quantum computer. Every connection uses
//     the X25519MLKEM768 hybrid key exchange (classical X25519 combined with
//     the post-quantum ML-KEM-768). A peer that cannot do this key exchange
//     is refused; there is no fallback to a classical-only group.
//
// The transport is the outer layer only. Message contents are additionally
// end-to-end encrypted by higher layers, so the server operator and the TLS
// layer never see plaintext chat messages.
//
// # Privacy
//
// The server side never logs client IP addresses. In particular the
// net/http error log, which would otherwise print lines such as
// "TLS handshake error from <ip>:<port>", is discarded (see NewHTTPServer).
package transport
