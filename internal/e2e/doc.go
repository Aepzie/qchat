// Package e2e seals and opens qchat 1:1 end-to-end messages as specified in
// docs/design/phase-2-identities.md, section "Message envelope".
//
// A message is an Inner structure (sender, recipient, random message ID,
// send time, kind, body) signed by the sender's hybrid identity key and
// then encrypted with HPKE (RFC 9180, KEM MLKEM768-X25519, HKDF-SHA256,
// ChaCha20-Poly1305) to the recipient's long-term KEM key. Nothing here is
// new cryptography: the package composes packages identity, hybridsig and
// sealbox and fixes the encodings.
//
// # Security properties
//
//   - Confidentiality against the relay and network observers, as long as
//     either X25519 or ML-KEM-768 remains secure.
//   - Authenticity: the recipient accepts only messages signed (Ed25519 and
//     ML-DSA-65) by the key whose hash is the sender ID, addressed to itself
//     and attributed by the relay to that same sender.
//   - Integrity: any modification of the payload makes decryption fail.
//
// # Limits (Phase 2)
//
//   - NO FORWARD SECRECY. Payloads are sealed to the recipient's static,
//     long-term KEM key. Anyone who records payloads (the relay, a network
//     observer able to break TLS later) and later obtains that private key,
//     for example from a stolen device and a guessed passphrase, can decrypt
//     every recorded Phase 2 message to that identity. Phase 3 replaces this
//     with PQXDH-style key agreement and a double ratchet.
//   - NON-REPUDIATION. The sender signs every message with its long-term
//     identity key, so a recipient can prove to third parties that the
//     sender wrote a message. This differs from Signal's deniable
//     authentication and is revisited in Phase 3.
//   - NO REPLAY PROTECTION IN THIS PACKAGE. [Open] verifies everything except
//     whether a message ID was seen before; the caller must check (sender,
//     MsgID) against its message store and drop duplicates.
//   - METADATA IS VISIBLE TO THE RELAY: sender ID, recipient ID, time and
//     payload size (no sealed sender and no padding until Phase 5).
//   - The send time is claimed by the sender and only flagged, not
//     enforced, when it is far from the local clock.
package e2e
