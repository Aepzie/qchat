// Package sealbox encrypts messages to a long-term public key with HPKE
// (RFC 9180) in base mode, using one fixed ciphersuite:
//
//	KEM   MLKEM768-X25519 (X-Wing, draft-ietf-hpke-pq)  ID 0x647a
//	KDF   HKDF-SHA256                                    ID 0x0001
//	AEAD  ChaCha20-Poly1305                              ID 0x0003
//
// The package is a thin, opinionated wrapper around [crypto/hpke]. Fixing the
// suite removes all algorithm negotiation (and with it downgrade attacks) and
// gives keys and ciphertexts fixed, checkable sizes. Nothing here is new
// cryptography.
//
// # Wire format
//
// A sealed box is the HPKE single-shot output: the 1120-byte encapsulated key
// followed by the AEAD ciphertext, which is the plaintext length plus a
// 16-byte Poly1305 tag. [Overhead] is the total expansion. No additional
// associated data is used; everything the receiver must agree on goes into
// the info string, which is bound into the key schedule.
//
// # Security properties
//
//   - Hybrid confidentiality. The X-Wing KEM combines ML-KEM-768 and X25519
//     with a standardised combiner, so a box stays confidential as long as
//     either component is unbroken: classical attackers must break X25519,
//     quantum attackers must break ML-KEM-768.
//   - Integrity. Any modification of the encapsulated key, ciphertext or tag,
//     and any mismatch in the info string or recipient key, makes [Open] fail.
//     [Open] never returns partial plaintext.
//   - Context binding. The info string (which must not be empty) is fed into
//     the HPKE key schedule, so a box sealed for one purpose or one
//     sender/recipient pair cannot be opened under another info string. Each
//     call to [Seal] uses a fresh encapsulation, so sealing the same
//     plaintext twice gives unrelated outputs.
//
// # Limits
//
//   - No sender authentication. Base mode proves nothing about who sealed a
//     box: anyone who knows the public key can produce a valid one. qchat signs
//     the inner message with the sender's hybrid identity key
//     (internal/crypto/hybridsig) to authenticate it.
//   - No forward secrecy, as used in Phase 2. HPKE itself creates a fresh
//     ephemeral encapsulation per box, but Phase 2 seals every message to the
//     recipient's long-term KEM key. Anyone who later obtains that private key
//     can open every recorded box. This is a property of how Phase 2 uses the
//     package, not of HPKE; Phase 3 replaces it with ephemeral key agreement
//     and a ratchet.
//   - No replay protection and no length hiding. A box can be delivered more
//     than once, and its size reveals the plaintext size. Callers deduplicate
//     by message ID and, in later phases, pad.
//   - Memory hygiene is best effort. [PrivateKey.Destroy] clears the seed held
//     by this package but cannot erase the expanded key state inside
//     crypto/hpke or copies made by the Go runtime.
package sealbox
