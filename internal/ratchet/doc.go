// Package ratchet implements qchat's KEM-based double ratchet, as specified
// in docs/design/phase-3-forward-secrecy.md ("Ratchet").
//
// The construction composes standard primitives (HPKE MLKEM768-X25519 via
// internal/crypto/sealbox, HKDF-SHA256, HMAC-SHA256, ChaCha20-Poly1305) in a
// way inspired by Signal's Double Ratchet. It is not Signal's protocol and
// has not been independently analysed.
//
// # Structure
//
// The session secret SK from the handshake is expanded into two root keys,
// one per direction (A->B for the initiator's messages, B->A for the
// responder's). Each direction is an independent sequence of epochs:
//
//   - The sender starts epoch e+1 when it is about to send and has received
//     a ratchet public key from the peer that is newer than the key its
//     current epoch targets. It encapsulates to that key with info
//     "qchat/v1/ratchet" || sender || recipient || u32(e+1) and feeds the
//     shared secret into its sending root chain with KDF_RK, obtaining a new
//     root key and the epoch's chain key. The initiator's first epoch targets
//     the responder's signed prekey.
//   - Within an epoch, each message key comes from a one-way HMAC chain step,
//     and each message key encrypts exactly one message.
//   - Every header repeats the epoch's KEM ciphertext and target, so any
//     message of an epoch can start that epoch at the receiver.
//
// Because the two directions never share a root chain, the sides need not
// agree on any global order of ratchet steps: both may send concurrently
// without diverging.
//
// Each side announces its current own ratchet public key in every header. It
// keeps the private keys of keys it announced until the peer has started an
// epoch targeting them (at most MaxUnconsumedOwnKeys). When a message of such
// an epoch decrypts, the key and all older ones are deleted, and if the
// consumed key was the one being announced a fresh key pair is generated and
// announced from then on. A peer therefore sees a new key roughly once per
// round trip, which bounds how often epochs (and KEM operations) happen.
//
// # Security properties
//
//   - Forward secrecy: chain and root steps are one-way and consumed keys are
//     deleted, so stealing the current state does not reveal messages whose
//     keys were already deleted. Skipped message keys stored for
//     out-of-order delivery are the exception, which is why they are bounded
//     (MaxStoredSkipped) and evicted oldest first.
//   - Post-compromise security: after a full state compromise, the A->B
//     direction heals once A has encapsulated to a key pair B generated after
//     the compromise, and likewise for B->A. A passive attacker who knew the
//     old root key cannot compute the new one without that private key.
//   - Hybrid post-quantum key agreement: every epoch uses MLKEM768-X25519.
//   - Integrity and binding: the AEAD associated data is the exact canonical
//     header encoding followed by the sender and recipient IDs, so every
//     header field is authenticated and a message cannot be redirected to
//     another session or direction.
//   - All-or-nothing decryption: Decrypt computes all changes on the side and
//     commits them only after the AEAD tag verifies. Forged, tampered,
//     replayed or misdirected messages leave the state unchanged.
//   - Bounded work on hostile input: header sizes and counters are checked,
//     and requests to skip more than MaxSkip keys rejected, before any KEM or
//     AEAD operation.
//   - Replay: message keys are single-use, so a replayed message fails.
//
// # Limits
//
//   - No header encryption: the relay sees epochs, counters and ratchet
//     public keys (a Phase 5 concern).
//   - The KEM step is unauthenticated on its own; authenticity comes from SK,
//     which the handshake binds to both identities, flowing through the root
//     chain into every message key.
//   - The state must be persisted before plaintext is shown and before a
//     ciphertext is sent. Encrypting from a stale copy of a state reuses
//     message keys, which breaks confidentiality of the affected messages.
//   - Memory hygiene is best effort, as for sealbox.
package ratchet
