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
//   - The sender starts epoch e+1 when it is about to send, has received a
//     ratchet public key from the peer that is newer than the key its
//     current epoch targets, and the peer has acknowledged epoch e (every
//     header carries the sender's receiving epoch, RecvEpoch). It
//     encapsulates to that key with info
//     "qchat/v1/ratchet" || sender || recipient || u32(e+1) and feeds the
//     shared secret into its sending root chain with KDF_RK, obtaining a new
//     root key and the epoch's chain key. The initiator's first epoch targets
//     the responder's signed prekey.
//   - Within an epoch, each message key comes from a one-way HMAC chain step,
//     and each message key encrypts exactly one message. The AEAD key and
//     nonce are HKDF-SHA256(salt = header Salt, ikm = message key), with a
//     fresh random 16-byte Salt per message.
//   - Every header repeats the epoch's KEM ciphertext and target, so any
//     message of an epoch can start that epoch at the receiver.
//
// Because the two directions never share a root chain, the sides need not
// agree on any global order of ratchet steps: both may send concurrently
// without diverging.
//
// Each side announces its newest own ratchet public key in every header. On
// its first send after any successful decryption it generates a fresh key
// pair and announces that from then on, unless it already holds
// MaxUnconsumedOwnKeys unconsumed keys. It keeps the private keys of all
// announced keys until the peer has started an epoch targeting one of them:
// when a message of such an epoch decrypts, that key and all older ones are
// deleted. Keys are never deleted to make room, since the peer may already
// have started an epoch targeting the oldest one. In a conversation that
// alternates, each side therefore starts a new epoch, and uses a key the
// other side generated after the previous turn, once per round trip.
//
// The acknowledgement rule keeps the sender's epochs at most one ahead of
// what the receiver can decrypt: an epoch can only be started from the
// previous one, whose KEM ciphertext the receiver must have seen. Without it,
// a peer that rotated keys while all messages of one epoch were delayed or
// lost would receive an epoch it could never decrypt, and so would every
// later one.
//
// # Security properties
//
//   - Forward secrecy: chain and root steps are one-way and consumed keys are
//     deleted, so stealing the current state does not reveal messages whose
//     keys were already deleted. Skipped message keys stored for
//     out-of-order delivery are the exception, which is why they are bounded
//     in number (MaxStoredSkipped, evicted oldest first) and in age: keys of
//     an epoch more than MaxSkippedEpochAge receiving epochs old are
//     deleted, and their messages are lost.
//   - Post-compromise security: after a full state compromise of A, the A->B
//     direction heals as soon as A starts a new epoch (its encapsulation uses
//     fresh randomness to a key whose private part the attacker lacks), and
//     B->A heals once B starts an epoch targeting a key A generated after the
//     compromise. With alternating traffic both happen within one round
//     trip. A passive attacker who knew the old root key cannot compute the
//     new one without the shared secret of that encapsulation.
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
//   - Rollback: a sender whose state was rolled back (a restored backup, a
//     lost write) reuses message keys, but the per-message salt gives every
//     message its own AEAD key and nonce, so no ChaCha20 keystream or
//     Poly1305 key is ever reused. The receiver decrypts only the first of
//     two messages at the same position; the other fails with ErrReplay.
//
// # Limits
//
//   - No header encryption: the relay sees epochs, counters and ratchet
//     public keys (a Phase 5 concern).
//   - The KEM step is unauthenticated on its own; authenticity comes from SK,
//     which the handshake binds to both identities, flowing through the root
//     chain into every message key.
//   - The state must be persisted before plaintext is shown and before a
//     ciphertext is sent. A rolled-back state does not break confidentiality
//     (see Rollback above) but loses messages and forward secrecy for the
//     keys it brought back. A rolled-back receiving state accepts messages
//     it had already decrypted; callers reject those by message ID.
//   - Header, state and wire formats are versioned (HeaderVersion,
//     StateVersion); older versions are rejected.
//   - Memory hygiene is best effort, as for sealbox.
package ratchet
