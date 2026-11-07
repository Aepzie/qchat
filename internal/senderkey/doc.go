// Package senderkey implements qchat's group sender keys, as specified in
// docs/design/phase-4-groups.md ("Sender keys" and "Group message
// transport").
//
// The construction is inspired by Signal's Sender Keys and composes standard
// primitives (HMAC-SHA256, HKDF-SHA256, ChaCha20-Poly1305 and the hybrid
// Ed25519 + ML-DSA-65 signatures of internal/crypto/hybridsig). It has not
// been independently analysed.
//
// # Structure
//
// Every member owns, per group, one current sender key generation: a
// symmetric chain key and a fresh hybrid signing key pair ([Sender]). The
// member hands the generation to each other member over the pairwise ratchet
// channel as a distribution message ([Sender.Distribution]); each recipient
// turns it into a [Receiver] for that member's generation.
//
// Each group message advances the chain by one step:
//
//	MK  = HMAC-SHA256(CK, 0x01)
//	CK' = HMAC-SHA256(CK, 0x02)
//	key || nonce = HKDF-SHA256(salt = header Salt, ikm = MK,
//	                           info = "qchat/v1/group-message-key")
//
// The message is sealed once with ChaCha20-Poly1305 under AD = CBOR(header)
// and signed with the generation's signing key under the context
// "qchat/v1/group-message" over CBOR(header) || ciphertext. The resulting
// group envelope {1: Version=3, 2: Header, 3: Ciphertext, 4: Sig} is sent to
// all members at once.
//
// # Security properties
//
//   - Sender authentication: the chain key is shared by all members, so the
//     AEAD alone only proves that some member wrote a message. The hybrid
//     signature, by a key only the owner holds, is what binds a message to
//     its sender, and it is verified before any key derivation, so a member
//     that knows the chain key cannot impersonate the owner or burn the
//     owner's message keys at other receivers.
//   - Binding: the header carries the group ID, sender ID, generation and
//     iteration, it is the exact AEAD associated data and it is signed, so a
//     message cannot be moved to another group, sender or generation. A
//     signature made with another generation's key never verifies.
//   - Forward secrecy within a generation: chain steps are one-way and used
//     message keys are deleted. A receiver created from a distribution at
//     iteration n cannot decrypt messages before n. Skipped keys stored for
//     out-of-order delivery are bounded (MaxStoredSkipped, evicted oldest
//     first).
//   - No post-compromise security from the chain alone: a leaked chain key
//     reveals every later message of the generation. Members therefore start
//     a new generation on every removal and after RotationMessages messages
//     or RotationAge (see [Sender.NeedsRotation]).
//   - All-or-nothing decryption: Decrypt computes chain advances on the side
//     and commits them only after the signature and the AEAD tag verify.
//     Forged, tampered, replayed or misdirected envelopes leave the state
//     unchanged.
//   - Bounded work on hostile input: envelope and header sizes, shapes and
//     the skip distance (MaxSkip) are checked before the signature is
//     verified and before any key derivation.
//   - Rollback: every message has a fresh random 16-byte salt, so a sender
//     whose state was rolled back reuses message keys but never a ChaCha20
//     key and nonce pair.
//
// # Limits
//
//   - The distribution message is not signed; it relies on the pairwise
//     channel for confidentiality and for authenticating its sender, which
//     is why [NewReceiver] takes that authenticated sender explicitly.
//   - Group membership, epochs and the deletion of old generations are the
//     caller's responsibility; this package only enforces that an envelope
//     matches the receiver's group, sender and generation.
//   - States must be persisted before plaintext is shown and before an
//     envelope is sent. A rolled-back receiving state accepts messages it
//     had already decrypted; callers reject those by message ID.
//   - The header is not encrypted: anyone holding an envelope sees the group
//     ID, sender ID, generation and iteration.
package senderkey
