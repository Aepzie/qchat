// Package senderkey implements qchat's group sender keys, as specified in
// docs/design/phase-4-groups.md ("Sender keys", "Group message transport"
// and "Changes after the internal security review").
//
// The construction is inspired by Signal's Sender Keys and composes standard
// primitives (HMAC-SHA256, HKDF-SHA256, ChaCha20-Poly1305,
// XChaCha20-Poly1305 and the hybrid Ed25519 + ML-DSA-65 signatures of
// internal/crypto/hybridsig). It has not been independently analysed.
//
// # Structure
//
// Every member owns, per group, one current sender key generation: a
// symmetric chain key, a random header key and a fresh hybrid signing key
// pair ([Sender]). The member hands the generation to each other member over
// the pairwise ratchet channel as a distribution message
// ([Sender.Distribution]); each recipient turns it into a [Receiver] for that
// member's generation.
//
// Each group message advances the chain by one step:
//
//	MK         = HMAC-SHA256(CK, 0x01)
//	CK'        = HMAC-SHA256(CK, 0x02)
//	commitment = HMAC-SHA256(MK, "qchat/v1/group-commit")
//	key || nonce = HKDF-SHA256(salt = header Salt, ikm = MK,
//	                           info = "qchat/v1/group-message-key")
//
// The header is the fixed-length (161-byte) string
//
//	Version=2 || GroupID || Sender || Generation || Iteration ||
//	GroupEpoch || StateBinding || Salt || Commitment
//
// The message is padded to its size bucket (package padding) and sealed
// with ChaCha20-Poly1305 under AD = header; the receiver unpads strictly
// after opening. The header is sealed with XChaCha20-Poly1305 under the
// generation's header key, a random 24-byte nonce and
// AD = "qchat/v1/group-header". The envelope is
// signed with the generation's signing key under the context
// "qchat/v1/group-message" over
//
//	Version || HeaderNonce || EncHeader || Ciphertext || header
//
// and encoded as {1: Version=5, 2: HeaderNonce, 3: EncHeader, 4: Ciphertext,
// 5: Sig}. It is sent to all members at once.
//
// # Routing by trial decryption
//
// The relay sees no group ID, sender ID, generation, iteration or epoch:
// every group envelope starts with the same bytes ([IsGroupEnvelope] tells
// only that it is a group message), and its size depends only on the
// padding bucket of the plaintext. A member finds the generation an
// envelope belongs to by trying the header keys it holds ([OpenHeader],
// [HeaderKeyring]); each try
// costs one XChaCha20-Poly1305 authentication over the short header, and a
// member holds at most a small multiple of groups x 256 header keys.
//
// # Security properties
//
//   - Sender authentication: the chain and header keys are shared by all
//     members, so the AEADs alone only prove that some member wrote a
//     message. The hybrid signature, by a key only the owner holds, is what
//     binds a message to its sender, and it is verified before any message
//     key derivation, so a member that knows the shared keys cannot
//     impersonate the owner or burn the owner's message keys at other
//     receivers.
//   - Binding: the header carries the group ID, sender ID, generation,
//     iteration, group epoch and state binding; it is the message AEAD's
//     associated data and it is signed, so a message cannot be moved to
//     another group, sender or generation, nor its epoch or binding changed.
//     A signature made with another generation's key never verifies.
//   - Key commitment: the signed header commits to the message key, so all
//     members that accept an envelope derived the same message key and read
//     the same plaintext, even if a malicious sender distributed different
//     chain or header keys to different members. Neither ChaCha20-Poly1305
//     nor XChaCha20-Poly1305 commits to its key, which is also why the
//     plaintext header, not only its encryption, is signed.
//   - Fork detection: [Receiver.Decrypt] returns the sender's group epoch and
//     state binding, so the caller can flag messages sent from a diverging
//     group state.
//   - Forward secrecy within a generation: chain steps are one-way and used
//     message keys are deleted. A receiver created from a distribution at
//     iteration n cannot decrypt messages before n. Skipped keys stored for
//     out-of-order delivery are bounded (MaxStoredSkipped, evicted oldest
//     first) and timestamped so the caller can prune them by age
//     ([Receiver.PruneSkipped]).
//   - Superseded generations: once the caller freezes a receiver
//     ([Receiver.Freeze]) its chain key is deleted and it only decrypts
//     messages whose skipped keys it still holds, so an old generation stops
//     accepting new messages.
//   - No post-compromise security from the chain alone: a leaked chain key
//     reveals every later message of the generation. Members therefore start
//     a new generation on every removal and after RotationMessages messages
//     or RotationAge (see [Sender.NeedsRotation]).
//   - All-or-nothing decryption: Decrypt computes chain advances on the side
//     and commits them only after the signature, the commitment and the AEAD
//     tag verify. Forged, tampered, replayed or misdirected envelopes leave
//     the state unchanged.
//   - Bounded work on hostile input: envelope sizes and shapes, the header
//     and the skip distance (MaxSkip) are checked before the signature is
//     verified and before any message key derivation.
//   - Rollback: every message has a fresh random salt and header nonce, so a
//     sender whose state was rolled back reuses message keys but never a
//     ChaCha20 key and nonce pair.
//
// # Limits
//
//   - The distribution message is not signed; it relies on the pairwise
//     channel for confidentiality and for authenticating its sender, which
//     is why [NewReceiver] takes that authenticated sender explicitly.
//   - Group membership, epochs, comparing state bindings, freezing old
//     generations, pruning skipped keys and deleting old generations are the
//     caller's responsibility; this package only enforces that an envelope
//     matches the receiver's group, sender and generation.
//   - States must be persisted before plaintext is shown and before an
//     envelope is sent. A rolled-back receiving state accepts messages it
//     had already decrypted; callers reject those by message ID.
//   - Every member of a group can read every header of the generations it
//     holds. The relay still sees the sender of each envelope (it relays it
//     on an authenticated connection), the recipients and the plaintext
//     padding bucket.
package senderkey
