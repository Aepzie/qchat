// Package handshake implements the asynchronous session start of qchat
// Phase 3 (docs/design/phase-3-forward-secrecy.md, section "Session
// start"): Alice derives a 32-byte session key SK for Bob from his prekey
// bundle while Bob is offline, and Bob derives the same SK from the signed
// Init header that accompanies Alice's first messages.
//
// # Construction
//
// With A and B the IDs of Alice and Bob and u32 a big-endian uint32:
//
//	T  = "qchat/v1/session" || A || B || u32(spkID) || u32(opkID or 0)
//	enc_ik,  ss_ik  = Encapsulate(Bob's identity KEM key, info = T)
//	enc_spk, ss_spk = Encapsulate(Bob's signed prekey,    info = T)
//	enc_opk, ss_opk = Encapsulate(Bob's one-time prekey,  info = T)   (if any)
//	SK = HKDF-SHA256(salt = 32 zero bytes, ikm = ss_ik || ss_spk || ss_opk,
//	                 info = T || SHA-256(enc_ik || enc_spk || enc_opk)
//	                          || SHA-256(sender bundle) || SHA-256(SPK)
//	                          || SHA-256(OPK or empty))
//
//	Init {1: Version=2, 2: SenderBundle, 3: SPKID, 4: OPKID (0 = none),
//	      5: EncIK, 6: EncSPK, 7: EncOPK (absent if none), 8: Sig,
//	      9: Created int64 (Unix seconds)}
//
// SPK and OPK are the exact signed encodings of Bob's prekeys as served by
// the relay (prekey.SignedPrekey.Raw, prekey.OneTimePrekey.Raw) and the
// sender bundle is SenderBundle; "empty" is the empty string.
//
// Sig is Alice's hybrid signature under [ContextSessionInit] over
// CBOR(all fields but 8) || B, the canonical CBOR map of fields 1 to 7 and
// 9 followed by the 32 raw bytes of Bob's ID. Because the CBOR map is
// self-delimiting the concatenation is unambiguous. Version 1 Inits
// (without Created) are rejected.
//
// # Security properties and their limits
//
//   - Every KEM is the hybrid MLKEM768-X25519, so SK stays secret while
//     either ML-KEM-768 or X25519 holds.
//   - ss_ik binds SK to Bob's long-term identity; ss_spk and ss_opk give
//     forward secrecy once Bob deletes the prekey private keys. Without a
//     one-time prekey, forward secrecy of SK only begins when Bob deletes
//     the signed prekey ([SignedPrekeyRetention] after its creation).
//   - T names both parties and both key IDs, and the HKDF info also hashes
//     all encapsulations, the sender bundle and both prekey encodings, so SK
//     is bound to the complete transcript; Alice's signature, which covers
//     the encapsulations, her bundle, the creation time and Bob's ID,
//     authenticates that transcript to Bob. An Init re-addressed to another
//     recipient, or presented by the relay as coming from another sender,
//     is rejected.
//   - The signed Created time bounds how long an Init can be replayed:
//     [AcceptAt] rejects it once it is older than [MaxInitAge] (or more
//     than [MaxInitClockSkew] in the future) with [ErrStaleInit].
//   - The signature makes the session start non-deniable (an explicit
//     non-goal of Phase 3).
//
// [AcceptAt] succeeding does NOT confirm SK. ML-KEM decapsulation uses
// implicit rejection, so an encapsulation that Alice computed wrongly (or a
// bug) yields an unrelated secret rather than an error. SK is confirmed
// only when the first ratchet message decrypts under it.
//
// # Replays
//
// Within [MaxInitAge] the relay (or anyone who recorded an Init) can
// present it again. Without the defences below a replayed Init would let
// it reset Bob's session with Alice to an old, attacker-chosen start, kill
// a newer session through the simultaneous-start rule of [Winner], and, for
// someone who has stolen Bob's identity and signed prekey private keys,
// impersonate Alice to Bob with a session that Alice never started (key
// compromise impersonation by replay). The handshake therefore relies on
// the following caller obligations.
//
// # Caller obligations
//
//   - Replay set. The caller keeps a set of [Accepted.ReplayKey] values per
//     signed prekey ID, until that signed prekey's private key is deleted
//     (or for at least [MaxInitAge]). After the first message of a session
//     started by an Init has decrypted, the caller adds its replay key, in
//     the same transaction that stores the new session and deletes the
//     one-time prekey (clientdb.DB.CommitReceiveInit; MarkInitSeen for the
//     bare check), and drops the new session if the key was already
//     present. Alice attaches the same Init to every message until
//     she has received a reply, so a replay key equal to that of the
//     caller's current session with the sender is not a replay: such
//     messages belong to the existing session and are decrypted with it,
//     without calling Accept again.
//   - One-time prekeys. The one-time prekey private key must be deleted,
//     durably, as soon as the FIRST message of the session that used it
//     has been decrypted, and never before (deleting it on a failed
//     decryption would let anyone who can inject an Init burn Bob's
//     one-time prekeys). Afterwards a replayed Init naming the same OPKID
//     is rejected with [ErrUnknownPrekey] even without the replay set.
//   - Session replacement. An Init never replaces a session that has
//     received messages in both directions (a confirmed session); only an
//     unconfirmed session of the caller's own, or a session that has only
//     received, may be replaced, and only by an Init that passed AcceptAt,
//     the replay set and decryption of its first message.
//   - Sender bundle serial. [Accepted.Sender] is not compared with any
//     pinned bundle; the caller must reject an Init whose sender bundle has
//     a lower serial than the pinned one (see identity.ParseBundleForIDMinSerial).
//   - Signed prekey policy. Rotate own signed prekeys every
//     [SignedPrekeyRotation], publish them with Expires = Created +
//     [SignedPrekeyLifetime], and delete the private key, and the replay
//     set kept for it, [SignedPrekeyRetention] after Created.
//
// The ratchet and the message ID tombstones additionally reject replayed
// messages within a session.
package handshake
