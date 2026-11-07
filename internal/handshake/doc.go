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
//	                 info = T || SHA-256(enc_ik || enc_spk || enc_opk))
//
//	Init {1: Version=1, 2: SenderBundle, 3: SPKID, 4: OPKID (0 = none),
//	      5: EncIK, 6: EncSPK, 7: EncOPK (absent if none), 8: Sig}
//
// Sig is Alice's hybrid signature under [ContextSessionInit] over
// CBOR(fields 1..7) || B, the canonical CBOR map of fields 1 to 7 followed
// by the 32 raw bytes of Bob's ID. Because the CBOR map is self-delimiting
// the concatenation is unambiguous.
//
// # Security properties and their limits
//
//   - Every KEM is the hybrid MLKEM768-X25519, so SK stays secret while
//     either ML-KEM-768 or X25519 holds.
//   - ss_ik binds SK to Bob's long-term identity; ss_spk and ss_opk give
//     forward secrecy once Bob deletes the prekey private keys. Without a
//     one-time prekey, forward secrecy of SK only begins when Bob deletes
//     the signed prekey (about two weeks after its rotation).
//   - T names both parties and both key IDs, and the HKDF info also hashes
//     all encapsulations, so SK is bound to the complete transcript; Alice's
//     signature, which covers the encapsulations, her bundle and Bob's ID,
//     authenticates that transcript to Bob. An Init re-addressed to another
//     recipient, or presented by the relay as coming from another sender,
//     is rejected.
//   - The signature makes the session start non-deniable (an explicit
//     non-goal of Phase 3).
//
// [Accept] succeeding does NOT confirm SK. ML-KEM decapsulation uses
// implicit rejection, so an encapsulation that Alice computed wrongly (or a
// bug) yields an unrelated secret rather than an error. SK is confirmed
// only when the first ratchet message decrypts under it.
//
// # Caller obligations
//
// The one-time prekey private key must be deleted by the caller, durably,
// as soon as the FIRST message of the session that used it has been
// decrypted, and never before (deleting it on a failed decryption would let
// anyone who can inject an Init burn Bob's one-time prekeys). After that,
// a replayed or second Init naming the same OPKID is rejected because the
// lookup fails. Until it is deleted, and for sessions without a one-time
// prekey at all, the relay can replay an Init; package ratchet and the
// message ID tombstones reject the replayed messages, and the caller must
// not set up a second session from an Init whose session already exists.
package handshake
