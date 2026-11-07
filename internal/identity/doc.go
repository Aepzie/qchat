// Package identity implements qchat identities as specified in
// docs/design/phase-2-identities.md: long-term hybrid key pairs, their IDs,
// the self-signed public bundles stored on the relay, the relay
// authentication proof and safety numbers.
//
// # Keys and IDs
//
// An [Identity] holds two private keys:
//
//   - a hybrid signing key, Ed25519 and ML-DSA-65 (package hybridsig), where
//     every signature must verify under both algorithms;
//   - an HPKE decryption key for the hybrid KEM MLKEM768-X25519 (package
//     sealbox), to which peers encrypt messages.
//
// The [ID] of an identity is
//
//	SHA-256("qchat-identity-v1" || hybrid signing public key)
//
// shown to users as "qc1-" followed by 52 base32 characters in groups of
// four (see [ID.String] and [ParseID]). Since the ID is a hash of the
// signing key, and the signing key signs the KEM key inside the bundle, an
// ID is a commitment to all of an identity's public keys.
//
// # Bundles and the untrusted relay
//
// A bundle ([Identity.Bundle], [ParseBundle]) is the canonical CBOR
// encoding of the public keys, a serial and a creation time, self-signed
// under the context "qchat/v1/bundle". The relay stores bundles and serves
// them on request, but is not trusted to serve the right one: a client that
// asks for the bundle of an ID must parse the answer with
// [ParseBundleForID], which recomputes the ID from the signing key and
// rejects any other bundle. The relay can therefore refuse to serve keys,
// but it cannot substitute its own without the client noticing.
//
// What ParseBundleForID cannot detect is an attacker who controls the
// channel over which the user learned the ID in the first place. Comparing
// the [SafetyNumber] (or scanning the [SafetyQR] code) in person closes that
// gap.
//
// # Encodings
//
// Bundles, the authentication proof input and the secret-key record are
// CBOR maps with integer keys in Core Deterministic encoding. Decoding is
// strict: duplicate keys, unknown fields, indefinite lengths, tags and any
// encoding other than the canonical one are rejected, so every structure has
// exactly one accepted byte representation and signatures can never be
// transplanted onto an alternative encoding.
//
// # Limits
//
//   - The KEM key is long-term and static in Phase 2, so messages sealed to
//     it have no forward secrecy (see package e2e).
//   - Erasing private keys from memory is best effort ([Identity.Destroy]).
//   - The display name is not part of the bundle and never reaches the
//     relay.
package identity
