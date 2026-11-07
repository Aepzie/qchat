// Package prekey implements the signed and one-time prekeys of qchat
// Phase 3 (docs/design/phase-3-forward-secrecy.md, section "Prekeys").
//
// A prekey is an HPKE MLKEM768-X25519 key pair whose public half is
// published on the relay, signed by the owner's identity. A peer who wants
// to start a session while the owner is offline encapsulates to the owner's
// identity key, the current signed prekey and, if the relay still has one,
// a one-time prekey (package handshake). Because the prekey private keys
// are deleted on a schedule (signed prekeys) or after first use (one-time
// prekeys), a later compromise of the device no longer reveals the session
// keys that were derived from them: this is where forward secrecy of the
// session start comes from.
//
// Both encodings are canonical CBOR maps with integer keys:
//
//	SignedPrekey  {1: Version=1, 2: Owner ID (32), 3: KeyID uint32, 4: Pub (1216),
//	               5: Created int64 (Unix s), 6: Expires int64, 7: Sig}
//	OneTimePrekey {1: Version=1, 2: Owner ID (32), 3: KeyID uint32, 4: Pub (1216), 5: Sig}
//
// Sig is the owner's hybrid signature (Ed25519 and ML-DSA-65, both
// required) over the canonical CBOR of all other fields, under the context
// label [ContextSignedPrekey] or [ContextOneTimePrekey]. The two labels
// differ, so a one-time prekey signature can never be presented as a signed
// prekey (which would let the relay extend a one-time key indefinitely)
// and vice versa.
//
// The relay is untrusted. It can withhold prekeys, serve an old signed
// prekey until it expires, or hand out the same one-time prekey twice; it
// cannot substitute keys of its own, because every prekey is verified
// against the owner's identity bundle, which in turn is verified against
// the owner's ID (identity.ParseBundleForID).
package prekey
