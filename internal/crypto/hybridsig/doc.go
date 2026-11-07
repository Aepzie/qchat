// Package hybridsig implements the qchat composite signature scheme: every
// signature is an Ed25519 signature and an ML-DSA-65 (FIPS 204) signature over
// the same domain-separated message, and a signature is valid only if both
// components verify.
//
// # Construction
//
// For a context label ctx and a message msg, both components sign
//
//	M' = "qchat-hybridsig-v1" || u8(len(ctx)) || ctx || msg
//
// Ed25519 signs M' directly (pure Ed25519, RFC 8032). ML-DSA-65 signs M' with
// its own FIPS 204 context string set to ctx, using the hedged (randomised)
// signing mode of [crypto/mldsa]. The encoded signature is the 64-byte Ed25519
// signature followed by the 3309-byte ML-DSA-65 signature, [SignatureSize]
// bytes in total. The encoded public key is the 32-byte Ed25519 public key
// followed by the 1952-byte ML-DSA-65 public key, [PublicKeySize] bytes in
// total. A private key is the pair of 32-byte seeds from which both component
// keys are deterministically expanded by the standard key generation
// algorithms.
//
// Nothing here is new cryptography: the package only composes two standard
// signature schemes from the Go standard library and fixes how their inputs
// are formed.
//
// # Security properties
//
//   - Hybrid unforgeability. Because verification requires both components, a
//     forgery requires breaking Ed25519 (for example with a quantum computer)
//     and ML-DSA-65 (for example through an unforeseen cryptanalytic result)
//     for the same key at the same time. Either scheme alone remaining secure
//     is enough.
//   - Domain separation. The fixed prefix binds signatures to this scheme and
//     version, and the length-prefixed context binds them to one purpose, so a
//     signature made for one protocol message (say ctx "qchat/v1/auth") can
//     never be presented as a signature for another (say ctx
//     "qchat/v1/bundle"). The length prefix makes the encoding of (ctx, msg)
//     injective: no two different pairs produce the same M'. ML-DSA additionally
//     receives ctx through its native context parameter.
//   - No component stripping. The two halves sign the same M' and are only
//     accepted together at fixed offsets, so a valid hybrid signature cannot
//     be turned into a valid single-algorithm signature for this scheme, and a
//     component signature taken from some other protocol cannot be combined
//     into a valid hybrid one (it would have to be over M', which embeds the
//     qchat prefix).
//   - Strict encoding. Public keys and signatures have fixed lengths; any other
//     length is rejected before any cryptographic work is done.
//
// # Limits
//
//   - Signatures are not deterministic: ML-DSA-65 hedged signing mixes fresh
//     randomness into each signature (protecting against fault and
//     side-channel attacks), so signing the same message twice yields
//     different ML-DSA halves. The Ed25519 half is deterministic.
//   - Signatures are non-repudiable: anyone holding the public key can prove
//     to a third party that the key holder signed a message.
//   - The scheme authenticates messages, it does not provide secrecy, freshness
//     or replay protection. Callers must include nonces, timestamps or message
//     IDs in the signed message where those properties matter.
//   - Memory hygiene is best effort. [PrivateKey.Destroy] overwrites the seeds
//     this package holds, but the Go runtime may have copied key material
//     (garbage-collector moves, stack growth, the internal expanded key state
//     of crypto/ed25519 and crypto/mldsa) to places this package cannot reach.
//     Go offers no guaranteed way to erase secrets from memory.
package hybridsig
