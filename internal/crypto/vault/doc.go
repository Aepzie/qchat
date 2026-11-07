// Package vault protects small secrets (identity seeds, the HPKE private key,
// the local database key) at rest under a passphrase.
//
// # Construction
//
// A 32-byte key is derived from the passphrase with Argon2id (RFC 9106) using
// a fresh random 16-byte salt and the cost parameters in [Params]. The secret
// is then encrypted with XChaCha20-Poly1305 under that key and a fresh random
// 24-byte nonce. Both primitives come from golang.org/x/crypto; the package
// only fixes how they are combined and serialised.
//
// # Blob format
//
// A blob is a CBOR header immediately followed by the AEAD ciphertext (the
// secret plus a 16-byte Poly1305 tag). The header is a map with integer keys
// in Core Deterministic encoding:
//
//	1  version     uint   format version, currently 1
//	2  kdf         uint   1 = Argon2id (version 0x13)
//	3  time        uint   Argon2 passes
//	4  memory      uint   Argon2 memory in KiB
//	5  threads     uint   Argon2 parallelism
//	6  salt        bytes  16 bytes
//	7  nonce       bytes  24 bytes, XChaCha20-Poly1305 nonce
//
// The exact header bytes are the associated data of the AEAD. Changing any
// header field, for example lowering the KDF cost or swapping the salt or
// nonce, therefore makes decryption fail; an attacker cannot downgrade the
// parameters of an existing blob. The decoder accepts only the canonical
// encoding (it re-encodes the parsed header and requires identical bytes), so
// there is exactly one valid header for every set of values.
//
// # Defending the decoder
//
// A vault file may be replaced by an attacker. [Open] therefore validates
// every header field before doing any expensive work: Argon2 parameters above
// [MaxTime], [MaxMemoryKiB] or [MaxThreads] are refused so that a crafted file
// cannot make the client allocate gigabytes of memory or spin for minutes.
// Parameters weaker than half the defaults are refused too (see [Params]),
// because a vault sealed that weakly would be cheap to brute force.
// [TestParams] lifts the lower limit inside test binaries only.
//
// # Security properties and limits
//
//   - Confidentiality and integrity of the secret and header, given a strong
//     enough passphrase. Argon2id makes each passphrase guess cost about
//     64 MiB of memory and three passes with the defaults; it does not make a
//     weak passphrase strong.
//   - [ErrWrongPassphrase] is returned both for a wrong passphrase and for a
//     blob whose header or ciphertext was modified while remaining
//     well-formed. The two cases are cryptographically indistinguishable: an
//     AEAD failure carries no information about its cause, and reporting one
//     would only help an attacker. Structurally broken blobs are reported as
//     [ErrMalformed].
//   - The passphrase is used as raw bytes. Callers must encode it the same
//     way every time (for example UTF-8 in Unicode normalisation form NFC).
//   - Memory hygiene is best effort. Derived keys are overwritten after use,
//     but the AEAD implementation keeps its own copy of the key schedule, the
//     Go runtime may move or copy buffers, and the returned secret is owned by
//     the caller, who should clear it when done.
//   - A vault does not hide its own existence or the approximate size of the
//     secret, and it offers no protection against an attacker who can read
//     process memory while the secret is in use.
package vault
