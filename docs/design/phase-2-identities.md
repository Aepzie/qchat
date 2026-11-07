# Phase 2 design: identities, hybrid keys, 1:1 end-to-end messages

Status: implemented in v0.2.0. This document is the contract between the
packages written in this phase. Later phases (prekeys, ratchet, sealed sender,
padding) build on it.

## Goals and explicit non-goals

Goals:

- Every user has a long-term hybrid identity: Ed25519 + ML-DSA-65 for
  signatures, X25519 + ML-KEM-768 (HPKE KEM `MLKEM768-X25519`) for encryption.
- The relay never sees plaintext or private keys and cannot substitute keys
  without detection.
- 1:1 messages are end-to-end encrypted and signed by the sender.
- Private keys and local history are encrypted at rest with a key derived from
  a passphrase (Argon2id).
- Contacts can be verified with safety numbers (text and QR code).

Non-goals for Phase 2 (documented as limitations, fixed later):

- **No forward secrecy.** Messages are encrypted to the recipient's long-term
  KEM key. Whoever later obtains that private key can decrypt every recorded
  Phase 2 message. Phase 3 replaces this with PQXDH-style key agreement and a
  double ratchet.
- **No offline delivery.** The relay only forwards to recipients that are
  online right now (Phase 3 adds a store-until-delivered queue).
- **No sealed sender, no padding.** The relay sees sender ID, recipient ID,
  time and ciphertext size (Phase 5).
- Signatures make messages non-repudiable towards the recipient (unlike
  Signal's deniable authentication). Revisited with the ratchet in Phase 3.

## Cryptographic building blocks

All from the Go standard library or `golang.org/x/crypto`; nothing home-grown.

| Purpose | Primitive | Package |
|---|---|---|
| Identity signatures | Ed25519 **and** ML-DSA-65 (both must verify) | `crypto/ed25519`, `crypto/mldsa` |
| Message encryption | HPKE (RFC 9180) base mode, KEM `MLKEM768-X25519` (0x647a), KDF HKDF-SHA256, AEAD ChaCha20-Poly1305 | `crypto/hpke` |
| Passphrase KDF | Argon2id, t=3, m=64 MiB, p=4, 16-byte salt (RFC 9106 second recommended profile) | `golang.org/x/crypto/argon2` |
| Local encryption | XChaCha20-Poly1305 with random 24-byte nonces | `golang.org/x/crypto/chacha20poly1305` |
| Hashing | SHA-256, SHA-512 | `crypto/sha256`, `crypto/sha512` |

The HPKE hybrid KEM combines X25519 and ML-KEM-768 with a standardised
combiner, so confidentiality holds as long as either component is unbroken.
This replaces an ad-hoc "concatenate and HKDF" construction.

### Hybrid signature (package `internal/crypto/hybridsig`)

```
M' = "qchat-hybridsig-v1" || u8(len(ctx)) || ctx || msg
sig = ed25519.Sign(skE, M') || mldsa65.Sign(skM, M', context=ctx)
```

`ctx` is a short ASCII domain-separation label (≤ 255 bytes) fixed per use,
for example `qchat/v1/bundle`. Verification fails unless **both** component
signatures verify. Encoded signature = 64 bytes Ed25519 followed by the
ML-DSA-65 signature (fixed sizes; any other length is rejected).

Private key = Ed25519 seed (32 bytes) + ML-DSA-65 seed (32 bytes).
Public key encoding = Ed25519 public key (32) || ML-DSA-65 public key (1952).

### Identity ID

```
ID = SHA-256("qchat-identity-v1" || hybridsig public key encoding)
```

The ID is shown to users as 52 lowercase base32 characters (RFC 4648 alphabet,
no padding) in groups of four, prefixed `qc1-` when written as one string.
Because the ID is a hash of the signing keys, the relay cannot return a
different key for an ID without the client noticing.

### Identity bundle (public, stored on the relay)

CBOR, integer keys, canonical encoding, versioned:

```
Bundle {
  1: Version  uint8   (=1)
  2: SigKey   bytes   hybridsig public key (1984 bytes)
  3: KEMKey   bytes   HPKE MLKEM768-X25519 public key (1216 bytes)
  4: Serial   uint64  monotonically increasing; a newer bundle (e.g. KEM key rotation) must have a higher serial
  5: Created  int64   Unix seconds, informational
  6: Sig      bytes   hybridsig over CBOR of fields 1..5 with ctx "qchat/v1/bundle"
}
```

The display name is **not** part of the bundle; it never reaches the relay.

### Message envelope (opaque to the relay)

```
Inner {                       CBOR, canonical
  1: Version   uint8 (=1)
  2: From      bytes(32)     sender ID
  3: To        bytes(32)     recipient ID
  4: MsgID     bytes(16)     random
  5: Sent      int64         Unix milliseconds
  6: Kind      uint8         1 = text
  7: Body      bytes         UTF-8 text, ≤ 64 KiB
  8: Sig       bytes         hybridsig over CBOR(fields 1..7), ctx "qchat/v1/message"
}
Sealed = HPKE.Seal(recipient KEMKey, info = "qchat/v1/message" || From || To, CBOR(Inner))
```

The recipient checks: HPKE opens; `Inner.To` is its own ID; `Inner.From`
equals the `From` the relay reported; the signature verifies against the
sender's bundle whose computed ID equals `From`; `MsgID` was not seen before
(replay); `Sent` is within ±24 h of local time (otherwise flagged, not dropped).

### Safety numbers

Signal's displayable fingerprint construction: for each party compute
`SHA-512` iterated 5200 times over `version(0x0000) || publicKey || ID`
(each round hashes previous output || publicKey), take the first 30 bytes, and
render as six 5-digit groups (each 5-byte chunk as big-endian integer mod
100000). The safety number is the two 30-digit halves concatenated with the
lexicographically smaller ID first: 60 digits, 12 groups. The QR code encodes
`qchat-verify:1:<idA hex>:<idB hex>:<60 digits>`.

## Relay protocol additions (protocol version stays 1)

New frame types, all bodies CBOR with integer keys:

| Type | Name | Direction | Body |
|---|---|---|---|
| 6 | Register | C→S | `{1: Bundle bytes, 2: Invite string (optional)}` |
| 7 | Registered | S→C | `{}` |
| 8 | AuthBegin | C→S | `{1: ID bytes(32)}` |
| 9 | AuthChallenge | S→C | `{1: Nonce bytes(32)}` |
| 10 | AuthProof | C→S | `{1: Sig bytes}` |
| 11 | AuthOK | S→C | `{}` |
| 12 | KeyRequest | C→S | `{1: ID bytes(32)}` |
| 13 | KeyResponse | S→C | `{1: Bundle bytes}` |
| 14 | Send | C→S | `{1: To bytes(32), 2: Payload bytes}` |
| 15 | SendResult | S→C | `{1: Status uint8}` 1 = delivered, 2 = recipient offline |
| 16 | Deliver | S→C | `{1: From bytes(32), 2: Payload bytes}` |

New error codes: 6 Unauthorized, 7 NotFound, 8 RegistrationDenied, 9 Conflict.

Responses echo the request frame ID.

Authentication proof: hybridsig with ctx `qchat/v1/auth` over
`CBOR{1: server SPKI fingerprint (32), 2: nonce (32), 3: ID (32)}`. Binding the
server fingerprint prevents a proof from being replayed against another
server. A connection is authenticated for exactly one ID.

Rules:

- `Register` is allowed before authentication. The relay verifies the bundle
  signature, computes the ID, and stores it. Registering an already known ID
  succeeds idempotently for the identical bundle, replaces it for a valid bundle
  with a higher serial, and fails with Conflict otherwise. When
  `registration = "invite"` (default) a valid unused invite code is required
  for new IDs.
- `KeyRequest` and `Send` require authentication. `Send` to the sender itself
  is rejected. Payload size is bounded by `limits.max_message_size`.
- `Deliver` is pushed to every authenticated connection of the recipient.
- The relay stores identities and invite hashes only. It never stores
  messages in Phase 2 and never logs IDs, IPs or payloads.

## Storage

Relay (`internal/store/serverdb`, SQLite via `modernc.org/sqlite`):
`identities(id BLOB PRIMARY KEY, bundle BLOB, serial INTEGER)`,
`invites(code_hash BLOB PRIMARY KEY, expires_at INTEGER, uses_left INTEGER)`.
Invite codes are 128-bit random, shown base32; only their SHA-256 is stored.

Client (`internal/store/clientdb` + `internal/crypto/vault`):

- `identity.qkey`: vault file holding identity seeds, the HPKE private key and
  a random 32-byte database key, encrypted with XChaCha20-Poly1305 under an
  Argon2id key from the passphrase. The header (version, KDF parameters, salt,
  nonce) is authenticated as associated data.
- `qchat.db`: SQLite where every row value is an AEAD ciphertext under the
  database key. Lookup columns are `HMAC-SHA256(dbKey, label || value)`, so the
  file reveals neither contact IDs nor message text. Row counts and sizes remain
  visible (documented).
