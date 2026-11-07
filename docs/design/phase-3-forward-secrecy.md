# Phase 3 design: prekeys, forward secrecy, offline delivery

Status: implemented in v0.3.0. Binding contract for the packages of this phase.
Builds on [phase-2-identities.md](phase-2-identities.md); identities, bundles,
IDs, relay authentication and the encrypted client database are unchanged.

> This construction composes standard primitives (HPKE, HKDF, HMAC,
> ChaCha20-Poly1305) in a way inspired by Signal's PQXDH and Double Ratchet, but
> it is **not** Signal's protocol and has **not** been analysed or audited.

## Goals

- **Forward secrecy:** stealing a device's current keys must not reveal
  messages whose keys were already deleted.
- **Post-compromise security:** after a state compromise, each direction heals
  once the peer has encapsulated to an own key generated after the compromise
  (a side announces a fresh own key on its first send after every receive, so
  this takes one round trip).
- **Post-quantum:** every key agreement uses the hybrid KEM MLKEM768-X25519, so
  confidentiality holds while either ML-KEM-768 or X25519 holds.
- **Asynchronous start and offline delivery:** a user can start a session with
  someone who is offline; the relay stores ciphertext until it is acknowledged.
- Phase 2's static-key message format is removed (pre-1.0, no compatibility).

Non-goals: deniability (initial messages are signed), header encryption and
sealed sender (Phase 5), multi-device.

## Primitive: KEM shared secret (package `internal/crypto/sealbox`)

```
Encapsulate(pub, info) -> (enc []byte /*1120*/, secret [32]byte)
Decapsulate(priv, enc, info) -> secret [32]byte
```

HPKE base mode, suite MLKEM768-X25519 / HKDF-SHA256 / **ExportOnly** AEAD,
`secret = Export("qchat/v1/kem", 32)`. `info` must be non-empty.

## Prekeys (package `internal/prekey`)

Both kinds are HPKE MLKEM768-X25519 key pairs signed by the owner's identity
(hybridsig, both signatures required), canonical CBOR with integer keys:

```
SignedPrekey  { 1: Version=1, 2: Owner ID(32), 3: KeyID uint32, 4: Pub(1216),
                5: Created int64 (unix s), 6: Expires int64, 7: Sig }   ctx "qchat/v1/signed-prekey"
OneTimePrekey { 1: Version=1, 2: Owner ID(32), 3: KeyID uint32, 4: Pub(1216), 5: Sig }   ctx "qchat/v1/one-time-prekey"
```

Signature covers CBOR of all other fields. Verification takes the owner's
parsed identity bundle and checks Owner == bundle.ID. Key IDs are random
non-zero uint32 chosen by the owner.

Client policy: one active signed prekey, rotated every 7 days, lifetime
`Expires = Created + 9 days`; the private key is kept until `Expires + 7 days`
(the relay's `undelivered_ttl`, so a queued first message can still be read)
and then deleted, 16 days after creation. A pool of 50 one-time prekeys; replenish when the relay reports fewer
than 20. A one-time private key is deleted as soon as the first message that
used it has been decrypted.

## Session start (package `internal/handshake`)

Alice starts a session with Bob from a relay-provided prekey bundle
(Bob's identity bundle, signed prekey, optional one-time prekey):

1. Verify Bob's bundle with `ParseBundleForID(want = Bob's ID)`, the signed
   prekey (owner, signature, not expired) and the one-time prekey if present.
2. `T = "qchat/v1/session" || A.ID || B.ID || u32(spkID) || u32(opkID or 0)`
3. Encapsulate with `info = T` to Bob's identity KEM key (`enc_ik, ss_ik`), his
   signed prekey (`enc_spk, ss_spk`) and, if present, the one-time prekey
   (`enc_opk, ss_opk`).
4. `SK = HKDF-SHA256(salt = 32 zero bytes, ikm = ss_ik || ss_spk || ss_opk,
   info = T || SHA-256(enc_ik || enc_spk || enc_opk) || SHA-256(sender bundle)
   || SHA-256(SPK) || SHA-256(OPK or empty))`, 32 bytes.
5. Init header (version 2), sent with every message until Alice has received a
   message on this session. It carries the sender bundle, the prekey IDs, the
   three encapsulations, a `Created` timestamp and Alice's hybridsig (ctx
   `qchat/v1/session-init`) over all other fields plus Bob's ID. Bob verifies:
   SenderBundle parses, its ID equals the relay-reported sender, signature
   valid, `Created` is at most 16 days old (the signed prekey retention) and not
   in the future, the Init was not seen before (replay set keyed by a hash of
   the encapsulations, kept per signed prekey until that key is deleted),
   prekeys known (unknown or deleted one-time prekey → reject), then derives
   the same SK. A sender bundle with a lower serial than the pinned contact
   bundle is never stored.

KEM decapsulation uses implicit rejection, so a wrong SK is only detected when
the first ratchet message fails to decrypt; no state is committed and no
prekey is deleted before that succeeds. Envelopes that need an `Accept` are
rate limited per sender. An Init never replaces a session that has already
received messages in both directions.

Simultaneous starts: if both sides start a session before receiving anything,
the session initiated by the lexicographically smaller ID wins; the other side
discards its own unconfirmed session when it receives the winning Init.

## Ratchet (package `internal/ratchet`)

A KEM-based double ratchet with **one root chain per direction**, so concurrent
sending never makes the two sides diverge:

- From SK: `RK_send/RK_recv = HKDF(SK, info "qchat/v1/root A->B" / "B->A")`
  (initiator sends on A->B).
- Each side holds a current own ratchet key pair (sealbox) and announces its
  public key in every header. A side starts a new **epoch** when it sends after
  having received a newer peer public key than its current epoch targets:
  `(ct, ss) = Encapsulate(peerPub, info = "qchat/v1/ratchet" || sender ID || recipient ID || u32(epoch))`,
  `RK_send, CK_send = KDF_RK(RK_send, ss)` where
  `KDF_RK(rk, ss) = HKDF-SHA256(salt = rk, ikm = ss, info = "qchat/v1/rk")` → 64 bytes split.
  For the initiator's first epoch the target is Bob's signed prekey.
- Message keys: `MK = HMAC-SHA256(CK, 0x01)`, `CK = HMAC-SHA256(CK, 0x02)`;
  `key||nonce = HKDF-SHA256(salt = header Salt, ikm = MK, info "qchat/v1/message-key")`
  → 32 + 12 bytes, AEAD ChaCha20-Poly1305, AD = CBOR(header) || sender ID ||
  recipient ID. The fresh random salt per message means that even a sender
  whose state was rolled back (backup restore, lost write) never reuses a
  key/nonce pair.
- Header (version 2; every message carries the epoch's KEM ciphertext so any
  single message of an epoch can start it): epoch, sender's current ratchet
  public key, target (SHA-256 of the recipient key encapsulated to), KEM
  ciphertext, PN, N and a 16-byte random Salt.
- A side announces a fresh own ratchet key on its first send after any
  receive and keeps the private keys of up to 4 announced, unconsumed keys;
  a key is deleted once a message of an epoch targeting it has been
  decrypted. Skipped message keys are stored for out-of-order delivery, at
  most 1000 per session and 1000 per step, and are deleted once they are more
  than 2 epochs old (messages that late are lost), so a withheld message
  cannot keep its key alive indefinitely.
- Every decryption is all-or-nothing: state changes are committed only after
  the AEAD tag verifies.
- State is serialised as versioned canonical CBOR and stored encrypted in the
  client database; it is written back before a decrypted message is shown or a
  ciphertext is handed to the relay.

## Message envelope (relay payload, version 2)

```
Envelope { 1: Version=2, 2: Init (optional), 3: Header, 4: Ciphertext }
Plaintext { 1: MsgID(16), 2: Sent int64 ms, 3: Kind uint8 (1 = text), 4: Body bytes ≤ 64 KiB }
```

Replay protection: ratchet message keys are single-use (a replayed ciphertext
fails), plus the existing MsgID tombstones.

## Relay changes (protocol version stays 1)

| Type | Name | Direction | Body |
|---|---|---|---|
| 17 | PrekeyUpload | C→S | `{1: SignedPrekey bytes (optional), 2: OneTimePrekeys [][]byte (0..100)}`; an empty upload only asks for the count |
| 18 | PrekeyStatus | S→C | `{1: OneTimeRemaining uint32, 2: SignedPrekeyExpires int64}` |
| 19 | PrekeyRequest | C→S | `{1: ID(32)}` |
| 20 | PrekeyResponse | S→C | `{1: Bundle, 2: SignedPrekey, 3: OneTimePrekey (optional)}` |
| 21 | Ack | C→S | `{1: QueueID uint64}` (no response) |

- `Deliver` gains `3: QueueID uint64` (required).
- `SendResult` status `3 = Accepted`; the relay now always answers Accepted for
  registered recipients, so senders can no longer probe online presence.
- The relay verifies prekey signatures against the owner's stored bundle,
  keeps one signed prekey (newest wins) and up to 200 one-time prekeys per ID,
  and hands out each one-time prekey exactly once (atomic delete).
  `PrekeyRequest` is rate limited per session (default 30/hour) to slow
  one-time-prekey draining.
- Every `Send` is stored (`queue` table: id, recipient, sender, payload,
  expires) and pushed to live sessions. Queued messages are pushed after
  authentication in order. The row is deleted on `Ack` from the recipient or
  when `undelivered_ttl` (default 7 days) expires. Limits per recipient:
  `max_queued_messages` (1000) and `max_queued_bytes` (64 MiB); beyond that,
  `Send` fails with a new error code `10 QueueFull`. Pruning runs periodically.
- The relay still never logs IDs, payloads or addresses.
