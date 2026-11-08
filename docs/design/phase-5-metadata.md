# Phase 5 design: metadata protection

Status: in progress. Builds on [phase-3-forward-secrecy.md](phase-3-forward-secrecy.md);
the wire formats of earlier phases are unchanged unless a section below says
otherwise.

Goal: reduce what the relay learns from traffic it already handles, starting
with the length of end-to-end payloads. Later sections (header protection,
sealed sender) will be added as they are designed.

## Padding (package `internal/padding`)

```
Buckets = [512 B, 1 KiB, 2 KiB, 4 KiB, 8 KiB, 16 KiB, 32 KiB, 64 KiB, 128 KiB, 256 KiB]
Pad(plaintext) -> padded      // ErrTooLarge if len(plaintext) > 256 KiB - 1
Unpad(padded)  -> plaintext   // ErrMalformed
BucketFor(n)   -> padded size for an n-byte plaintext
```

- **Scheme:** ISO/IEC 7816-4 style: append `0x80`, then zero bytes up to the
  smallest bucket of at least `len(plaintext) + 1` bytes. The marker is always
  present, so every plaintext (empty, or ending in `0x80`/`0x00`) is
  unambiguous.
- **Unpad is strict:** the input length must be exactly one bucket, and the
  input must end in `0x80` followed only by zeros; anything else is
  `ErrMalformed`. A larger bucket than the minimal one is accepted, so a
  sender may pad further than `Pad` does.
- **Timing:** `Unpad` scans the whole input from the end with constant-time
  byte comparisons and selects, so its running time depends on the bucket
  size (public) and not on the plaintext length. This is best effort at the Go
  level, not a guarantee about the compiled code.
- **Placement:** padding is applied **inside** the encryption: the sender pads
  the plaintext and then seals it with the message AEAD; the receiver opens
  and then unpads. The AEAD authenticates the padding, and the ciphertext
  overhead (ratchet header, tag, framing) does not depend on the plaintext
  length, so the relay only sees `overhead + bucket`. A padding error after a
  successful AEAD open means a buggy or malicious peer, never the relay.

Rationale for the buckets: powers of two keep the worst-case overhead below
2x (plus one byte), and ten classes are coarse enough that a typical chat
message, a short paragraph and a small attachment chunk mostly fall into the
first one or two buckets. 512 B as the smallest bucket covers almost all text
messages. The largest encoded plaintext today is `e2e.MaxPlaintextSize`
(64 KiB body + 64 B), which pads to 128 KiB; the 256 KiB bucket leaves room
for larger bodies without a format change.

### Integration

**Pairwise messages (`internal/e2e`, envelope version 3).** The sender
encodes the `Plaintext` (every kind: text, group control, sender key
distribution) and pads it with `e2e.MarshalPaddedPlaintext`; the ratchet
encrypts the padded bytes. The receiver decrypts and calls
`e2e.ParsePaddedPlaintext`, which unpads strictly and then parses. A padding
error is handled exactly like a failed decryption: the delivery is counted
as dropped and acknowledged, and the ratchet state is not stored, so the
session is unaffected. The envelope encoding itself did not change, so the
envelope version was bumped from 2 to 3 to make the new plaintext format
distinguishable; version 2 envelopes are rejected (pre-1.0, no
compatibility).

Limits: `e2e.MaxPaddedPlaintextSize` = `BucketFor(MaxPlaintextSize)` =
128 KiB, `MaxCiphertextSize` = 128 KiB + 16, and `MaxEnvelopeSize` =
`MaxInitSize` (23,181) + `MaxHeaderSize` (4,096) + `MaxCiphertextSize`
(131,088) + 64 = 158,429 bytes. Sealed, it is padded to the 256 KiB sealed
bucket (see "Sealed payload"), which is why the relay's default
`max_message_size` is 264 KiB (270,336).

**Group messages (`internal/senderkey`, group envelope version 5).**
`Sender.Encrypt` pads the plaintext before sealing it with the message
AEAD; `Receiver.Decrypt` unpads after opening and before committing any
chain advance, so an authentic, signed envelope with invalid padding fails
with `ErrDecrypt` and leaves the receiver unchanged. `MaxPlaintextSize`
(64 KiB) still bounds the unpadded plaintext; the ciphertext must be
exactly a bucket of at most 128 KiB plus the 16-byte tag, which is checked
together with the other shape checks before the signature is verified. The
largest group envelope is 128 KiB + 16 + 3,373 (signature) + 24 (nonce) +
177 (encrypted header) + framing, about 132 KiB. The version was bumped
from 4 to 5; version 4 envelopes are no longer recognised as group
envelopes.

### What it hides

- The exact length of each message body; the relay learns only its bucket.
- Differences between short messages: bodies of 1, 100 and 400 bytes give
  payloads of identical size, pairwise and in groups (tested in
  `internal/app`).

### What it does not hide

- The bucket itself, so very large payloads remain distinguishable from text.
- Timing, frequency and number of messages, sender and recipient IDs, the
  number of recipients, and online/offline patterns.
- The ratchet header. It is not encrypted, so the relay reads the epoch,
  the counters (`PN`, `N`) and the ratchet public key directly; its size is
  not the leak. Per the Phase 3 format every message of an epoch repeats
  the epoch's KEM ciphertext, so header size does not reveal epoch starts:
  it is constant apart from the CBOR widths of `Epoch`, `PN` and `N`
  (1 to 5 bytes each), which only repeat values the relay can read anyway.
  The header (about 2.4 KB) still dominates the size of short messages.
  Header protection is a separate Phase 5 item.
- Whether an Init is attached, for identified sends. A pairwise envelope
  carrying the handshake Init (the initiator's messages until the first
  reply) is about 13 KB larger, and the Init field is visible in the
  unencrypted envelope structure, so identified envelopes are deliberately
  **not** padded to a fixed size: as long as the field itself is readable,
  size padding would add bandwidth without hiding anything. Sealed sends
  hide it: the sealed layer pads its whole content with a 32 KiB floor
  (see "Sealed payload"), so a typical first message and a later one have
  the same size.
- Anything visible to the peers themselves; padding is only against the relay
  and network observers.

## Tor

Goal: let a client hide its IP address from the relay and from the network,
and let an operator hide the relay's location, without making Tor a
dependency of either binary. Tor is optional; without it nothing changes.

### Client: SOCKS5 dialer (`internal/transport/socks5.go`)

```go
func SOCKS5Dialer(proxyAddr, isolation string) func(ctx context.Context, network, addr string) (net.Conn, error)
var ErrSOCKS5 error
type SOCKS5ReplyError struct{ Code byte }
```

The returned function plugs into `transport.DialOptions.NetDialContext` and
`client.Options.Dialer`. TLS 1.3 with X25519MLKEM768 and SPKI pinning runs
unchanged on top of the proxied TCP stream. It is a minimal SOCKS5 client
(RFC 1928, CONNECT only) written for qchat, with no new module dependency:

- **No local name resolution.** Host names are sent as `ATYP 0x03` (domain
  name) and resolved by the proxy; only IP literals are sent as addresses.
  No DNS query reveals the server's name, and `.onion` names work.
  `http.Transport` passes the name unresolved to the dial function, and its
  `Proxy` field stays nil, so environment proxies cannot interfere.
- **Stream isolation.** A non-empty `isolation` token is sent as both user
  name and password of RFC 1929 username/password authentication, and only
  that method is offered: a proxy that does not accept it is refused rather
  than used without isolation. Tor's `IsolateSOCKSAuth` (on by default) puts
  streams with different credentials on different circuits. The client
  draws a fresh random 128-bit token per run, so qchat shares no circuit
  with other applications or with earlier runs, while its reconnects within
  one run reuse circuits.
- **Bounded time.** Connecting to the proxy is limited to 30 s and the SOCKS
  handshake to 120 s (onion circuits are slow to build); the caller's
  context cancels either at any time, and context errors are returned as
  such. The deadline is cleared once the tunnel is up. The session's own
  45 s dial timeout and its reconnect back-off apply on top.
- **Strict parsing.** Every reply field is checked: version bytes, the
  selected method (must be the one offered), the RFC 1929 status, the
  reserved byte, the address type and the exact length of the bound address.
  The reply is consumed byte for byte without buffering, so the first byte
  from the server is never lost or misread. Any violation fails the dial
  with an error wrapping `ErrSOCKS5`; failure codes are returned as
  `*SOCKS5ReplyError`, with Tor's onion service codes `0xF0`-`0xF7` named.
  Invalid input (non-TCP network, missing or zero port, empty or over-long
  host, IPv6 zone, token over 255 bytes) fails before any connection.

### Client: flags (`cmd/client`)

- `--tor` uses Tor's default SOCKS port `127.0.0.1:9050`.
- `--socks5 HOST:PORT` uses another proxy, for example Tor Browser at
  `127.0.0.1:9150`, and overrides `--tor`'s address. An explicitly given
  value must pass `transport.ValidateHostPort`, even an empty one.
- With either flag, every connection the client makes (the chat session and
  the profile recovery lookup) is dialed through the proxy. There is no
  fallback: if the proxy is down or refuses, the client does not connect.
- The status bar's `Tor:` segment (`tui.Config.Tor`) shows `on` whenever a
  proxy is configured.
- Locked builds keep their embedded server and pin; the proxy flags still
  apply.
- `transport.ValidateHostPort` already accepts v3 onion host names (56
  base32 characters plus `.onion`); tests cover them, and
  `qchat-server init --host <onion>.onion` accepts them for the certificate.

### Server: onion service

The server has no Tor code. The operator runs tor with
`HiddenServiceDir` / `HiddenServicePort 7443 127.0.0.1:7443` and binds
`qchat-server` to `127.0.0.1:7443` so that it is not also reachable
directly. Because all onion connections arrive from `127.0.0.1`,
`limits.max_connections_per_ip` must be raised to `limits.max_connections`.
Step-by-step instructions are in
[deploy/tor/README.md](../../deploy/tor/README.md).

Every per-IP limit becomes a global limit behind an onion service, since
all clients share `127.0.0.1`. For an onion relay:

- Raise `limits.sealed_recipients_per_minute_per_ip` (default 6000) and
  `limits.anonymous_lookups_per_hour_per_ip` (default 1200) to the total
  the relay should accept from all clients together, for example 10 to 50
  times the defaults for a few hundred users. Only entries and lookups
  whose access proof the relay accepts spend these budgets; refused ones
  spend only their own connection's refusal budget (256 at once, then 256
  per minute), so clients without valid access keys cannot exhaust the
  shared budget for everybody. Clients that hold a valid key still can,
  up to the per-connection limits per connection; the defences below
  bound how many connections they open.
- In `torrc`, enable `HiddenServicePoWDefensesEnabled 1` (Tor 0.4.8 or
  later) so that introduction floods cost the client proof-of-work, and
  set `HiddenServiceMaxStreams` (for example 64, with
  `HiddenServiceMaxStreamsCloseCircuit 1`) so that one circuit cannot open
  an unbounded number of streams. Together they replace the per-IP
  connection limit the relay can no longer apply.

### Security notes

- TLS pinning stays mandatory over Tor. A stolen onion service key lets an
  attacker publish the onion address but not pass the client's pin check,
  and the inner TLS adds a post-quantum key exchange that Tor's onion
  service protocol lacks.
- Tor hides network addresses, not identities: the relay still sees which
  identity authenticates and, for queued messages, the sender and recipient
  IDs. Sealed sender and padding address those separately.
- The proxy sees only the destination name and port and an opaque TLS
  stream. A non-Tor SOCKS5 proxy given with `--socks5` learns the server
  name and the client's address; the status bar still says `Tor: on`, since
  the client cannot tell what the proxy is.
- Timing correlation by an adversary who watches both the client's and the
  relay's network is outside Tor's threat model and outside this phase.

## Sealed sender

Goal: the relay must not learn who sent a message. Until now `Send` and
`SendMulti` run on an authenticated connection, so the relay knows the
sender ID of every message and stores it in the queue. Sealed sender moves
sending onto a separate, anonymous connection and the sender ID into the
end-to-end encrypted payload.

### Unidentified delivery access

Without authentication anyone could fill a user's queue, so a sealed send
must prove that the recipient allowed the sender to write to it.

```
AccessKey = 16 random bytes, one per user (package internal/sealed)
Verifier  = HMAC-SHA256(AccessKey, "qchat/v1/access-verifier")   // 32 bytes
```

- The user shares its `AccessKey` with contacts and group members inside the
  end-to-end encrypted channel (application layer), and uploads only the
  `Verifier` on its authenticated connection:
  `SetAccessKey{1: Verifier [32], 2: AllowUnidentified bool (omitted when false)}`,
  answered by an empty `AccessKeySet{}`. The relay stores one verifier per
  identity (serverdb table `access_keys`, deleted with the identity); a new
  upload replaces the old one, which is how a user revokes access.
- `AllowUnidentified` lets anyone send sealed messages to the user without a
  valid proof. It is off by default.
- A sender proves access with `AccessProof = Verifier` of the recipient. The
  relay stores only `SHA-256(Verifier)` (serverdb schema version 5, column
  `verifier_hash`; the migration hashed existing rows in place) and
  compares `SHA-256(AccessProof)` with it in constant time. The proof is a
  bearer token: the live relay sees it on every sealed send and can use it,
  which gives it nothing it could not do anyway, since it can inject any
  queue row. A copy of the database alone, however, no longer holds working
  proofs. The access key itself never reaches the relay.
- An all-zero verifier is rejected (`SetAccessKey` is malformed, and
  `serverdb.SetAccessKey` refuses it); migration 5 deleted stored ones.

### Frames (wire version 1, new types 24 to 27)

```
C→S  SetAccessKey{1: Verifier [32], 2: AllowUnidentified}    authenticated only
S→C  AccessKeySet{}
C→S  SealedSend{1: To [32], 2: AccessProof [32], 3: Payload}  anonymous only
S→C  SendResult{Accepted}   or Error NotFound / QueueFull / TooLarge / RateLimited
C→S  SealedSendMulti{1: Entries [{1: To, 2: AccessProof}] (1..256, distinct To),
                     2: Payload (at most MaxSealedMultiPayloadSize)}
S→C  SendMultiResult{Accepted, Failed, Reasons}   (NotFound / QueueFull per entry)
S→C  Deliver{From = 32 zero bytes, Payload, QueueID}
C→S  KeyRequest{1: ID [32], 2: AccessProof [32]}          anonymous only
S→C  KeyResponse{Bundle}    or Error NotFound / RateLimited
C→S  PrekeyRequest{1: ID [32], 2: AccessProof [32]}       anonymous only
S→C  PrekeyResponse{Bundle, SignedPrekey, OneTimePrekey}  or Error NotFound / RateLimited
```

`AccessProof` in `KeyRequest` and `PrekeyRequest` is an optional field
(omitted when absent, so the encoding of identified requests is
unchanged). With it, the request is an **anonymous lookup**: it locks an
undecided connection into anonymous mode like a sealed send, is a fatal
BadRequest on a connection that registered or began authentication, and
is answered only if the proof grants access to `ID` exactly as for a
`SealedSend`; an unknown ID, a refused proof and (for prekeys) an ID
without a signed prekey all answer NotFound. Without it the request needs
an authenticated connection as before. A sealed sender can therefore fetch
a contact's bundle and prekeys without the relay learning who asked, which
the identified lookup used to reveal right before the first sealed
message.

- **Anonymous connection.** Sealed frames are accepted only on a connection
  that has completed Hello/Welcome and has never sent `Register`,
  `AuthBegin` or `AuthProof`. The first sealed frame locks the connection
  into anonymous mode; from then on `Register` and `AuthBegin` close it with
  a fatal BadRequest, and a sealed frame on a connection that registered or
  started authentication is closed the same way. The relay therefore never
  sees a sealed message and an identity on the same connection. Key and
  prekey requests without a proof, `Ack`, `SetAccessKey` and the other
  authenticated requests keep answering Unauthorized on an anonymous
  connection.
- **No oracle.** An unknown recipient, a recipient without a verifier and a
  wrong proof all answer NotFound. The relay looks the recipient up and runs
  the same constant-time comparison (against a fixed dummy verifier when
  there is none) in every case. QueueFull is reported only after the proof
  was accepted, so it tells nothing to someone without a proof.
- **Delivery.** Sealed messages reuse `Deliver` with an all-zero `From`
  (`protocol.SealedFrom`; no identity has the zero ID, which would be a
  SHA-256 preimage). A new frame type would hide nothing more, and clients
  that predate sealed sender fail closed: they find no session for the zero
  ID and drop the message. The recipient learns the sender only from inside
  the payload.
- **Queue rows.** Schema version 4 makes `queue.sender` nullable; sealed rows
  store NULL. A sealed row is pushed after authentication exactly like an
  identified one, with the zero `From`. The stored expiry of every row,
  sealed or identified, is `undelivered_ttl` after storage rounded up to
  the next full hour, so a copy of the database dates a message only to
  the hour and does not tell the two kinds apart by their expiry.
- **Sealed queue share.** Sealed rows count toward `max_queued_messages`
  and `max_queued_bytes` like any other, and in addition are capped per
  recipient at `limits.max_queued_sealed_messages` (default 500) and half
  of `max_queued_bytes`. Anyone who holds a recipient's access key (every
  contact and group member) can send sealed junk; the cap keeps that junk
  from filling the queue identified senders need, and QueueFull for sealed
  sends says nothing about identified traffic.

### Sealed payload (package `internal/sealed`)

```
SealedEnvelope = {1: Version = 2, 2: Box}
Box            = sealbox.Seal(recipient KEM key,
                              info = "qchat/v1/sealed" || RecipientID,
                              Pad({1: SenderID [32], 2: Inner}))
Pad            = padding scheme of internal/padding (0x80, zeros) to the
                 smallest of 32, 64, 128, 256 KiB that holds the content
Seal(sender identity.ID, recipient *identity.Bundle, inner) -> envelope
Open(recipient (ID + OpenBox), envelope) -> (ClaimedSender, Inner)
IsEnvelope(b) // prefix a2 01 02 02, distinct from e2e and group envelopes
```

- **Padding.** Version 1 sealed the CBOR content unpadded, so the relay
  saw the inner envelope's exact length: whether it carried a session Init
  (about 13 KB for a typical bundle, at most 23,181 bytes) and the CBOR
  widths of the ratchet header counters and of the one-time prekey ID in
  the Init. Version 2 pads the content inside the HPKE box, with a floor
  of 32 KiB (`sealed.MinPaddedSize`) chosen to hold Init + header + a
  small padded body, and `Open` unpads strictly: the plaintext must be
  exactly one of the four buckets and end in valid padding, otherwise
  `ErrMalformed`. Version 1 envelopes are rejected with
  `ErrUnsupportedVersion`. A sealed envelope is exactly one of four sizes:
  32 KiB + 1,143, or 64, 128 or 256 KiB + 1,145 (`sealed.MaxOverhead` =
  HPKE overhead 1,136 + 9 bytes of CBOR framing; the 32 KiB box has a
  two-byte shorter length header). Every typical text message, with or
  without Init, is the 32 KiB size.
- **Size limits.** `sealed.MaxInnerSize` = 256 KiB - 43 = 262,101 bytes
  and `sealed.MaxEnvelopeSize` = 256 KiB + 1,145 = 263,289 bytes, below
  `protocol.MaxPayloadSize`. The largest pairwise envelope (158,429 bytes)
  lands in the 256 KiB bucket, so the default `limits.max_message_size`
  was raised from 256 KiB to 264 KiB (270,336); relays configured below
  263,289 refuse the largest sealed messages with TooLarge.
- **One-time prekey IDs.** The relay knows which one-time prekey it handed
  to which lookup. The ID returned in an Init travels only inside the
  sealed, padded box, so neither its value nor its CBOR width reaches the
  relay; with anonymous lookups the relay also does not learn which
  identity fetched the prekey.
- **Cost.** Every sealed pairwise message costs at least about 33 KiB on
  the wire and in the queue, against about 3 KiB identified. This is the
  price of hiding the Init; it is also why sealed rows have their own
  share of the queue byte limit.

- **Pairwise:** the sender wraps each pairwise `e2e` envelope with
  `sealed.Seal` to the recipient and sends it with `SealedSend`. The HPKE
  box hides the sender ID from the relay and binds the envelope to the
  recipient ID.
- **Groups:** group envelopes (senderkey v5) already carry the sender ID
  only inside the encrypted header, so the one ciphertext is sent with
  `SealedSendMulti` without an outer layer, keeping store-once fan-out. An
  outer seal per member would need one payload per member.
- **The claimed sender is not authenticated by the seal.** Anyone can seal
  any SenderID to anyone. The inner layer authenticates it: the pairwise
  ratchet AEAD and the session Init signature are bound to the sender ID,
  and group envelopes carry the sender's hybrid signature. The application
  routes by the claimed sender, opens the inner layer with that sender's
  state and treats any failure as a drop that changes no state. It never
  shows or acts on the claimed ID before the inner layer has verified it.
- Strict canonical CBOR; unknown version: `ErrUnsupportedVersion`; any
  decryption failure: `ErrDecrypt`; bad padding and the zero sender ID:
  `ErrMalformed`.

### Anti-abuse

- On an anonymous connection, every sealed recipient (one per `SealedSend`,
  one per entry of `SealedSendMulti`) first spends a token from a
  per-connection bucket of `limits.sealed_recipients_per_minute` (default
  3000, burst 512), whatever its proof.
- The proofs are then checked, and the outcome is charged: each **granted**
  entry spends a token from the per-IP bucket of
  `limits.sealed_recipients_per_minute_per_ip` (default 6000, burst 1024;
  IPv6 by /64), each **refused** entry a token from a cheap per-connection
  refusal budget (burst 256, 256 per minute, not configurable). Before
  this change refused entries spent the per-IP bucket too, so behind an
  onion service, where the per-IP bucket is global, anyone could exhaust
  sealed sending for every user with junk proofs. A request that cannot
  get its tokens after a short wait is rejected with RateLimited and
  nothing is stored. RateLimited after the check reveals nothing a NotFound
  or an acceptance would not.
- Anonymous lookups spend one token of the connection's
  `limits.prekey_requests_per_hour` bucket, then, after the proof check,
  either a token of the per-IP lookup bucket
  `limits.anonymous_lookups_per_hour_per_ip` (default 1200, burst 120) if
  granted, or a token of the same refusal budget if refused. Holders of a
  valid access key can drain a contact's one-time prekeys anonymously,
  bounded by these buckets; the client then falls back to the signed
  prekey alone.
- The per-IP buckets live in memory only, are dropped once full again, are
  capped in number and are never logged. See "Server: onion service" for
  onion deployments.
- The frame rate limit, `max_message_size`, the 64 MiB fan-out cap and the
  recipient's queue limits (including the sealed share) apply as for
  identified sends.

### Client (`internal/client`)

- `Options.Anonymous` opens connections that neither register nor
  authenticate; `Request` then allows only `SealedSend`, `SealedSendMulti`
  and `KeyRequest` / `PrekeyRequest` carrying an access proof, and an
  authenticated session refuses those (`ErrWrongSession`). Helpers:
  `SetAccessKey`, `SealedSend`, `SealedSendMulti`,
  `AnonKeyRequest(ctx, id, proof) ([]byte, error)` and
  `AnonPrekeyRequest(ctx, id, proof) (protocol.PrekeyResponse, error)`;
  the caller verifies what they return exactly as for identified lookups.
- A Deliver on an anonymous connection is a protocol violation.
- **Tor:** each Session must use its own circuit, or the shared circuit
  links the anonymous connection to the authenticated one. The anonymous
  session's dialer is built with a fresh isolation token
  (`client.NewIsolationToken()` passed to `transport.SOCKS5Dialer`).
- **No automatic reconnect.** A Session reuses its dialer, and so its
  isolation token, for every reconnect, which would put the new anonymous
  connection on the old one's circuit and link the two. An anonymous
  Session therefore does not reconnect: when its connection fails or
  ends, `Run` emits `StateChanged{Failed}` with an error wrapping
  `client.ErrAnonymousSessionEnded` and returns it. The application
  starts a new Session with a fresh token. `Options.AnonymousReconnect`
  restores the old behaviour for callers that accept the linkage.

### What it hides and what it does not

- Hidden from the relay's database and anyone who later reads it: who sent
  a stored message. Hidden from the live relay, given separate circuits or
  addresses: which identity sent a sealed message.
- Not hidden: the recipient, the payload size bucket and timing. Without Tor
  (or over a shared circuit) the relay links the anonymous and the
  authenticated connection by address. All sealed messages sent over one
  anonymous connection are linkable to each other, so clients should
  replace it (a new Session with a new token) from time to time.

#### What sealed sender does NOT hide

An honest list of what the relay, or someone with its database and
traffic, can still learn:

- **Group fan-out complement.** A `SealedSendMulti` names every recipient.
  If the sender left itself out, the one group member missing from the
  list would be the sender. Mitigation (application rule): the sender
  includes itself in the recipient list of its own group messages, so the
  list is the whole membership for every sender. The membership itself
  remains visible.
- **Access-key redistribution bursts.** When a user rotates its access key
  it sends the new key to all its contacts at once. That burst of messages
  from one client, shortly after a `SetAccessKey`, outlines its contact
  list (by recipient) even when every message is sealed.
- **Control traffic size.** Sealed pairwise messages all share the 32 KiB
  floor, but identified small messages and control messages are in the
  512 B to 4 KiB buckets of the inner padding. Traffic not sent sealed
  remains distinguishable by size; only the sealed floor makes sealed
  control and text messages look alike.
- **Recipient-set fingerprint per anonymous connection.** Everything sent
  over one anonymous connection is linkable, so the set of recipients it
  addresses (plus its lookups) is a fingerprint that often identifies the
  sender. Replacing the anonymous Session regularly limits it; the client
  no longer reconnects with the same token on its own.
- **Connection timing without Tor.** Without Tor the relay sees the same
  address on the authenticated and the anonymous connection, and even
  with separate addresses it can correlate a sealed message with activity
  (or a reply) on an authenticated connection by timing.
- **Onion operator stream linking.** Over an onion service, streams that
  share one Tor circuit arrive together; a relay operator who also runs
  the onion service can tell which streams came over the same circuit.
  Separate isolation tokens per Session, and a fresh token for each new
  anonymous Session, keep the anonymous and authenticated streams on
  different circuits; nothing hides streams that share one.
- **First contact is identified** unless the recipient set
  `AllowUnidentified`: before a sender has received the recipient's access
  key it has no proof, so its first message (typically the one carrying
  the Init) goes over the authenticated connection, naming the sender.
- **No automatic fallback rule.** The protocol does not say when a client
  should fall back from sealed to identified sending (for example after a
  NotFound caused by a rotated key). Every fallback reveals the sender for
  that message, and a relay that answers NotFound on purpose can force it;
  the decision is left to the application and should be visible to the
  user.
- Payload size bucket, timing, frequency, recipient IDs and online
  patterns, as for identified traffic.
