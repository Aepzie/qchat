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
(131,088) + 64 = 158,429 bytes, below the relay's default
`max_message_size` of 256 KiB (262,144).

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
- Whether an Init is attached. A pairwise envelope carrying the handshake
  Init (the initiator's messages until the first reply) is several KB
  larger, and the Init field is visible in the unencrypted envelope
  structure. Envelopes with an Init are therefore deliberately **not**
  padded to a fixed size: as long as the field itself is readable, size
  padding would add bandwidth without hiding anything. Once the envelope
  is wrapped in an encrypted outer layer (sealed sender), that layer should
  pad its whole content to a bucket, which then also blurs the Init
  difference for small messages.
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
  relay compares it in constant time with the stored verifier. The proof is
  a bearer token: the relay, and anyone who reads its database, can use it
  to send sealed messages to that user. That gives the relay nothing it
  could not do anyway, since it can inject any queue row; the access key
  itself never reaches the relay.

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
```

- **Anonymous connection.** Sealed frames are accepted only on a connection
  that has completed Hello/Welcome and has never sent `Register`,
  `AuthBegin` or `AuthProof`. The first sealed frame locks the connection
  into anonymous mode; from then on `Register` and `AuthBegin` close it with
  a fatal BadRequest, and a sealed frame on a connection that registered or
  started authentication is closed the same way. The relay therefore never
  sees a sealed message and an identity on the same connection. Key,
  prekey, `Ack`, `SetAccessKey` and the other authenticated requests keep
  answering Unauthorized on an anonymous connection.
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
  identified one, with the zero `From`.

### Sealed payload (package `internal/sealed`)

```
SealedEnvelope = {1: Version = 1, 2: Box}
Box            = sealbox.Seal(recipient KEM key,
                              info = "qchat/v1/sealed" || RecipientID,
                              {1: SenderID [32], 2: Inner})
Seal(sender identity.ID, recipient *identity.Bundle, inner) -> envelope
Open(recipient (ID + OpenBox), envelope) -> (ClaimedSender, Inner)
IsEnvelope(b) // prefix a2 01 01 02, distinct from e2e and group envelopes
```

- **Pairwise:** the sender wraps each pairwise `e2e` envelope with
  `sealed.Seal` to the recipient and sends it with `SealedSend`. The HPKE
  box hides the sender ID from the relay and binds the envelope to the
  recipient ID.
- **Groups:** group envelopes (senderkey v4) already carry the sender ID
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
  decryption failure: `ErrDecrypt`; the zero sender ID is rejected. The
  outer layer adds at most `sealed.MaxOverhead` (1187) bytes.

### Anti-abuse

- On an anonymous connection, sealed recipients (one per `SealedSend`, one
  per entry of `SealedSendMulti`) spend tokens from a per-connection bucket
  of `limits.sealed_recipients_per_minute` (default 3000, burst 512) and a
  per-IP bucket of `limits.sealed_recipients_per_minute_per_ip` (default
  6000, burst 1024; IPv6 by /64). A request waits briefly for tokens like
  `SendMulti`; otherwise it is rejected with RateLimited and nothing is
  stored. The per-IP buckets live in memory only, are dropped once full
  again, are capped in number and are never logged. Behind a Tor onion
  service every client arrives from 127.0.0.1, so operators raise the
  per-IP limit as they do `max_connections_per_ip`.
- The frame rate limit, `max_message_size`, the 64 MiB fan-out cap and the
  recipient's queue limits apply as for identified sends.

### Client (`internal/client`)

- `Options.Anonymous` opens connections that neither register nor
  authenticate; `Request` then allows only `SealedSend` and
  `SealedSendMulti`, and an authenticated session refuses them
  (`ErrWrongSession`). Helpers: `SetAccessKey`, `SealedSend`,
  `SealedSendMulti`.
- A Deliver on an anonymous connection is a protocol violation.
- **Tor:** each Session must use its own circuit, or the shared circuit
  links the anonymous connection to the authenticated one. The anonymous
  session's dialer is built with a fresh isolation token
  (`client.NewIsolationToken()` passed to `transport.SOCKS5Dialer`), kept
  for that session's reconnects.

### What it hides and what it does not

- Hidden from the relay's database and anyone who later reads it: who sent
  a stored message. Hidden from the live relay, given separate circuits or
  addresses: which identity sent a sealed message.
- Not hidden: the recipient, the payload size bucket and timing. Without Tor
  (or over a shared circuit) the relay links the anonymous and the
  authenticated connection by address. All sealed messages sent over one
  anonymous connection are linkable to each other, so clients should
  reconnect it from time to time. Timing correlation (a sealed message
  arriving while the sender's authenticated connection is active, replies)
  remains possible. Group fan-out reveals the recipient list.
