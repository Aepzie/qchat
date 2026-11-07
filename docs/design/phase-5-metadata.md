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

Integration (not yet wired in): `internal/e2e` pads the encoded `Plaintext`
before the ratchet AEAD and unpads after opening; `MaxCiphertextSize` and
`MaxEnvelopeSize` then have to be derived from the padded size of
`MaxPlaintextSize` instead of the plaintext size, and must stay below the
relay's `max_message_size`.

What it hides:

- The exact length of each message body; the relay learns only its bucket.
- Differences between short messages (a one-word reply and a 400-character
  paragraph look identical).

What it does not hide:

- The bucket itself, so very large payloads remain distinguishable from text.
- Timing, frequency and number of messages, sender and recipient IDs, the
  number of recipients, and online/offline patterns.
- Header size: the ratchet header (about 2.4 KB, dominated by the hybrid KEM
  public key and ciphertext) is larger than a padded small message and
  dominates the payload size of short messages, and its size may differ
  between messages that start a new epoch and those that do not. Header
  protection is a separate Phase 5 item.
- Anything visible to the peers themselves; padding is only against the relay
  and network observers.
