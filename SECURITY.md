# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately using GitHub Security Advisories: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open public issues for security problems.

- We aim to acknowledge reports within 7 days.
- We follow coordinated disclosure with a default window of 90 days.
- There is no bug bounty.
- Supported versions: only the latest release (the project is pre-1.0).

## Unaudited software

qchat has not been audited by an independent party. Do not rely on it to protect sensitive communications until an independent security audit has been completed and published. The audit is the next planned step after Phase 8 (v0.8.0). Internal reviews were done during development, but they are not a substitute for independent analysis.

## Threat model

### Assets

- Message content and transferred files
- Private keys, session keys and group keys
- Contact graph (who talks to whom)
- Metadata (timing, size, presence, group membership)

### Adversaries and goals

- **Honest-but-curious or compromised relay server.** The server must never see plaintext, file contents, private keys, group keys or group names. Its view of metadata is minimised: message sizes are bucketed, stored messages do not name their sender when sealed sender is used, and the server never logs IP addresses.
- **Network attacker (active MITM or passive recorder).** Cannot read or modify traffic; the client pins the server key and does not trust public CAs. With Tor, the network also does not learn the relay's address from the client's traffic (and the other way round for an onion service).
- **Harvest-now-decrypt-later quantum adversary.** The design goal is hybrid post-quantum constructions throughout (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65), so confidentiality and authenticity hold as long as at least one component remains unbroken. The transport key exchange (X25519MLKEM768), message and session encryption (HPKE with MLKEM768-X25519) and user signatures (Ed25519 + ML-DSA-65, both must verify) are hybrid. The relay's TLS certificate key is still classical Ed25519: recorded traffic stays confidential against a future quantum computer, but such a computer could impersonate the pinned relay in a live connection. It still could not read or forge end-to-end messages, but it could receive a victim's ciphertexts and observe their metadata.
- **Stolen device.** Private keys and the local database key are sealed in `identity.qkey` with XChaCha20-Poly1305 under an Argon2id key (t=3, 64 MiB, p=4) derived from the passphrase (minimum 12 characters). Every value in the local SQLite database is encrypted, including received files; row counts and sizes remain visible. Someone with write access to the files can roll individual rows back to older versions without detection.

### Metadata minimisation (what it does)

- Padding hides the exact length of each message body from the relay; it sees only the size bucket.
- Sealed sender keeps the sender ID out of the relay's queue and, over separate connections or circuits, out of the relay's live view.
- Tor hides the client's IP address from the relay and the relay's location from the network, when the operator runs an onion service.
- The relay answers every send with "accepted", so other users cannot probe presence.
- There are no typing indicators.

These are mitigations with the limits listed below, not guarantees of anonymity.

## Protections by phase

| Phase | Protections available |
|-------|-----------------------|
| 1 (v0.1.0) | Transport only: TLS 1.3 with X25519MLKEM768 and SPKI pinning. No end-to-end encryption. |
| 2 (v0.2.0) | Hybrid identity keys; self-authenticating IDs; 1:1 end-to-end encrypted and signed messages (no forward secrecy); safety numbers; passphrase-encrypted local storage; online-only delivery. |
| 3 (v0.3.0) | Signed hybrid prekeys; KEM-based asynchronous session start; per-direction hybrid KEM double ratchet (forward secrecy, post-compromise security); ciphertext-only offline delivery with acknowledgements; no presence probing via send results. |
| 4 (v0.4.0) | Groups up to 256 members: admin-signed membership controls, sender keys with hybrid-signed messages and encrypted headers, key rotation by every remaining member on removal, verified join history, out-of-sync detection. |
| 5 (v0.5.0) | Padding to size buckets inside the encryption (pairwise and groups); sealed sender with access keys and anonymous connections; optional Tor through a SOCKS5 dialer with per-session stream isolation, and onion service deployment. |
| 6 (v0.6.0) | Pinned, reproducible client builds so users need not check a fingerprint by hand; checksums and a keyless cosign signature for releases; installers and packaging guidance. |
| 7 (v0.7.0) | Encrypted file transfer (per-file key, XChaCha20-Poly1305 chunks, files encrypted at rest); disappearing messages with a local sweeper; Markdown rendering that sanitises message text and never makes links clickable; encrypted local settings; history search without a plaintext index. |
| 8 (v0.8.0, current) | staticcheck and govulncheck clean (no reachable vulnerabilities); gosec findings fixed or justified in the code; additional fuzz targets for parsers of untrusted input; CI checks; release pipeline built with GoReleaser and signed with cosign. |

## Cryptographic choices

| Purpose | Primitive | Library |
|---------|-----------|---------|
| Transport | TLS 1.3, X25519MLKEM768 only | Go standard library `crypto/tls` |
| Message encryption (hybrid) | HPKE (RFC 9180) base mode, KEM MLKEM768-X25519, HKDF-SHA256, ChaCha20-Poly1305 | Go standard library `crypto/hpke` |
| Signatures (hybrid) | Ed25519 + ML-DSA-65, both required | `crypto/ed25519`, `crypto/mldsa` |
| Local authenticated encryption | XChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` |
| Passphrase key derivation | Argon2id | `golang.org/x/crypto/argon2` |
| Key derivation / lookup keys | HKDF-SHA256, HMAC-SHA256 | `crypto/hkdf`, `crypto/hmac` |
| Safety numbers | Signal displayable-fingerprint construction (iterated SHA-512) | `crypto/sha512` |
| Hybrid KEM shared secrets | HPKE export-only with MLKEM768-X25519 | `crypto/hpke` |
| Session start | KEM-based, PQXDH-inspired: encapsulations to identity key, signed prekey and one-time prekey, combined with HKDF; signed Init | Built from the primitives above (no new primitives) |
| Ratchet | Per-direction KEM double ratchet; HMAC-SHA256 chains; ChaCha20-Poly1305 with salted per-message keys | `crypto/hpke`, `crypto/hkdf`, `crypto/hmac`, `golang.org/x/crypto/chacha20poly1305` |
| Groups | Sender-key chains with salted per-message keys, key commitment, per-generation hybrid signature, encrypted headers | Primitives above |
| Padding | ISO/IEC 7816-4 style padding to buckets of 512 B to 256 KiB, applied inside the AEAD | `internal/padding` (framing, not a cryptographic primitive) |
| Sealed sender | HPKE box to the recipient's KEM key with the recipient ID in the context; access verifier HMAC-SHA256 | `crypto/hpke`, `crypto/hmac` |
| File transfer | 48 KiB chunks, XChaCha20-Poly1305 under a per-file key, sent inside the end-to-end layer | `golang.org/x/crypto/chacha20poly1305` |
| Tor transport | SOCKS5 (RFC 1928, CONNECT) with username/password stream isolation (RFC 1929); TLS and pinning run on top | Minimal client in `internal/transport`, no new dependency |
| Release signing | Keyless cosign signature of the checksum file, recorded in a transparency log | cosign (release pipeline only) |
| Storage | SQLite | `modernc.org/sqlite` |

Design documents are in [docs/design](docs/design). No home-grown cryptographic primitives are used.

## NOT protected

This list is consolidated from all phases. It is long on purpose.

### Endpoints and users

- A compromised or malware-infected endpoint while the application is unlocked.
- Screen capture and keyboard capture.
- Weak passphrases.
- Users who obtain a contact's ID over an untrusted channel and never compare safety numbers. IDs are hashes of the signing keys, so the relay cannot substitute keys for a correct ID, but whoever controls the channel the ID was exchanged over can hand out their own ID instead.
- Lack of guaranteed memory zeroization: Go's garbage collector may copy secrets in memory.
- Bugs in unaudited code, and side channels in dependencies.

### Local storage and deletion

- Forward secrecy depends on deleted keys really being gone. qchat deletes consumed keys, uses SQLite `secure_delete` and checkpoints the WAL, but file-system journaling, SSD wear levelling, backups and Go's memory management may keep copies.
- Disappearing messages and deleted files are removed from the local database by a sweeper, with the same limits: SSDs, backups, snapshots and journaling may retain copies. The timer is agreed in-band, so it relies on the other participant's client to honour it; a contact can keep, copy or photograph anything they receive.
- Files written with `/save` are plaintext on disk and are outside qchat's protection from then on.
- Someone with write access to the local files can roll individual rows back to older versions without detection. Row counts and sizes are visible.
- Search works by decrypting and scanning recent history, so plaintext exists in memory while searching.

### Protocol analysis

- **The session protocol is not an analysed protocol.** The prekey handshake and the KEM double ratchet are composed from standard primitives and inspired by Signal's PQXDH and Double Ratchet, but they are not Signal's protocols and have had no independent cryptographic analysis. See [docs/design/phase-3-forward-secrecy.md](docs/design/phase-3-forward-secrecy.md).
- **The group protocol is not an analysed protocol.** Groups are a composition inspired by Signal's Sender Keys, not MLS. See [docs/design/phase-4-groups.md](docs/design/phase-4-groups.md).
- **The sealed-sender construction is not an analysed protocol.** See [docs/design/phase-5-metadata.md](docs/design/phase-5-metadata.md).
- No deniability: messages that start a session are signed and therefore non-repudiable towards the recipient. Later messages are authenticated by the session keys only.
- Without a one-time prekey (pool drained, or withheld by the relay), the first messages of a session until the first reply are protected by the identity key and the signed prekey only (retained for up to 16 days).
- Post-compromise security needs traffic in both directions: after a state compromise a direction heals within one round trip, not while one side stays silent. Messages delayed by more than two ratchet epochs are lost (their keys are deleted).
- Messages sent with v0.2.0 (static keys, no forward secrecy) remain decryptable by whoever obtains that version's long-term key. Sessions and envelopes of earlier versions are not compatible with later ones.
- A relay can serve an older, validly signed key bundle to someone who has never seen a newer one (first contact); later rollbacks are detected via the bundle serial.

### Groups

- There is no ordering authority for membership changes: concurrent admin actions are resolved by a fixed rule (revocations beat grants, seniority decides between revocations), and a conflicting change that arrives late is dropped, so members can end up with different views. This is flagged ("out of sync") but not repaired automatically.
- Sender keys give forward secrecy per message chain but no post-compromise security except through rotation (on removal, after 1000 messages or 7 days). A removed member is cut off only once every remaining member has rotated.
- The relay sees the recipient list of every group message (approximating membership), the sender (unless the sender is sealed), and the size, but not group IDs, names or which group a message belongs to.

### What the relay sees

- The sender ID, recipient ID, time and ciphertext size bucket of every identified message, and undelivered ciphertext with the sender ID for up to `undelivered_ttl` (default 7 days). Sealed messages store no sender, see below.
- Online presence and connection timing. (Other users cannot probe presence: the relay answers every send with "accepted".)
- The ratchet header of pairwise messages is not encrypted: the relay reads the epoch, the counters and the ratchet public key. The header (about 2.4 KB) dominates the size of short messages.
- Whether a pairwise envelope carries a handshake Init: such envelopes are several KB larger and the field is visible. They are not padded to hide this.
- Large payloads (for example file chunks) are distinguishable from short text by their bucket, and the number and timing of chunks reveal that a transfer is happening and roughly how large it is.
- The relay can drop or delay messages (denial of service).

### Sealed sender

- The relay can still learn the sender from the network. Without Tor, or over a shared circuit, it links the anonymous and the authenticated connection by address. All sealed messages sent over one anonymous connection are linkable to each other, so clients should reconnect it from time to time.
- Timing correlation remains possible: a sealed message arriving while a sender's authenticated connection is active, and replies.
- The recipient is not hidden, and group fan-out reveals the recipient list.
- The access proof is a static bearer value (the verifier) that stays the same for all of a user's senders until the user revokes it by uploading a new one. It acts as a stable pseudonym for the recipient's contacts: anyone who holds it, including the relay and anyone who reads its database, can send sealed messages to that user, and the relay can link sealed sends that carry the same proof. It does not let anyone read messages.
- **First contact is identified.** Access keys for sealed sending are exchanged inside the encrypted session, so the first message to a new contact reveals the sender to the relay unless the recipient enabled `AllowUnidentified`. The set of recipients an anonymous connection writes to can fingerprint a contact list, and access-key redistribution after removing a contact reaches all remaining contacts within minutes.
- With `AllowUnidentified` enabled, anyone can send sealed messages to the user without a proof.
- The sender claimed inside a sealed envelope is not authenticated by the seal; the inner layer (ratchet AEAD, Init signature, group signature) authenticates it. Clients that predate sealed sender drop sealed messages.
- Sealed sending is anti-abuse limited per connection and per IP; behind an onion service every client arrives from 127.0.0.1, so operators must raise these limits, which weakens them.

### Padding

- Padding hides length only to bucket granularity (powers of two from 512 B to 256 KiB), not timing, frequency, number of messages, the number of recipients or online/offline patterns.
- The constant-time unpadding is best effort at the Go level, not a guarantee about the compiled code.
- Padding is only against the relay and network observers; peers see the true content.

### Tor

- Tor does not defend against a global passive adversary: traffic analysis (timing and volume), even with Tor and padding, can still correlate users. Timing correlation by an adversary who watches both the client's and the relay's network is outside Tor's threat model.
- Tor hides network addresses, not identities: the relay still sees which identity authenticates and, for identified messages, the sender and recipient IDs.
- A SOCKS5 proxy given with `--socks5` that is not Tor learns the server name and the client's address, and the status bar still reports `Tor: on` because the client cannot tell what the proxy is.
- A stolen onion service key lets an attacker publish the onion address, but not pass the client's pin check.
- Tor adds its own risks (exit and guard selection, circuit building, software vulnerabilities) that qchat does not control.

### Post-quantum

- The relay's TLS certificate key is still classical Ed25519. A future quantum computer could impersonate the pinned relay in a live connection (see the threat model above).

### Releases and installers

- A release or pinned installer is only as trustworthy as the channel through which its checksum or fingerprint was obtained. cosign verification proves a file came from this repository's release workflow, not that the source is free of bugs.
- Unsigned Windows and macOS binaries trigger SmartScreen or Gatekeeper warnings; code signing and notarization are the operator's responsibility.
- Reproducible builds let a second person confirm a pinned client, but only if they actually rebuild and compare.

### Other

- Server-side denial of service beyond the built-in connection and rate limits.
- Traffic analysis by a global passive adversary.
