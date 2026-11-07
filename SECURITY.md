# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately using GitHub Security Advisories: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open public issues for security problems.

- We aim to acknowledge reports within 7 days.
- We follow coordinated disclosure with a default window of 90 days.
- There is no bug bounty.
- Supported versions: only the latest release (the project is pre-1.0).

## Unaudited software

qchat has not been audited by an independent party. It is pre-alpha software. Do not rely on it to protect sensitive communications until an independent security audit has been completed and published.

## Threat model

### Assets

- Message content
- Private keys and group keys
- Contact graph (who talks to whom)
- Metadata (timing, size, presence, group membership)

### Adversaries and goals

- **Honest-but-curious or compromised relay server.** The server must never see plaintext, private keys, group keys or group names. Its view of metadata should be minimised.
- **Network attacker (active MITM or passive recorder).** Cannot read or modify traffic; the client pins the server key and does not trust public CAs.
- **Harvest-now-decrypt-later quantum adversary.** The design goal is hybrid post-quantum constructions throughout (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65), so confidentiality and authenticity hold as long as at least one component remains unbroken. As of Phase 2, the transport key exchange (X25519MLKEM768), message encryption (HPKE with MLKEM768-X25519) and user signatures (Ed25519 + ML-DSA-65, both must verify) are hybrid. The relay's TLS certificate key is still classical Ed25519: recorded traffic stays confidential against a future quantum computer, but such a computer could impersonate the pinned relay in a live connection. It still could not read or forge end-to-end messages, but it could receive a victim's ciphertexts and observe their metadata.
- **Stolen device.** Private keys and the local database key are sealed in `identity.qkey` with XChaCha20-Poly1305 under an Argon2id key (t=3, 64 MiB, p=4) derived from the passphrase (minimum 12 characters). Every value in the local SQLite database is encrypted; row counts and sizes remain visible. Someone with write access to the files can roll individual rows back to older versions without detection.

### Metadata minimisation goals

The server never logs IP addresses. Planned measures include sealed sender, padding to size buckets and an optional Tor onion service. These are goals for later phases, not current guarantees.

### NOT protected

- A compromised or malware-infected endpoint while the application is unlocked.
- Screen capture and keyboard capture.
- Weak passphrases.
- Users who obtain a contact's ID over an untrusted channel and never compare safety numbers. IDs are hashes of the signing keys, so the relay cannot substitute keys for a correct ID, but whoever controls the channel the ID was exchanged over can hand out their own ID instead.
- Traffic analysis by a global passive adversary (timing and volume), even with Tor and padding.
- The server learning online presence and connection timing. (Other users can no longer probe presence: since v0.3.0 the relay answers every send with "accepted".)
- **The session protocol is not an analysed protocol.** The prekey handshake and the KEM double ratchet (v0.3.0) are composed from standard primitives and inspired by Signal's PQXDH and Double Ratchet, but they are not Signal's protocols and have had no independent cryptographic analysis. See [docs/design/phase-3-forward-secrecy.md](docs/design/phase-3-forward-secrecy.md).
- Forward secrecy depends on deleted keys really being gone. qchat deletes consumed keys, uses SQLite `secure_delete` and checkpoints the WAL, but file-system journaling, SSD wear levelling, backups and Go's memory management may keep copies.
- Messages that start a session are signed and therefore non-repudiable towards the recipient (no deniability). Later messages are authenticated by the session keys only.
- Without a one-time prekey (pool drained, or withheld by the relay), the first messages of a session until the first reply are protected by the identity key and the signed prekey only (retained for up to 16 days).
- Post-compromise security needs traffic in both directions: after a state compromise a direction heals within one round trip, not while one side stays silent. Messages delayed by more than two ratchet epochs are lost (their keys are deleted).
- The relay sees sender ID, recipient ID, time and ciphertext size of every message and stores undelivered ciphertext with the sender ID for up to `undelivered_ttl` (default 7 days). Sealed sender and padding come in Phase 5.
- Messages sent with v0.2.0 (static keys, no forward secrecy) remain decryptable by whoever obtains that version's long-term key.
- A relay can serve an older, validly signed key bundle to someone who has never seen a newer one (first contact); later rollbacks are detected via the bundle serial.
- Denial of service by the server (it can drop or delay messages).
- Side channels in dependencies.
- Bugs in unaudited code.
- Lack of guaranteed memory zeroization: Go's garbage collector may copy secrets in memory.

## Protections by phase

| Phase | Protections available |
|-------|-----------------------|
| 1 (v0.1.0) | Transport only: TLS 1.3 with X25519MLKEM768 and SPKI pinning. No end-to-end encryption. |
| 2 (v0.2.0) | Hybrid identity keys; self-authenticating IDs; 1:1 end-to-end encrypted and signed messages (no forward secrecy); safety numbers; passphrase-encrypted local storage; online-only delivery. |
| 3 (v0.3.0, current) | Signed hybrid prekeys; KEM-based asynchronous session start; per-direction hybrid KEM double ratchet (forward secrecy, post-compromise security); ciphertext-only offline delivery with acknowledgements; no presence probing via send results. |
| 4 | Group messaging with key rotation on member removal. |
| 5 | Sealed sender, padding, optional Tor. |
| 6-8 | Installer builder, UI, tests, fuzzing, release pipeline. |

Planned phases are goals, not guarantees.

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
| Storage | SQLite | `modernc.org/sqlite` |

The full Phase 2 design is in [docs/design/phase-2-identities.md](docs/design/phase-2-identities.md).

No home-grown cryptographic primitives are used.
