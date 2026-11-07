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
- **Harvest-now-decrypt-later quantum adversary.** Hybrid post-quantum constructions are used throughout (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65), so confidentiality and authenticity hold as long as at least one component remains unbroken.
- **Stolen device.** Local data is encrypted with a key derived from the user's passphrase using Argon2id.

### Metadata minimisation goals

The server never logs IP addresses. Planned measures include sealed sender, padding to size buckets and an optional Tor onion service. These are goals for later phases, not current guarantees.

### NOT protected

- A compromised or malware-infected endpoint while the application is unlocked.
- Screen capture and keyboard capture.
- Weak passphrases.
- Users who do not verify safety numbers: a first-contact MITM by the server is possible until keys are verified out of band.
- Traffic analysis by a global passive adversary (timing and volume), even with Tor and padding.
- The server learning online presence and connection timing.
- Denial of service by the server (it can drop or delay messages).
- Side channels in dependencies.
- Bugs in unaudited code.
- Lack of guaranteed memory zeroization: Go's garbage collector may copy secrets in memory.

## Protections by phase

| Phase | Protections available |
|-------|-----------------------|
| 1 (current) | Transport only: TLS 1.3 with X25519MLKEM768 and SPKI pinning. **No end-to-end encryption yet**; the relay can read message content. |
| 2 | Hybrid identity keys; 1:1 end-to-end encrypted messages. |
| 3 | Forward secrecy via Double Ratchet; prekeys; ciphertext-only offline delivery. |
| 4 | Group messaging with key rotation on member removal. |
| 5 | Sealed sender, padding, optional Tor. |
| 6-8 | Installer builder, UI, tests, fuzzing, release pipeline. |

Planned phases are goals, not guarantees.

## Cryptographic choices

| Purpose | Primitive | Library |
|---------|-----------|---------|
| Transport | TLS 1.3, X25519MLKEM768 only | Go standard library `crypto/tls` |
| Key encapsulation (hybrid) | X25519 + ML-KEM-768, combined with HKDF | `crypto/ecdh`, `crypto/mlkem` |
| Signatures (hybrid) | Ed25519 + ML-DSA-65 | `crypto/ed25519`, `cloudflare/circl` |
| Authenticated encryption | XChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` |
| Passphrase key derivation | Argon2id | `golang.org/x/crypto/argon2` |
| Key derivation | HKDF | Go standard library `crypto/hkdf` |
| Initial key agreement / ratchet | PQXDH-style, Double Ratchet | Built from the primitives above (no new primitives) |
| Storage | SQLite | `modernc.org/sqlite` |

No home-grown cryptographic primitives are used.
