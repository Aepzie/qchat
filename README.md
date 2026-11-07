# qchat

An open-source, end-to-end-encrypted, post-quantum-hybrid terminal chat written in Go.

> **Warning: pre-alpha, unaudited.** qchat is under early development and has not been reviewed by an independent security auditor. Do not use it for anything sensitive until an independent security audit has been completed. In the current phase there is **no end-to-end encryption yet**; only the transport is protected. See [SECURITY.md](SECURITY.md).

## Overview

qchat consists of two binaries:

- `qchat-server`: a relay server (Linux and Windows).
- `qchat`: a terminal client built with Bubble Tea v2 and Lip Gloss v2.

A server operator can build clients with the server address and the server public-key fingerprint embedded, so users connect only to that pinned server.

## Features

Implemented (Phase 1, v0.1.0):

- TLS 1.3 transport restricted to the hybrid key exchange X25519MLKEM768
- Server certificate pinning by SPKI SHA-256 (no public CA trust)
- Versioned CBOR wire frames with strict decoding
- Relay server commands: `init`, `run`, `fingerprint`
- Basic terminal UI skeleton

Planned:

- Hybrid identity keys: Ed25519 + ML-DSA-65 signatures
- Hybrid key encapsulation: X25519 + ML-KEM-768, combined with HKDF
- PQXDH-style initial key agreement and Double Ratchet (forward secrecy)
- Offline delivery with prekeys; the relay stores only ciphertext until delivery
- Group chats with key rotation on member removal
- Metadata protection: sealed sender, padding to size buckets, optional Tor onion service
- Local key storage encrypted with a key derived by Argon2id
- Client installer builder with embedded server configuration
- File transfer and themes

## Architecture

```
+----------+                                         +----------+
|  qchat   |  <== WebSocket over TLS 1.3 ==>         |  qchat-  |
|  client  |      (X25519MLKEM768 only,              |  server  |
|   TUI    |       SPKI SHA-256 pinned)              |  relay   |
+----------+                                         +----------+
                                                          |
                                                          v
                                                 SQLite (planned, Phase 3)
```

Frames on the wire are versioned CBOR messages. The relay never logs client IP addresses and, once end-to-end encryption is implemented, only handles ciphertext.

Planned cryptographic building blocks (established libraries only): Go standard library (`crypto/ecdh`, `crypto/mlkem`), `cloudflare/circl` (ML-DSA-65), XChaCha20-Poly1305, Argon2id, and `modernc.org/sqlite` (no CGO).

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Repository, skeleton, pinned TLS 1.3 server/client connection, simple TUI (v0.1.0) | Done |
| 2 | Identities, hybrid keys, 1:1 end-to-end messages | Planned |
| 3 | Forward secrecy (ratchet), prekeys, offline delivery | Planned |
| 4 | Groups, including key rotation | Planned |
| 5 | Metadata protection: sealed sender, padding, Tor | Planned |
| 6 | Client installer builder with embedded server config | Planned |
| 7 | TUI polish, files, themes | Planned |
| 8 | Tests, fuzzing, documentation, release pipeline | Planned |

## Build

Requires Go 1.27.3 or newer.

```sh
go build -o qchat-server ./cmd/server
go build -o qchat ./cmd/client
```

## Quick start

Initialise and run a server (default port 7443):

```sh
qchat-server init --data-dir ./data --host chat.example.org
qchat-server run --config ./data/server.toml
qchat-server fingerprint --data-dir ./data
```

Connect a client using the fingerprint printed above:

```sh
qchat --server chat.example.org:7443 --pin sha256:<hex>
```

A hardened systemd unit is provided in [`deploy/systemd/qchat-server.service`](deploy/systemd/qchat-server.service).

## Building pinned client installers (Phase 6)

The `server build-client` command and the installers are not implemented yet. The client already honours a build-time lock, so an operator can produce a locked client manually:

```sh
go build -o qchat -ldflags "-X github.com/craguS/qchat/internal/buildcfg.ServerAddr=chat.example.org:7443 -X github.com/craguS/qchat/internal/buildcfg.ServerPin=sha256:<hex>" ./cmd/client
```

A locked client refuses `--server`/`--pin` values that differ from the embedded ones.

## Screenshots (coming)

Screenshots will be added once the terminal UI is usable.

## Security

Please read [SECURITY.md](SECURITY.md) for the threat model, the list of what is not protected, and how to report vulnerabilities. Contribution rules are in [CONTRIBUTING.md](CONTRIBUTING.md); changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

qchat is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
