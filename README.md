# qchat

An open-source, end-to-end-encrypted, post-quantum-hybrid terminal chat written in Go.

> **Warning: pre-alpha, unaudited.** qchat is under early development and has not been reviewed by an independent security auditor. Do not use it for anything sensitive until an independent security audit has been completed. Since v0.3.0 1:1 messages use forward-secret sessions built from a KEM-based handshake and double ratchet that are composed from standard primitives but **not independently analysed**. See [SECURITY.md](SECURITY.md) for exactly what is and is not protected.

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
- Relay server commands: `init`, `run`, `fingerprint`, `invite create|list|prune`

Implemented (Phase 2, v0.2.0):

- Hybrid identity signatures: Ed25519 + ML-DSA-65, both required
- Self-authenticating IDs (`qc1-…`) and self-signed key bundles
- Passphrase-protected profile (Argon2id) and encrypted local database
- Safety numbers with terminal QR codes, key-change warnings
- Relay registration with invite codes, authentication bound to the TLS connection
- Terminal UI with contacts, conversations, message requests and delivery status

Implemented (Phase 3, v0.3.0):

- Signed hybrid prekeys (MLKEM768-X25519), rotated and topped up automatically
- KEM-based asynchronous session start inspired by PQXDH, with a signed, timestamped and replay-checked Init
- Per-direction hybrid KEM double ratchet: forward secrecy and post-compromise security
- Offline delivery: the relay stores only ciphertext until the recipient acknowledges it (default TTL 7 days)
- Send results no longer reveal whether a recipient is online

Implemented (Phase 4, v0.4.0):

- Groups up to 256 members with admins: `/group create|add|remove|admin|unadmin|rename|leave|accept|members`
- Sender keys with hybrid-signed messages and encrypted headers; key rotation on removal
- Verified join history for new members and out-of-sync detection
- Relay fan-out with `SendMulti`: payload stored once, partial delivery reporting

Implemented (Phase 5, v0.5.0):

- Padding of all end-to-end plaintexts to size buckets inside the encryption
- Sealed sender: separate anonymous sessions, access keys, anonymous key lookups; the relay stores no sender for sealed messages
- Optional Tor: `--tor` / `--socks5`, onion service deployment ([deploy/tor](deploy/tor/README.md))

Planned:

- Metadata protection: sealed sender, padding to size buckets, optional Tor onion service
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
                                   SQLite: identity bundles, prekeys,
                                   invite hashes, undelivered ciphertext
```

Frames on the wire are versioned CBOR messages. The relay never logs client IP addresses and only handles ciphertext.

Cryptographic building blocks (established libraries only): Go standard library (`crypto/tls`, `crypto/hpke`, `crypto/mldsa`, `crypto/ed25519`, `crypto/hkdf`, `crypto/hmac`), `golang.org/x/crypto` (XChaCha20-Poly1305, ChaCha20-Poly1305, Argon2id) and `modernc.org/sqlite` (no CGO). Details in [SECURITY.md](SECURITY.md) and [docs/design](docs/design).

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Repository, skeleton, pinned TLS 1.3 server/client connection, simple TUI (v0.1.0) | Done |
| 2 | Identities, hybrid keys, 1:1 end-to-end messages (v0.2.0) | Done |
| 3 | Forward secrecy (ratchet), prekeys, offline delivery (v0.3.0) | Done |
| 4 | Groups, including key rotation (v0.4.0) | Done |
| 5 | Metadata protection: sealed sender, padding, Tor (v0.5.0) | Done |
| 6 | Client installer builder with embedded server config (v0.6.0) | Done |
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

Registration requires an invite code by default (`registration = "invite"` in `server.toml`). Create one per user; it is shown only once:

```sh
qchat-server invite create --config ./data/server.toml --uses 1 --ttl 72h
```

Connect a client using the fingerprint printed by `init`. On first start the client creates a profile (display name and a passphrase of at least 12 characters):

```sh
qchat --server chat.example.org:7443 --pin sha256:<hex> --invite <CODE>
```

Then, inside the client:

- `/whoami` shows your ID (`qc1-…`) and a QR code; share it with your contact over a channel you trust.
- `/add <qc1-id> <name>` adds a contact; type to send end-to-end encrypted messages.
- `/verify` shows the 60-digit safety number and QR code; compare it with your contact and press `v`.

Messages to offline contacts are stored by the relay as ciphertext until the recipient comes online and acknowledges them (default up to 7 days).

Deployment guides: [`deploy/systemd`](deploy/systemd/README.md) (Linux) and [`deploy/windows`](deploy/windows/README.md) (Windows service). A hardened systemd unit is provided in [`deploy/systemd/qchat-server.service`](deploy/systemd/qchat-server.service).

## Building pinned client installers

A server operator builds clients that carry the server address and the fingerprint of the server's public key. A pinned client connects only to that server and rejects `--server`/`--pin` values that differ from the embedded ones, so users cannot be talked into pointing it at an impostor. Run this in a qchat source tree of the version to ship, with the Go toolchain from `go.mod`:

```sh
qchat-server build-client --config /etc/qchat/server.toml --server chat.example.org:7443 --version v0.5.0 --out ./qchat-clients
```

It writes `qchat_<version>_<os>_<arch>[.exe]` for Linux, Windows and macOS on amd64 and arm64 (narrow with `--targets windows/amd64,darwin/arm64`) and a `SHA256SUMS` file. Without `--server`, the first host name of the certificate and the listen port are used; `--source DIR` points to a source tree other than the current module. `build-client` reads only `server.toml` and the certificate, never the private key, and embeds only the address, the public fingerprint and the version. `qchat --version` on a pinned client prints `(locked to <address>)`.

Builds are reproducible: `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, `-ldflags "-s -w -buildid= ..."` and `GOENV=off` with pinned `GOFLAGS`, `GOEXPERIMENT` and architecture levels make the binaries depend only on the source tree, the exact Go toolchain and the embedded values, so anyone can rebuild them and compare `SHA256SUMS` (details and caveats in [`packaging/README.md`](packaging/README.md#reproducible-builds)).

[`packaging/README.md`](packaging/README.md) turns the binaries into installers: an Inno Setup installer for Windows ([`packaging/windows/qchat.iss`](packaging/windows/qchat.iss)), `.deb`/`.rpm` packages with nfpm, and a signed and notarized `.pkg` for macOS. It also explains Authenticode and Developer ID signing, without which SmartScreen and Gatekeeper warn users or block the client, and how to verify release checksums and cosign signatures. Tagged releases are built by GoReleaser ([`.goreleaser.yaml`](.goreleaser.yaml)), including server `.deb`/`.rpm` packages and a keyless cosign signature of the checksum file.

## Screenshots (coming)

Screenshots will be added once the terminal UI is usable.

## Security

Please read [SECURITY.md](SECURITY.md) for the threat model, the list of what is not protected, and how to report vulnerabilities. Contribution rules are in [CONTRIBUTING.md](CONTRIBUTING.md); changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

qchat is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
