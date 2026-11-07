# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-07

Adds identities and 1:1 end-to-end encrypted messages. This release has
**no forward secrecy** (Phase 3) and **no offline delivery**: messages only
reach recipients that are online.

### Added

- Hybrid identity signatures: Ed25519 and ML-DSA-65 (`crypto/mldsa`), both required.
- Self-authenticating identity IDs (`qc1-…`, SHA-256 of the signing key) and
  self-signed key bundles with serials for key rotation.
- 1:1 messages signed by the sender and sealed with HPKE (RFC 9180) using the
  hybrid KEM MLKEM768-X25519, sender and recipient IDs bound into the context.
- Passphrase-protected profiles: Argon2id + XChaCha20-Poly1305 key file and an
  encrypted local SQLite database with HMAC lookup keys and replay tombstones.
- Signal-compatible safety numbers with terminal QR codes (`/verify`, `/whoami`)
  and key-change warnings.
- Relay: registration with optional invite codes (`qchat-server invite
  create|list|prune`), challenge-response authentication bound to the server
  key and the TLS connection, key bundle lookup and online-only delivery.
- Client: profile creation and unlock screens, contacts, conversations,
  message requests from unknown senders, delivery status, `--profile`, `--invite`.
- Design document `docs/design/phase-2-identities.md`.

### Security

- Relay queues are bounded per session and server-wide in bytes, and the number
  of sessions per identity is capped.
- A missing local database is no longer silently recreated.
- On Windows the relay database lives in `db\` with write access for the
  service account while the key stays read-only; profile directories must be
  owned by the current user.

## [0.1.0] - 2026-11-07

First development preview. There is **no end-to-end encryption** in this
release; only the connection between client and relay is protected.

### Added

- Project skeleton, documentation, CI workflow and a hardened systemd unit.
- Versioned CBOR wire protocol with strict, canonical-only decoding and fuzz targets.
- TLS 1.3 transport restricted to the hybrid X25519MLKEM768 key exchange, with
  server SPKI SHA-256 pinning instead of CA trust; WebSocket compression disabled.
- Relay server `qchat-server` with `init`, `run`, `fingerprint` and `version`
  commands, Hello/Welcome version negotiation, ping/pong keepalive, per-session
  rate limiting and Windows service support.
- Terminal client `qchat` (Bubble Tea v2) with status bar, conversation sidebar,
  scrollable history, vim-like modes and a command palette. Notes typed in this
  version stay local.
- Build-time server lock for clients (`internal/buildcfg`) via `-ldflags -X`.

### Security

- Connection limits (global, per IP, pending handshakes) are enforced at accept
  time, before TLS; HTTP keep-alive is disabled and every connection must finish
  the upgrade within 10 seconds.
- `qchat-server init` creates the data directory and key with restrictive ACLs on
  Windows and refuses pre-existing directories that other accounts control.
- The server never logs client IP addresses or client-supplied data.
- A pinned-key mismatch blocks the connection and is never retried.

[Unreleased]: https://github.com/craguS/qchat/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/craguS/qchat/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/craguS/qchat/releases/tag/v0.1.0
