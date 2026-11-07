# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/craguS/qchat/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/craguS/qchat/releases/tag/v0.1.0
