# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project skeleton and documentation.
- Versioned CBOR wire protocol.
- TLS 1.3 transport restricted to X25519MLKEM768 key exchange, with server SPKI SHA-256 pinning.
- Relay server with `init`, `run` and `fingerprint` commands.
- Terminal UI client skeleton.
