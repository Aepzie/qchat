# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- TUI themes `dusk` (default), `fjord`, `ember`, `contrast` and `paper`, with
  `/theme <name>` and completion. Themes with a background set the terminal
  background while the client runs; QR codes stay dark on light.
- Optional `tui.SettingsBackend`; the client stores `ui.theme` and
  `ui.markdown` in the encrypted settings table. Other settings are not
  reachable from the interface.
- Markdown rendering of message bodies with glamour, limited to emphasis,
  code spans, code blocks, lists and block quotes. Links show their address
  in brackets and are not clickable (no OSC 8), images show as
  `[image: alt]`, HTML is shown as text. Bodies of 8 KiB or more and bodies
  that fail to render fall back to plain text. `/markdown on|off`.
- `/search <text>` and `/search all <text>` with a results overlay; optional
  `tui.SearchBackend`, implemented by decrypting and scanning at most the
  2000 most recent messages of each conversation.
- `/help` opens a scrollable overlay with every command grouped by topic.
- End-to-end encrypted file transfer to contacts and groups
  (docs/design/phase-7-files.md): `/send <path>` (or `/file`), progress in
  the conversation, `/save` to list and `/save <n> [dir]` to save. Files of
  up to 64 MiB are sealed in 48 KiB chunks with XChaCha20-Poly1305 under a
  random per-file key, sent as new message kinds 5 (offer) and 6 (chunk)
  inside the existing sessions and sender keys, verified per chunk and by
  SHA-256, and kept encrypted in the profile's `files` directory until
  saved. Saving never overwrites a file; sender file names are sanitised.
  Incomplete transfers expire after 24 hours. Files from identities that
  are not contacts are dropped.
- Disappearing messages per conversation with `/timer off|30s|5m|1h|1d|1w`,
  agreed in-band with message kind 7 (the latest setting wins). A sweeper
  deletes expired messages and their files from the database and the view.
- Package `filexfer`; optional `tui.FileBackend` and `tui.TimerBackend`.
- Client database schema 6: an `expires` column on messages and the `files`
  and `timers` tables.

### Decided against

- Typing indicators: they would disclose to the relay when and to whom the
  user is writing, in real time.

## [0.6.0] - 2026-11-08

Pinned client installers, reproducible builds and a signed release pipeline.

### Added

- `qchat-server build-client`: builds clients locked to the server's
  address and public key fingerprint for Linux, Windows and macOS (amd64,
  arm64) from a qchat source tree, and writes `SHA256SUMS`. It reads only
  the configuration and certificate, never the private key.
- Reproducible client builds (`CGO_ENABLED=0`, `-trimpath`,
  `-buildvcs=false`, empty build ID, build-affecting environment variables
  overridden), verified by a test that builds twice and compares the output.
- Release pipeline: `.goreleaser.yaml` for server and client archives,
  checksums, SBOMs, server `.deb`/`.rpm` packages with a systemd unit and a
  `qchat` system user, and a keyless cosign signature of the checksum file;
  `.github/workflows/release.yml` runs it on `v*` tags.
- Installer configurations for pinned clients: Inno Setup script for Windows
  (`packaging/windows/qchat.iss`) and an nfpm configuration for Linux.
- `packaging/README.md`: building pinned installers, Authenticode and
  Developer ID signing with notarization, and verifying checksums and cosign
  signatures.

## [0.5.0] - 2026-11-08

Metadata protection: padding, sealed sender and optional Tor. The sealed-sender
construction is composed from standard primitives and has not been
independently analysed. Envelopes of earlier versions are not accepted.

### Added

- Padding (`internal/padding`): plaintexts are padded inside the encryption to
  buckets of 512 B, 1, 2, 4, 8, 16, 32, 64, 128 or 256 KiB with a strict,
  constant-time-scanning unpad. Applied to pairwise messages (envelope
  version 3) and group messages (group envelope version 5).
- Sealed sender (`internal/sealed`): per-user access keys, access verifiers
  uploaded with `SetAccessKey`, and the frames `SealedSend` and
  `SealedSendMulti`. Sealed messages arrive as `Deliver` with an all-zero
  sender and carry the sender ID inside an HPKE box. Group messages are sent
  with one ciphertext and no outer layer.
- Anonymous connections: a connection that sends a sealed frame can never
  register or authenticate; the client opens separate anonymous sessions for
  sealed sending.
- Relay storage for access verifiers (table `access_keys`) and queue rows
  without a sender (schema version 4), and new limits
  `limits.sealed_recipients_per_minute` and
  `limits.sealed_recipients_per_minute_per_ip`.
- Tor support: `--tor` (`127.0.0.1:9050`) and `--socks5 HOST:PORT`, a minimal
  SOCKS5 client with no local name resolution, a fresh stream-isolation token
  per run and per anonymous session, strict reply parsing and bounded
  handshake time. The status bar shows `Tor: on`.
- Onion service deployment guide `deploy/tor/README.md`; v3 onion names are
  accepted by `qchat-server init --host`.
- Design document `docs/design/phase-5-metadata.md`.

### Changed

- Pairwise envelope version 2 became 3 and group envelope version 4 became 5;
  older versions are rejected (pre-1.0, no compatibility).
- With a proxy configured, every client connection (chat session and profile
  recovery lookup) is dialed through it, with no fallback to a direct
  connection.
- Behind an onion service all connections arrive from loopback, so operators
  raise `limits.max_connections_per_ip` and the per-IP sealed limit.

### Security

- Padding hides message length from the relay except for the bucket; it does
  not hide timing, counts, recipients or the unencrypted ratchet header.
- Sealed sends answer NotFound for an unknown recipient, a missing verifier
  and a wrong proof alike, using a constant-time comparison, so they are not
  an oracle for registered users.
- The sender claimed in a sealed envelope is never shown or acted on before
  the inner layer (ratchet, Init signature or group signature) verifies it.
- Changes from an internal review before release: the sealed content is
  padded to 32, 64, 128 or 256 KiB (sealed envelope version 2), bundles and
  prekeys of contacts are fetched anonymously with an access proof, the relay
  stores only hashes of access verifiers and caps sealed queue rows
  separately (`limits.max_queued_sealed_messages`), sealed group fan-outs
  include the sender itself, there is never an automatic fallback from sealed
  to identified sending, and anonymous sessions are replaced (with a fresh Tor
  isolation token) instead of reconnecting. The default
  `limits.max_message_size` is now 264 KiB.
- Known limits (see SECURITY.md): the first message to a new contact is
  identified; the set of recipients an anonymous connection writes to can
  fingerprint a contact list; without Tor the relay can link anonymous and
  authenticated connections by address and timing; Tor does not defend
  against a global passive adversary.

## [0.4.0] - 2026-11-08

Adds end-to-end encrypted groups. The group protocol is composed from
standard primitives (inspired by Signal's Sender Keys) and has not been
independently analysed.

### Added

- Groups of up to 256 members with admin-signed membership control messages
  (create, add, remove, promote, demote, rename, leave), epochs and state
  hashes, and verified control history for new members.
- Sender keys: one encryption per group message with a forward-only chain,
  salted per-message keys, key commitment and a per-generation hybrid
  Ed25519 + ML-DSA-65 signature; headers encrypted under a per-generation key.
- Rotation of every remaining member's sender key on removal or leave, after
  1000 messages or 7 days; older generations are frozen and pruned.
- Out-of-sync detection by binding each group message to the sender's group
  state.
- Relay `SendMulti` (frame 22) and `SendMultiResult` (frame 23): one payload
  stored once for many recipients, partial success, per-recipient budget
  `limits.multi_recipients_per_minute`.
- TUI: groups sidebar, group conversations, members overlay, invitations and
  `/group` commands.
- Design document `docs/design/phase-4-groups.md`, including an MLS evaluation.

### Changed

- Default `limits.prekey_requests_per_hour` raised from 30 to 120.

### Security

- Changes from an internal review before release: conflict resolution that
  cannot be won by grinding identity IDs, encrypted group headers, join
  history verification, fork detection, and bounded relay fan-out.

## [0.3.0] - 2026-11-08

Adds forward secrecy and offline delivery. The session protocol is composed
from standard primitives but has not been independently analysed. Sessions
and messages from v0.2.0 are not compatible.

### Added

- Hybrid KEM shared secrets via HPKE export-only (MLKEM768-X25519).
- Signed prekeys and one-time prekeys, verified by the relay against the
  owner's bundle; weekly rotation and automatic top-up in the client.
- KEM-based asynchronous session start inspired by PQXDH: encapsulations to
  the identity key, signed prekey and one-time prekey, signed and timestamped
  Init with a replay set.
- Per-direction KEM double ratchet with salted per-message keys, bounded and
  age-limited skipped keys and one-round-trip healing.
- Relay offline queue: ciphertext is stored until acknowledged or until
  `undelivered_ttl` (default 7 days); new limits `max_queued_messages`,
  `max_queued_bytes`, `prekey_requests_per_hour`.
- Design document `docs/design/phase-3-forward-secrecy.md`.

### Changed

- Message envelope version 2 replaces the Phase 2 static-key format.
- The relay answers every send with "accepted", so other users can no longer
  learn whether a recipient is online.

### Security

- Changes from an internal protocol review: Init freshness and replay
  protection, rollback-safe message keys, transcript hashes of the sender
  bundle and prekeys, shorter signed prekey lifetime aligned with the queue TTL.

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

[Unreleased]: https://github.com/craguS/qchat/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/craguS/qchat/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/craguS/qchat/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/craguS/qchat/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/craguS/qchat/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/craguS/qchat/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/craguS/qchat/releases/tag/v0.1.0
