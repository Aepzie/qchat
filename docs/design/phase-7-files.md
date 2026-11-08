# Phase 7 design: encrypted files and disappearing messages

Status: implemented on `feature/phase-7-files`. Builds on Phases 3 and 4:
files and timers are ordinary messages of the pairwise sessions and group
sender keys, so everything those phases guarantee (forward secrecy,
authenticity, post-removal security in groups) carries over. Nothing changes
on the relay.

> Like the earlier phases, this is a composition of standard primitives, not
> an analysed protocol. It has not been audited.

## Goals and non-goals

Goals:

- Send files of up to 64 MiB to a contact or a group, end-to-end encrypted,
  with the relay seeing only what it sees for any message (sender,
  recipients, time, size).
- Reject any tampering: every chunk is authenticated, the whole file is
  checked against a SHA-256 the sender committed to, and a file that fails
  either check is never offered for saving.
- Never let a sender choose a path, overwrite a file or smuggle terminal
  escapes through a file name.
- Keep received files encrypted at rest until the user saves one.
- Per-conversation disappearing messages that both sides agree on.

Non-goals: resumable uploads after a restart of the sender, previews or
thumbnails, streaming playback, transfers to identities that are not
contacts (pairwise) or not members (groups), hiding file sizes (padding is
Phase 5 work and applies to the chunk messages like to any other message).

## New message kinds

Package `e2e` gains three plaintext kinds. Each is accepted both over a
pairwise session and inside a group envelope; their bodies are binary.

| Kind | Name        | Body |
|------|-------------|------|
| 5    | file offer  | canonical CBOR `Offer` (package `filexfer`) |
| 6    | file chunk  | canonical CBOR `Chunk` (package `filexfer`) |
| 7    | timer       | 4 bytes: the timer in whole seconds, big endian, 0 = off |

```
Offer {1: FileID (16), 2: Name (1..255 bytes UTF-8), 3: Size (1..64 MiB),
       4: SHA-256 (32), 5: Chunks, 6: MIME (optional, informational), 7: Key (32)}
Chunk {1: FileID (16), 2: Index, 3: Total, 4: nonce (24) || ciphertext}
```

Decoding is strict in the style of package `e2e`: canonical encoding only,
no unknown or duplicate keys, sizes and counts checked (`Chunks` must equal
`ceil(Size / 48 KiB)`, `Index < Total <= 1366`, the sealed chunk must have
exactly the length its position implies).

## File transfer

### Sender

1. The file must be a regular file of 1 byte to 64 MiB
   (`filexfer.MaxFileSize`).
2. A random 16-byte file ID and a random 32-byte file key are drawn.
3. The file is read **once**: it is cut into 48 KiB chunks (the last one
   shorter), and each chunk is sealed with XChaCha20-Poly1305 under the
   file key, a random 24-byte nonce and the associated data
   `FileID || Index || Total` (both as big-endian uint32). The sealed chunks
   go straight into the sender's own file store and the SHA-256 of the
   plaintext is computed on the way. A file that is shorter or longer than
   its size when it was opened is refused, so the hash always matches what
   is sent.
4. The offer, carrying name (sanitised, see below), size, hash, chunk count,
   an optional MIME guess and the file key, is sent as a normal message of
   kind 5. It is stored in the conversation like a text message (the body
   is the file name, flagged as a file) together with a transfer record that
   keeps the encoded offer, file key included, in the encrypted client
   database.
5. The chunks follow as kind 6 messages in the background. They are sent
   strictly one after another: the next chunk leaves only after the relay
   answered the previous one (`SendResult` / `SendMultiResult`), and at most
   one per 100 ms, which keeps the client well below the relay's default
   per-session frame rate (20 frames/s, burst 40) even with acks and pings
   in between. A refused chunk is retried up to five times with exponential
   backoff from one second; then the transfer is marked failed.

**Double encryption.** Every chunk is already ciphertext under the file key
before it enters the normal end-to-end layer, where it is encrypted again by
the ratchet or the sender key. The inner layer is what makes the at-rest
format and the whole-file check possible (the receiver stores the sender's
sealed chunks as they are); the outer layer keeps the relay blind exactly as
for any message, provides sender authentication and forward secrecy, and
means a leaked file key alone does not expose chunks seen on the wire. The
cost is 40 bytes per chunk.

### Receiver

- Offers and chunks are accepted from **contacts only** over pairwise
  sessions, and from **current members** inside groups (the same checks as
  for group text). From anyone else the session is still advanced and the
  content is dropped, so a stranger cannot make the client store data.
- An offer creates a transfer record and an empty transfer file
  `files/incoming/<local>.part`, where `<local>` is a random **local** ID:
  no name or ID chosen by the sender ever reaches the file system. A second
  offer with the same (sender, file ID) is dropped.
- Each chunk is authenticated with the file key **before** it is written
  into its fixed-size slot of the transfer file (slot = presence marker +
  sealed chunk), so chunks may arrive in any order and duplicates are
  harmless. A chunk that does not authenticate, does not belong to a known
  receiving transfer or has the wrong position or length is dropped.
- The chunk is written before the session or sender key state that
  decrypted it is stored, so a local failure (disk full, database error)
  leaves the relay delivery unacknowledged and it is simply delivered and
  written again.
- When every slot is filled the whole file is verified again: every chunk is
  opened and the plaintext hashed; only if the SHA-256 matches the offer is
  the transfer file renamed to `files/<local>.qcf` and the transfer marked
  complete. Otherwise it is marked failed and its data deleted.
- Transfers that are still incomplete 24 hours after the offer arrived are
  marked expired and their data is deleted. Store files without a transfer
  record (left behind by a crash) are deleted by the same sweep.

### Files at rest

Received (and sent) files stay **encrypted at rest**: the store holds the
sender's sealed chunks, and the file key exists only in the transfer
record, which is sealed under the database key like every other row of the
client database. The store directories are created with mode 0700 (on
Windows they inherit the profile directory's ACL) and must be plain
directories; a symbolic link in their place is refused, and store
files are opened only after checking they are regular files.

`/save <n> [dir]` decrypts the file into a new file in `dir` (default: the
user's Downloads folder, else the home directory). The destination is
created with `O_CREAT|O_EXCL`, so it **never replaces** an existing file and
never follows a symbolic link at the final path component: if the name is
taken, `name (1).ext`, `name (2).ext` and so on are tried. Every chunk and
the SHA-256 are checked again while writing; on any failure the partial
output is removed. The saved copy is **not** encrypted; the interface says
so.

Deleting a file (contact removed, message expired) deletes its store file
and its transfer record; the database is checkpointed so the file key
leaves the WAL. As with all deletions, copies below the file level (SSD
remapping, backups) are out of reach.

### File names

`filexfer.SanitizeName` turns the offered name into one harmless path
component on every platform:

- only the part after the last `/` or `\` is kept (`..\..\x` becomes `x`);
- control characters, Unicode format characters (bidirectional overrides
  such as U+202E, isolates, zero-width characters) and invalid UTF-8 are
  removed, so `\x1b[2J.txt` becomes `[2J.txt`;
- characters Windows forbids (`<>:"|?*`) become `_`;
- leading dots and spaces and trailing dots and spaces are removed, so the
  result is never hidden, `.` or `..`;
- Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`,
  `LPT1`-`LPT9`, also with an extension such as `CON.txt`) get a `_` prefix;
- the result is cut to 200 bytes, keeping the extension; an empty result
  becomes `file`.

The interface additionally sanitises the name like any other text before
it is drawn.

### Limits

- 64 MiB per file, 48 KiB per chunk, 1366 chunks at most.
- The relay's queue limits apply to chunks like to any message. With the
  default relay configuration a recipient that is **offline** can queue at
  most 1000 messages and 64 MiB; a larger file to an offline recipient
  fails with "mailbox full" once the queue is full. Large files therefore
  need the recipient online (its client acknowledges chunks as they arrive).
  In a group, members whose queue is full miss chunks and their transfer
  expires; the sender is not told which members missed chunks.
- At 10 chunks per second a 64 MiB file takes a little over two minutes.
- Sender keys rotate every 1000 messages; a large group file therefore
  usually triggers one rotation, which is distributed pairwise before the
  next chunk and costs nothing else.

## Disappearing messages

Every conversation has a timer, off by default, set with
`/timer off|30s|5m|1h|1d|1w` (any whole number of seconds up to four
weeks is accepted by the backend).

- Setting the timer sends a kind 7 message to the other side (pairwise, or
  with the own sender key to the whole group), and the new timer applies
  locally once the relay accepted it.
- **Agreement:** each side keeps the timer together with the sender time of
  the timer message that set it. A received timer replaces the stored one
  if its sender time is later; of two with the same time, the longer timer
  wins. So when both sides change it at once, both end up with the same
  setting. Every change made by the other side is shown as a system line.
  Timer messages are accepted from contacts and group members only.
- A message filed while the timer is on stores its expiry: send time plus
  timer for an outgoing message, arrival time plus timer for an incoming
  one (the local clock, so a sender's clock cannot shorten or extend it).
  Messages filed before a change keep their expiry.
- A sweeper runs every two seconds while the client runs (and once at
  start). It deletes expired messages from the database for real (`DELETE`
  with `secure_delete=ON`, then a truncating WAL checkpoint), deletes the
  files they offered, drops expired message requests from memory, and tells
  the interface, which removes them from the view. The replay tombstone of
  each message stays, so a deleted message cannot be delivered again.

What disappearing messages do **not** do:

- They do not stop the other side from keeping a message: it can be
  copied, photographed, saved (files), or kept by a modified client that
  ignores the timer.
- A peer whose clock runs ahead can make its timer change win over a later
  one of yours; the timer is agreement between cooperating clients, not
  enforcement.
- The relay never had a readable copy; its encrypted copy is deleted when
  the recipient acknowledges it or when the undelivered-message TTL ends,
  independently of the timer.
- A message is only deleted while the client runs; a closed client deletes
  it on its next start.
- The database stores the expiry of each disappearing message in a plain
  column (rounded up to whole seconds) so the sweeper can find them
  without decrypting every row; someone holding the file therefore learns
  roughly when those messages were sent or received.

## Typing indicators

Still not implemented, by design (see the changelog): they would tell the
relay in real time when and to whom the user is writing.

## Tests

- `internal/filexfer`: out-of-order reassembly, tampered and misplaced
  chunks rejected, tampering at rest detected on save, wrong total hash
  rejected, size limits, file-changed-while-read detection, a name
  sanitising table (`..\..\x`, `CON.txt`, `\x1b[2J.txt`, bidi overrides,
  forbidden characters, long names) plus a fuzz target, save never
  overwrites, save does not follow a symbolic link, a linked store
  directory is refused.
- `internal/store/clientdb`: transfer records, timers, deletion of expired
  1:1 and group messages with replay tombstones kept and the row gone from
  the WAL.
- `internal/app` (with the fake relay): 1:1 and group transfers end to end,
  chunks delivered in reverse order, a forged chunk dropped mid-transfer,
  a wrong hash failing the transfer, size limits, files from strangers
  dropped, partial transfers expiring after 24 hours, timer agreement for
  crossing changes and ties, the sweeper deleting expired 1:1 and group
  messages and their files, files deleted with their contact.
- `internal/tui`: `/send` progress, incoming files with hostile names,
  `/save` listing and saving, `/timer`, removal of expired messages.
