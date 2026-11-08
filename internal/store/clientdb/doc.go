// Package clientdb is the client's local encrypted database (qchat.db).
//
// The database is a SQLite file opened through database/sql with the pure-Go
// modernc.org/sqlite driver, in WAL mode with a busy timeout and
// secure_delete=ON. Schema changes are applied by numbered migrations recorded
// in the schema_migrations table.
//
// # Keys
//
// The caller supplies a random 32-byte database key, normally taken from the
// passphrase vault. Two independent subkeys are derived from it with
// HKDF-SHA256 using distinct info labels: one encrypts row values, the other
// computes lookup columns. The raw database key is never used directly and no
// subkey serves two purposes.
//
// # Row format
//
// Every stored value is a CBOR-encoded record sealed with XChaCha20-Poly1305.
// The random 24-byte nonce is prepended to the ciphertext. The associated data
// is the table name, a zero byte and the row's lookup key (for messages also
// the local sequence number), so a ciphertext copied into another row or
// another table fails authentication. After decryption the identifiers inside
// the record are compared with the row they were read from.
//
// Lookup columns hold HMAC-SHA256(lookupKey, label || value), with a distinct
// label per kind of value. They allow equality lookups without revealing the
// identifier itself.
//
// A canary row in the meta table is written when the database is created.
// Opening an existing file with a different key fails to authenticate the
// canary and returns ErrWrongKey before any other row is touched.
//
// # What the file reveals
//
// Someone holding qchat.db but not the database key can see:
//
//   - the number of contacts, groups, messages, settings, ratchet sessions,
//     own prekey secrets and sender key states, and the size of every stored
//     value;
//   - which messages belong to the same conversation, because the peer column
//     is the same HMAC for every message of one contact or group, though not
//     whether a conversation is a 1:1 or a group conversation;
//   - which sender key states belong to the same group, and which of them
//     belong to the same member of that group (the grp and member columns),
//     and which row is the group's own sender key state (its member column
//     is empty); member columns are keyed by group, so one member's rows
//     cannot be linked across groups;
//   - the local, monotonically increasing sequence number of each message,
//     and therefore the relative order in which messages were stored;
//   - the number of messages ever stored, including those of deleted
//     contacts, because the seen table keeps one replay tombstone (the
//     message lookup HMAC, without any value) per appended message;
//   - the number of session starts in the replay set (seen_inits: a lookup
//     HMAC over the signed prekey ID and replay key, without any value) and
//     the expiry of each entry in Unix seconds; when every entry uses its
//     signed prekey's RetireAt, as recommended, the expiries only reveal how
//     many sessions each signed prekey started;
//   - for a disappearing message, when it expires, in whole Unix seconds
//     (the expires column the sweeper queries), and with it roughly when
//     it was sent or received;
//   - the number of file transfers (each row holds an encrypted record with
//     the file key) and of conversations with a disappearing message
//     timer, and which file transfer rows share an offer message lookup;
//   - the schema version.
//
// The file does not reveal contact IDs, display names, identity bundles,
// message IDs, message bodies, timestamps, statuses, setting values, which
// peers have a session, ratchet states, prekey kinds, IDs and keys, group
// IDs, group states (and with them names and members), message senders,
// sender key generations or sender key states.
//
// Group message rows share the messages table, its sequence and its replay
// tombstones with 1:1 messages, but are sealed under a different associated
// data domain, so a group row moved into a 1:1 conversation fails
// authentication.
//
// # What is not detected
//
// Tampering with a stored value is detected and reported as ErrCorrupt.
// The following changes by someone with write access to the file are not:
//
//   - deleting whole rows, including replay tombstones and replay set
//     entries, which re-enables the acceptance of the deleted messages and
//     session starts;
//   - rolling the whole file back to an earlier copy;
//   - per-row rollback: replacing a row's value with an older ciphertext of
//     the same row. The associated data binds a ciphertext to its table and
//     row, not to a version, so an earlier value of the same row still
//     authenticates. An attacker can thereby revert, for example, a
//     contact's Verified flag or KeyChangedAt, a pinned bundle and its
//     serial, a message status, or the own bundle serial setting. Rolling
//     back a session row restores an earlier ratchet state, and putting back
//     a copy of a deleted prekey row restores that prekey secret.
//
// Callers must therefore not rely on values stored here, such as bundle
// serials, for protection against an attacker who can write the file; the
// database protects confidentiality and detects forgery, not rollback.
//
// secure_delete overwrites freed pages with zeros. In WAL mode, old page
// images may remain in the -wal file until the next checkpoint; Close runs a
// truncating checkpoint to shrink that window.
//
// # Deleting secrets
//
// Forward secrecy needs deleted prekey private keys and ratchet states to be
// gone from the files, not just unreachable: someone who later learns the
// database key could otherwise decrypt an old copy of the row. Therefore
// DeletePrekeySecret, PruneRetiredPrekeys, DeleteSession, a CommitReceive
// that consumes a one-time prekey, DeleteGroup, the sender key deletions
// (DeleteMemberSenderKey, DeleteMemberSenderKeys, DeleteGroupSenderKeys),
// DeleteFileTransfer and a DeleteExpiredMessages that deleted something run
// PRAGMA wal_checkpoint(TRUNCATE) after committing. It copies every WAL
// frame into the main file, syncs it and truncates the -wal file to zero
// bytes, which removes the old page images; the main file then holds only
// the zeroed pages written by secure_delete. This costs a few extra writes
// and syncs per call (typically milliseconds on a small client database),
// which is why it is not done after ordinary writes. Superseded session and
// sender key states written by PutSession, CommitSend, CommitReceive,
// PutOwnSenderKey, PutMemberSenderKey, CommitGroupSend and
// CommitGroupReceive therefore stay in the -wal file until the next
// checkpoint (SQLite's automatic one or Close). Data already copied by the
// operating system or the storage device below the file level, such as SSD
// remapping or backups, is out of reach of any of this.
//
// # File permissions
//
// On Unix the database file is created (or tightened) with mode 0600, and
// SQLite gives the -wal and -shm files the same mode as the main file. On
// Windows no per-file ACL is set: the file inherits the ACL of its directory,
// so the caller must place it in a directory that only the user can access
// (the per-user application data directory does this by default).
package clientdb
