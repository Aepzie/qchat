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
//   - the number of contacts, messages and settings, and the size of every
//     stored value;
//   - which messages belong to the same conversation, because the peer column
//     is the same HMAC for every message of one contact;
//   - the local, monotonically increasing sequence number of each message,
//     and therefore the relative order in which messages were stored;
//   - the number of messages ever stored, including those of deleted
//     contacts, because the seen table keeps one replay tombstone (the
//     message lookup HMAC, without any value) per appended message;
//   - the schema version.
//
// The file does not reveal contact IDs, display names, identity bundles,
// message IDs, message bodies, timestamps, statuses or setting values.
//
// # What is not detected
//
// Tampering with a stored value is detected and reported as ErrCorrupt.
// The following changes by someone with write access to the file are not:
//
//   - deleting whole rows, including replay tombstones, which re-enables
//     the acceptance of the deleted messages;
//   - rolling the whole file back to an earlier copy;
//   - per-row rollback: replacing a row's value with an older ciphertext of
//     the same row. The associated data binds a ciphertext to its table and
//     row, not to a version, so an earlier value of the same row still
//     authenticates. An attacker can thereby revert, for example, a
//     contact's Verified flag or KeyChangedAt, a pinned bundle and its
//     serial, a message status, or the own bundle serial setting.
//
// Callers must therefore not rely on values stored here, such as bundle
// serials, for protection against an attacker who can write the file; the
// database protects confidentiality and detects forgery, not rollback.
//
// secure_delete overwrites freed pages with zeros. In WAL mode, old page
// images may remain in the -wal file until the next checkpoint; Close runs a
// truncating checkpoint to shrink that window.
//
// # File permissions
//
// On Unix the database file is created (or tightened) with mode 0600, and
// SQLite gives the -wal and -shm files the same mode as the main file. On
// Windows no per-file ACL is set: the file inherits the ACL of its directory,
// so the caller must place it in a directory that only the user can access
// (the per-user application data directory does this by default).
package clientdb
