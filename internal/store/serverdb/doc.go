// Package serverdb is the relay's database (qchat.db): public identity
// bundles and hashed invite codes, nothing else.
//
// The database is a SQLite file opened through database/sql with the pure-Go
// modernc.org/sqlite driver, in WAL mode with a busy timeout, foreign keys
// and secure_delete=ON. Every write transaction starts with BEGIN IMMEDIATE,
// so concurrent writers queue on the busy timeout instead of failing when a
// read lock would have to be upgraded. Schema changes are applied by numbered
// migrations recorded in the schema_migrations table; Open applies the
// missing ones and refuses a database written by a newer schema.
//
// # What is stored
//
//   - identities(id, bundle, serial): the identity ID, the bundle exactly as
//     the client sent it, and its serial. No creation, update or last-seen
//     time is stored, and nothing links an identity to an address or an
//     invite, to keep the metadata the relay holds to the minimum the
//     protocol needs.
//   - invites(code_hash, expires_at, uses_left): the SHA-256 of the
//     normalized invite code, the expiry in Unix seconds and the remaining
//     uses. The code itself is never stored and cannot be recovered; an
//     invite whose last use is redeemed is deleted at once.
//
// Messages are never stored.
//
// # Trust boundary
//
// This package does not parse bundles or verify signatures. The caller must
// verify the bundle signature, compute the ID from the signing key and take
// the serial from the verified bundle before calling PutIdentity or
// RedeemInviteAndPut; this package only enforces the replacement rules
// (identical bundle, higher serial, otherwise conflict) atomically.
//
// # Invite codes
//
// A code is 128 random bits, written as 26 upper-case base32 characters
// (RFC 4648 alphabet, no padding) in groups of four separated by '-'.
// Parsing ignores '-', white space and letter case. Unknown, malformed,
// expired and used-up codes all produce the same ErrInviteInvalid, so a
// caller cannot tell them apart.
//
// # File permissions
//
// On Unix the database file is created (or tightened) with mode 0600, and
// SQLite gives the -wal and -shm files the same mode as the main file. On
// Windows no per-file ACL is set: the files inherit the ACL of their
// directory, so the caller must place the database in a protected directory
// (qchat-server init creates the data directory with such an ACL).
//
// secure_delete overwrites freed pages with zeros. In WAL mode, old page
// images may remain in the -wal file until the next checkpoint; Close runs a
// truncating checkpoint to shrink that window.
package serverdb
