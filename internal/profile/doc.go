// Package profile manages the local qchat account on disk: the private
// identity, the encrypted client database and the passphrase that protects
// them, as specified in docs/design/phase-2-identities.md, section
// "Storage".
//
// A profile directory (see [DefaultDir]) contains
//
//   - identity.qkey: a vault (package vault: Argon2id from the passphrase,
//     XChaCha20-Poly1305) sealing the CBOR record
//     {1: version, 2: identity secret-key record, 3: 32-byte database key};
//   - qchat.db (with its SQLite WAL files): the client database (package
//     clientdb), every value encrypted under the database key.
//
// The directory is created readable only by the current user (mode 0700 on
// Unix; a protected DACL granting only the user and SYSTEM on Windows), and
// the key file is replaced atomically (temporary file, flush, rename).
//
// # Threat model
//
// Someone who copies the profile directory learns nothing beyond file sizes
// and row counts without the passphrase, but can attempt offline guessing,
// slowed down by Argon2id; the passphrase policy ([MinPassphraseRunes]) is
// the remaining defence. Malware running as the same user while the profile
// is unlocked can read the keys from memory or capture the passphrase; no
// file format protects against that. Erasing keys from memory on
// [Profile.Close] is best effort.
package profile
