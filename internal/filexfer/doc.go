// Package filexfer implements the end-to-end encrypted file transfer of
// Phase 7 (docs/design/phase-7-files.md): the file offer and file chunk
// formats carried as e2e.KindFileOffer and e2e.KindFileChunk, the chunk
// encryption, file name sanitising and the profile's file store.
//
// A file is split into chunks of [ChunkSize] bytes. Each chunk is sealed
// with XChaCha20-Poly1305 under a random 32-byte file key and a random
// nonce, with associated data fileID || index || total (index and total as
// big-endian uint32), so a chunk cannot be moved to another position,
// another file or a transfer of a different length. The file key travels in
// the offer, which, like every chunk, is a normal message of the pairwise
// session or group sender key; the chunks are therefore encrypted twice,
// which keeps the relay blind to them even if a file key leaks.
//
// # Encodings
//
// Offers and chunks are canonical CBOR maps with integer keys, decoded
// strictly: duplicate or unknown keys, indefinite lengths, tags and any
// non-canonical encoding are rejected.
//
//	Offer {1: FileID (16), 2: Name, 3: Size, 4: SHA-256 (32), 5: Chunks, 6: MIME (optional), 7: Key (32)}
//	Chunk {1: FileID (16), 2: Index, 3: Total, 4: nonce || ciphertext}
//
// # Store
//
// [Store] keeps files under the profile directory: transfers in progress
// in files/incoming/<local>.part, finished files in files/<local>.qcf,
// where <local> is a random local ID (never a name chosen by the sender).
// Both hold the chunks exactly as they were sealed by the sender, one fixed
// size slot per chunk, so files are encrypted at rest under their file key,
// which the caller keeps in the encrypted client database. A finished file
// has had every chunk authenticated and its SHA-256 checked; [Store.Export]
// checks both again while it writes the plaintext to a new file that never
// replaces an existing one.
package filexfer
