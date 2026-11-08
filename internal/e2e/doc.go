// Package e2e defines the qchat end-to-end message formats of Phase 3
// (docs/design/phase-3-forward-secrecy.md, section "Message envelope"):
// the envelope that travels as the opaque relay payload, and the plaintext
// that the ratchet encrypts.
//
//	Envelope  {1: Version=2, 2: Init (optional), 3: Header, 4: Ciphertext}
//	Plaintext {1: MsgID (16), 2: Sent int64 (Unix ms), 3: Kind uint8, 4: Body}
//
// Kinds (docs/design/phase-4-groups.md): 1 text, 2 group control, 3 sender
// key distribution, all carried pairwise; 4 group text, carried only inside
// a group envelope of package senderkey. Phase 7
// (docs/design/phase-7-files.md) adds 5 file offer, 6 file chunk and 7
// disappearing message timer, carried both pairwise and in group envelopes.
//
// Init is the signed session start of package handshake, attached by the
// initiator until it has received a message on the session. Header and
// Ciphertext are the output of ratchet.State.Encrypt for the encoded
// Plaintext. This package only fixes and checks the encodings; it performs
// no cryptography. Session handling (which Init to accept, which ratchet
// state decrypts a message, persistence) is the caller's job.
//
// # Encodings and limits
//
// Both structures are canonical CBOR maps with integer keys, and decoding
// is strict: duplicate or unknown keys, indefinite lengths, tags and any
// encoding other than the canonical one are rejected, so every value has
// exactly one accepted byte representation. Every field has a size bound
// ([MaxInitSize], [MaxHeaderSize], [MaxCiphertextSize], [MaxBodySize]) and
// input above [MaxEnvelopeSize] or [MaxPlaintextSize] is rejected before it
// is decoded.
//
// # What the formats do not protect
//
//   - The envelope is not encrypted: the relay sees whether an Init is
//     attached, the ratchet header (epochs, counters, ratchet public keys)
//     and the ciphertext size. Header encryption and padding are later
//     phases.
//   - Plaintext.Sent is claimed by the sender; [ClockSkewed] only flags
//     values far from the local clock.
//   - Plaintext.MsgID is chosen by the sender. The ratchet rejects replayed
//     ciphertexts; the caller additionally rejects a (sender, MsgID) it has
//     already stored.
package e2e
