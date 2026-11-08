// Package sealed implements the end-to-end part of sealed sender: the
// access keys that authorise anonymous delivery and the envelope that
// carries the sender ID to the recipient without revealing it to the relay.
//
// # Access keys
//
// Every user holds a random [AccessKey] of [AccessKeySize] bytes and shares
// it with its contacts and group members inside the end-to-end encrypted
// channel. The relay receives only its [AccessKey.Verifier],
// HMAC-SHA256(AccessKey, "qchat/v1/access-verifier"), which senders present
// as the access proof of a protocol.SealedSend. Replacing the verifier at
// the relay revokes the old key.
//
// # Envelope
//
//	SealedEnvelope = {1: Version = 1, 2: Box}
//	Box            = sealbox.Seal(recipient KEM key,
//	                              "qchat/v1/sealed" || RecipientID,
//	                              {1: SenderID, 2: Inner})
//
// The HPKE box (MLKEM768-X25519, HKDF-SHA256, ChaCha20-Poly1305) hides the
// sender ID and the inner payload from the relay and binds the envelope to
// the recipient ID. Every structure is strict, canonical CBOR.
//
// # Trust
//
// The seal does not authenticate the sender: anyone who knows a
// recipient's bundle can seal any SenderID to it. The claimed sender
// returned by [Open] must be treated as a routing hint only. The inner
// payload, the pairwise envelope of package e2e, authenticates it: its
// ratchet AEAD and its session Init signature are bound to the sender ID,
// so opening it with the claimed sender's session fails unless the claim
// is true. Callers must route by the claimed sender, open the inner layer,
// and drop the message without changing any state if that fails; they must
// never display or act on the claimed sender before then.
//
// Group envelopes are not sealed with this package: the sender ID of a
// group message is already inside its encrypted header, so the group
// ciphertext is sent as is with protocol.SealedSendMulti, one payload for
// every member.
package sealed
