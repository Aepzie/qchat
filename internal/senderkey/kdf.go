package senderkey

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// keySize is the size of every chain key and message key.
const keySize = 32

// ChainKeySize is the size of a chain key as carried in a distribution
// message.
const ChainKeySize = keySize

// labelMessageKey is the HKDF info of the message key expansion. It differs
// from the pairwise ratchet's label, so a group message key can never be
// confused with a pairwise one even if the same bytes appeared in both.
const labelMessageKey = "qchat/v1/group-message-key"

// HMAC inputs of the chain step. The message key and the next chain key are
// computed from the same chain key with distinct constants, so learning a
// message key reveals nothing about the chain key that follows.
var (
	chainMessageInput = []byte{0x01}
	chainNextInput    = []byte{0x02}
)

// chainStep advances a sender chain by one message:
//
//	MK = HMAC-SHA256(CK, 0x01), CK' = HMAC-SHA256(CK, 0x02).
//
// HMAC is one-way, so a stolen CK' reveals neither MK nor any earlier key of
// the chain. This is what stops a member added mid-chain from reading the
// messages sent before it joined.
func chainStep(ck [keySize]byte) (messageKey, next [keySize]byte) {
	mac := hmac.New(sha256.New, ck[:])
	mac.Write(chainMessageInput)
	mac.Sum(messageKey[:0])
	mac.Reset()
	mac.Write(chainNextInput)
	mac.Sum(next[:0])
	return messageKey, next
}

// messageAEADKey expands a message key into the ChaCha20-Poly1305 key and
// nonce:
//
//	key || nonce = HKDF-SHA256(salt = header Salt, ikm = MK,
//	                           info = "qchat/v1/group-message-key"), 32 + 12 bytes.
//
// An honest sender uses every message key once. The fresh random salt covers
// a sender whose state was rolled back and therefore reuses a message key:
// the two messages still get independent AEAD keys and nonces, so neither
// the ChaCha20 keystream nor the Poly1305 key repeats (except with
// probability about 2^-128 per pair).
func messageAEADKey(mk [keySize]byte, salt []byte) (key [chacha20poly1305.KeySize]byte, nonce [chacha20poly1305.NonceSize]byte, err error) {
	if len(salt) != SaltSize {
		return key, nonce, fmt.Errorf("senderkey: message salt of %d bytes", len(salt))
	}
	out, err := hkdf.Key(sha256.New, mk[:], salt, labelMessageKey, len(key)+len(nonce))
	if err != nil {
		return key, nonce, fmt.Errorf("senderkey: deriving message key: %w", err)
	}
	defer clear(out)
	copy(key[:], out[:len(key)])
	copy(nonce[:], out[len(key):])
	return key, nonce, nil
}

// sealMessage encrypts plaintext under message key mk and the header salt
// with associated data ad.
func sealMessage(mk [keySize]byte, salt, plaintext, ad []byte) ([]byte, error) {
	key, nonce, err := messageAEADKey(mk, salt)
	if err != nil {
		return nil, err
	}
	defer clear(key[:])
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("senderkey: creating AEAD: %w", err)
	}
	return aead.Seal(nil, nonce[:], plaintext, ad), nil
}

// openMessage decrypts and authenticates ciphertext under message key mk and
// the header salt with associated data ad. Every failure is reported as
// [ErrDecrypt].
func openMessage(mk [keySize]byte, salt, ciphertext, ad []byte) ([]byte, error) {
	key, nonce, err := messageAEADKey(mk, salt)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer clear(key[:])
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, ErrDecrypt
	}
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// labelCommit is the HMAC input of the message key commitment.
const labelCommit = "qchat/v1/group-commit"

// labelHeader is the associated data of the header encryption.
const labelHeader = "qchat/v1/group-header"

// commitmentSize is the size of a message key commitment.
const commitmentSize = 32

// commitMessageKey returns the commitment to message key mk:
//
//	commitment = HMAC-SHA256(MK, "qchat/v1/group-commit").
//
// The commitment travels in the encrypted header, which is signed. HMAC-SHA256
// with a 32-byte key is collision resistant in the key, so every receiver
// that accepts an envelope has derived the same message key, and therefore
// the same AEAD key and nonce, even if a malicious sender distributed
// different chain keys to different members. ChaCha20-Poly1305 is not
// key-committing; without this check one ciphertext could be made to open
// to different plaintexts under different keys.
func commitMessageKey(mk [keySize]byte) [commitmentSize]byte {
	mac := hmac.New(sha256.New, mk[:])
	mac.Write([]byte(labelCommit))
	var c [commitmentSize]byte
	mac.Sum(c[:0])
	return c
}

// sealHeader encrypts an encoded header with XChaCha20-Poly1305 under the
// generation's header key and a random 24-byte nonce, with the associated
// data "qchat/v1/group-header". The nonce is large enough to be drawn at
// random for every message of a generation.
func sealHeader(key *[HeaderKeySize]byte, nonce, encoded []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("senderkey: creating header AEAD: %w", err)
	}
	return aead.Seal(nil, nonce, encoded, []byte(labelHeader)), nil
}

// openHeader decrypts an encrypted header under one candidate header key. A
// failure only means that the key does not fit; it reports false and costs
// one HChaCha20, one ChaCha20 block and Poly1305 over encHeaderSize bytes.
func openHeader(key *[HeaderKeySize]byte, nonce, sealed []byte) ([]byte, bool) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, false
	}
	encoded, err := aead.Open(nil, nonce, sealed, []byte(labelHeader))
	if err != nil {
		return nil, false
	}
	return encoded, true
}

// signedPayload is the message covered by an envelope signature:
//
//	EnvelopeVersion || HeaderNonce || EncHeader || Ciphertext || Header
//
// where Header is the plaintext header (which carries the message key
// commitment). Every part except the ciphertext has a fixed length, so the
// concatenation is unambiguous. The encrypted parts are signed so that
// nobody without the signing key can make a receiver do more than the
// header decryption; the plaintext header is signed as well because
// XChaCha20-Poly1305 is not key-committing: a sender that handed different
// header keys to different members could otherwise craft one EncHeader that
// opens to different headers for them.
func signedPayload(nonce, encHeader, ciphertext, headerBytes []byte) []byte {
	msg := make([]byte, 0, 1+len(nonce)+len(encHeader)+len(ciphertext)+len(headerBytes))
	msg = append(msg, EnvelopeVersion)
	msg = append(msg, nonce...)
	msg = append(msg, encHeader...)
	msg = append(msg, ciphertext...)
	return append(msg, headerBytes...)
}
