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

// signedPayload is the message covered by an envelope signature:
// CBOR(header) || ciphertext. The header is a single canonical CBOR item, and
// CBOR items are self-delimiting, so the boundary between the two parts is
// unambiguous: no other split of the same bytes yields a valid header.
func signedPayload(header, ciphertext []byte) []byte {
	msg := make([]byte, 0, len(header)+len(ciphertext))
	msg = append(msg, header...)
	return append(msg, ciphertext...)
}
