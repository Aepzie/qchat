package ratchet

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// keySize is the size of every root key, chain key, message key and the
// session secret SK.
const keySize = 32

// Domain-separation labels. Each derivation uses its own label so that no
// output of one step can be confused with, or substituted for, the output of
// another.
const (
	labelRootAB     = "qchat/v1/root A->B"
	labelRootBA     = "qchat/v1/root B->A"
	labelRootStep   = "qchat/v1/rk"
	labelRatchet    = "qchat/v1/ratchet"
	labelMessageKey = "qchat/v1/message-key"
)

// HMAC inputs of the symmetric chain step. The message key and the next chain
// key are computed from the same chain key with distinct constants, so
// learning a message key reveals nothing about the chain key that follows.
var (
	chainMessageInput = []byte{0x01}
	chainNextInput    = []byte{0x02}
)

// deriveRoots expands the session secret into the two initial root keys, one
// per direction. The initiator sends on A->B and the responder on B->A; giving
// each direction its own root chain means that the two sides never have to
// agree on an order of ratchet steps, so concurrent sending cannot make them
// diverge.
func deriveRoots(sk [keySize]byte) (ab, ba [keySize]byte, err error) {
	abKey, err := hkdf.Key(sha256.New, sk[:], nil, labelRootAB, keySize)
	if err != nil {
		return ab, ba, fmt.Errorf("ratchet: deriving root key: %w", err)
	}
	defer clear(abKey)
	baKey, err := hkdf.Key(sha256.New, sk[:], nil, labelRootBA, keySize)
	if err != nil {
		return ab, ba, fmt.Errorf("ratchet: deriving root key: %w", err)
	}
	defer clear(baKey)
	copy(ab[:], abKey)
	copy(ba[:], baKey)
	return ab, ba, nil
}

// kdfRK is KDF_RK of the specification: one root step mixing a fresh KEM
// shared secret into a root chain,
//
//	RK', CK = HKDF-SHA256(salt = rk, ikm = ss, info = "qchat/v1/rk"), 64 bytes.
//
// Using the old root key as salt chains every epoch to all previous ones,
// while the fresh secret ss provides post-compromise security: an attacker
// who knew rk but not the private key ss was encapsulated to cannot compute
// RK' or CK.
func kdfRK(rk, ss [keySize]byte) (nextRoot, chain [keySize]byte, err error) {
	out, err := hkdf.Key(sha256.New, ss[:], rk[:], labelRootStep, 2*keySize)
	if err != nil {
		return nextRoot, chain, fmt.Errorf("ratchet: root step: %w", err)
	}
	defer clear(out)
	copy(nextRoot[:], out[:keySize])
	copy(chain[:], out[keySize:])
	return nextRoot, chain, nil
}

// chainStep advances a symmetric chain by one message:
//
//	MK = HMAC-SHA256(CK, 0x01), CK' = HMAC-SHA256(CK, 0x02).
//
// HMAC is one-way, so a stolen CK' does not reveal MK or any earlier key of
// the chain (forward secrecy within an epoch).
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
// nonce: key || nonce = HKDF-SHA256(MK, info = "qchat/v1/message-key"),
// 32 + 12 bytes. Every message key is used for exactly one message, so the
// deterministic nonce is never reused under the same key.
func messageAEADKey(mk [keySize]byte) (key [chacha20poly1305.KeySize]byte, nonce [chacha20poly1305.NonceSize]byte, err error) {
	out, err := hkdf.Key(sha256.New, mk[:], nil, labelMessageKey, len(key)+len(nonce))
	if err != nil {
		return key, nonce, fmt.Errorf("ratchet: deriving message key: %w", err)
	}
	defer clear(out)
	copy(key[:], out[:len(key)])
	copy(nonce[:], out[len(key):])
	return key, nonce, nil
}

// sealMessage encrypts plaintext under message key mk with associated data ad.
func sealMessage(mk [keySize]byte, plaintext, ad []byte) ([]byte, error) {
	key, nonce, err := messageAEADKey(mk)
	if err != nil {
		return nil, err
	}
	defer clear(key[:])
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("ratchet: creating AEAD: %w", err)
	}
	return aead.Seal(nil, nonce[:], plaintext, ad), nil
}

// openMessage decrypts and authenticates ciphertext under message key mk with
// associated data ad. Every failure is reported as [ErrDecrypt].
func openMessage(mk [keySize]byte, ciphertext, ad []byte) ([]byte, error) {
	key, nonce, err := messageAEADKey(mk)
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

// ratchetInfo is the HPKE info string of an epoch's encapsulation:
// "qchat/v1/ratchet" || sender ID || recipient ID || u32(epoch), with the
// epoch big-endian. Binding both identities and the epoch number means an
// encapsulation cannot be replayed into another session, the other
// direction, or another epoch of the same direction.
func ratchetInfo(sender, recipient [32]byte, epoch uint32) []byte {
	info := make([]byte, 0, len(labelRatchet)+2*32+4)
	info = append(info, labelRatchet...)
	info = append(info, sender[:]...)
	info = append(info, recipient[:]...)
	return binary.BigEndian.AppendUint32(info, epoch)
}

// associatedData is the AEAD associated data of a message:
// CBOR(header) || sender ID || recipient ID. It authenticates every header
// field (including the announced ratchet key and the counters) and binds the
// message to its direction and participants.
func associatedData(header []byte, sender, recipient [32]byte) []byte {
	ad := make([]byte, 0, len(header)+2*32)
	ad = append(ad, header...)
	ad = append(ad, sender[:]...)
	return append(ad, recipient[:]...)
}
