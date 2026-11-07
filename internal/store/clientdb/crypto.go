package clientdb

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// HKDF info labels for the two subkeys. They must differ so that the
// encryption key and the lookup key are independent.
const (
	infoEncryption = "qchat clientdb v1 row encryption"
	infoLookup     = "qchat clientdb v1 lookup hmac"
)

// HMAC labels for lookup columns. Each ends with a zero byte so that no label
// is a prefix of another.
const (
	labelContact  = "qchat/clientdb/v1/contact\x00"
	labelMessage  = "qchat/clientdb/v1/message\x00"
	labelSetting  = "qchat/clientdb/v1/setting\x00"
	labelSession  = "qchat/clientdb/v1/session\x00"
	labelPrekey   = "qchat/clientdb/v1/prekey\x00"
	labelSeenInit = "qchat/clientdb/v1/seen-init\x00"
)

// lookupSize is the length of every lookup column (HMAC-SHA256 output).
const lookupSize = sha256.Size

// sealOverhead is the number of bytes a sealed value adds to its plaintext.
const sealOverhead = chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead

// keys holds the subkeys derived from the database key.
type keys struct {
	aead      cipher.AEAD
	lookupKey []byte
}

// deriveKeys derives the encryption and lookup subkeys from dbKey.
func deriveKeys(dbKey [32]byte) (*keys, error) {
	encKey, err := hkdf.Key(sha256.New, dbKey[:], nil, infoEncryption, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("clientdb: derive encryption key: %w", err)
	}
	lookupKey, err := hkdf.Key(sha256.New, dbKey[:], nil, infoLookup, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("clientdb: derive lookup key: %w", err)
	}
	aead, err := chacha20poly1305.NewX(encKey)
	clear(encKey)
	if err != nil {
		return nil, fmt.Errorf("clientdb: init cipher: %w", err)
	}
	return &keys{aead: aead, lookupKey: lookupKey}, nil
}

// wipe clears the lookup key. The AEAD's internal key copy cannot be cleared
// and is released to the garbage collector.
func (k *keys) wipe() {
	clear(k.lookupKey)
	k.aead = nil
}

// lookup returns HMAC-SHA256(lookupKey, label || parts...).
func (k *keys) lookup(label string, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, k.lookupKey)
	m.Write([]byte(label))
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// contactLookup returns the lookup key of the contact with the given ID. It is
// also the peer column of that contact's messages.
func (k *keys) contactLookup(id [32]byte) []byte {
	return k.lookup(labelContact, id[:])
}

// messageLookup returns the lookup key of a message.
func (k *keys) messageLookup(peer [32]byte, msgID [16]byte) []byte {
	return k.lookup(labelMessage, peer[:], msgID[:])
}

// settingLookup returns the lookup key of a setting.
func (k *keys) settingLookup(name string) []byte {
	return k.lookup(labelSetting, []byte(name))
}

// sessionLookup returns the lookup key of the ratchet session with peer.
func (k *keys) sessionLookup(peer [32]byte) []byte {
	return k.lookup(labelSession, peer[:])
}

// prekeyLookup returns the lookup key of an own prekey secret.
func (k *keys) prekeyLookup(kind PrekeyKind, keyID uint32) []byte {
	return k.lookup(labelPrekey, []byte{byte(kind)}, binary.BigEndian.AppendUint32(nil, keyID))
}

// seenInitLookup returns the replay set entry of a session start that used
// the own signed prekey spkID and has replay key key.
func (k *keys) seenInitLookup(spkID uint32, key [32]byte) []byte {
	return k.lookup(labelSeenInit, binary.BigEndian.AppendUint32(nil, spkID), key[:])
}

// rowAAD builds the associated data that binds a ciphertext to its table, its
// lookup key and, for messages, its sequence number (seq < 0 omits it).
func rowAAD(table string, lookupKey []byte, seq int64) []byte {
	aad := make([]byte, 0, len(table)+1+len(lookupKey)+8)
	aad = append(aad, table...)
	aad = append(aad, 0)
	aad = append(aad, lookupKey...)
	if seq >= 0 {
		aad = binary.BigEndian.AppendUint64(aad, uint64(seq))
	}
	return aad
}

// seal encrypts plaintext under a fresh random nonce and returns
// nonce || ciphertext.
func (k *keys) seal(plaintext, aad []byte) ([]byte, error) {
	out := make([]byte, chacha20poly1305.NonceSizeX, sealOverhead+len(plaintext))
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("clientdb: generate nonce: %w", err)
	}
	return k.aead.Seal(out, out, plaintext, aad), nil
}

// open authenticates and decrypts a value produced by seal. Any failure is
// reported as ErrCorrupt.
func (k *keys) open(sealed, aad []byte) ([]byte, error) {
	if len(sealed) < sealOverhead {
		return nil, ErrCorrupt
	}
	nonce, ciphertext := sealed[:chacha20poly1305.NonceSizeX], sealed[chacha20poly1305.NonceSizeX:]
	plaintext, err := k.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrCorrupt
	}
	return plaintext, nil
}
