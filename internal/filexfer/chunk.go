package filexfer

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// chunkAD returns the associated data of a chunk: fileID || index || total.
func chunkAD(fileID [FileIDSize]byte, index, total uint32) []byte {
	ad := make([]byte, 0, FileIDSize+8)
	ad = append(ad, fileID[:]...)
	ad = binary.BigEndian.AppendUint32(ad, index)
	return binary.BigEndian.AppendUint32(ad, total)
}

// SealChunk encrypts the plaintext of chunk index of the file o and
// returns nonce || ciphertext. plain must have the length the chunk has in
// a file of o.Size bytes.
func SealChunk(o *Offer, index uint32, plain []byte) ([]byte, error) {
	if index >= o.Chunks || len(plain) != chunkLen(o.Size, index) {
		return nil, fmt.Errorf("%w: chunk %d of wrong size", ErrMalformed, index)
	}
	aead, err := chacha20poly1305.NewX(o.Key[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, chacha20poly1305.NonceSizeX, chacha20poly1305.NonceSizeX+len(plain)+chacha20poly1305.Overhead)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("filexfer: reading randomness: %w", err)
	}
	return aead.Seal(out, out, plain, chunkAD(o.FileID, index, o.Chunks)), nil
}

// OpenChunk authenticates and decrypts chunk index of the file o. It
// returns [ErrAuth] for a chunk that does not authenticate or does not have
// the length that chunk must have.
func OpenChunk(o *Offer, index uint32, sealed []byte) ([]byte, error) {
	if index >= o.Chunks || len(sealed) != SealedLen(o, index) {
		return nil, ErrAuth
	}
	aead, err := chacha20poly1305.NewX(o.Key[:])
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := sealed[:chacha20poly1305.NonceSizeX], sealed[chacha20poly1305.NonceSizeX:]
	plain, err := aead.Open(nil, nonce, ciphertext, chunkAD(o.FileID, index, o.Chunks))
	if err != nil {
		return nil, ErrAuth
	}
	return plain, nil
}

// SealedLen returns the length of sealed chunk index of the file o.
func SealedLen(o *Offer, index uint32) int {
	return chacha20poly1305.NonceSizeX + chunkLen(o.Size, index) + chacha20poly1305.Overhead
}
