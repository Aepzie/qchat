package filexfer

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Format parameters and limits.
const (
	// ChunkSize is the plaintext size of every chunk but the last.
	ChunkSize = 48 << 10
	// MaxFileSize is the largest file that can be sent or accepted.
	MaxFileSize = 64 << 20
	// MaxChunks is the number of chunks of a file of MaxFileSize bytes.
	MaxChunks = (MaxFileSize + ChunkSize - 1) / ChunkSize
	// FileIDSize is the length of a file ID.
	FileIDSize = 16
	// KeySize is the length of a file key.
	KeySize = chacha20poly1305.KeySize
	// MaxNameSize bounds an offered file name in bytes.
	MaxNameSize = 255
	// MaxMIMESize bounds an offered media type in bytes.
	MaxMIMESize = 127
	// MaxSealedChunkSize is the largest sealed chunk: nonce, a full chunk
	// and the authentication tag.
	MaxSealedChunkSize = chacha20poly1305.NonceSizeX + ChunkSize + chacha20poly1305.Overhead
	// maxWireSize bounds an encoded offer or chunk before it is decoded.
	maxWireSize = MaxSealedChunkSize + 256
)

// Errors returned by this package. Callers compare with [errors.Is].
var (
	// ErrMalformed reports an offer or chunk that is not in the canonical
	// format or violates a limit.
	ErrMalformed = errors.New("filexfer: malformed file message")
	// ErrTooLarge reports a file above MaxFileSize.
	ErrTooLarge = fmt.Errorf("filexfer: file is larger than %d MiB", MaxFileSize>>20)
	// ErrEmpty reports a file without content.
	ErrEmpty = errors.New("filexfer: file is empty")
	// ErrAuth reports a chunk that does not authenticate.
	ErrAuth = errors.New("filexfer: chunk does not authenticate")
	// ErrHash reports a file whose content does not match the offered
	// SHA-256.
	ErrHash = errors.New("filexfer: file does not match its checksum")
	// ErrIncomplete reports a file with chunks missing.
	ErrIncomplete = errors.New("filexfer: file is incomplete")
)

// Offer announces a file.
type Offer struct {
	FileID [FileIDSize]byte
	// Name is the sender's file name. It is not sanitised; use
	// [SanitizeName] before it touches the file system or a terminal.
	Name string
	Size int64
	// SHA256 is the hash of the whole plaintext.
	SHA256 [32]byte
	Chunks uint32
	// MIME is an optional media type guess; it is informational only.
	MIME string
	// Key is the file key the chunks are sealed with.
	Key [KeySize]byte
}

// Chunk is one sealed chunk of a file.
type Chunk struct {
	FileID [FileIDSize]byte
	Index  uint32
	Total  uint32
	// Sealed is nonce || ciphertext.
	Sealed []byte
}

type offerWire struct {
	FileID []byte `cbor:"1,keyasint"`
	Name   string `cbor:"2,keyasint"`
	Size   int64  `cbor:"3,keyasint"`
	SHA256 []byte `cbor:"4,keyasint"`
	Chunks uint32 `cbor:"5,keyasint"`
	MIME   string `cbor:"6,keyasint,omitempty"`
	Key    []byte `cbor:"7,keyasint"`
}

type chunkWire struct {
	FileID []byte `cbor:"1,keyasint"`
	Index  uint32 `cbor:"2,keyasint"`
	Total  uint32 `cbor:"3,keyasint"`
	Sealed []byte `cbor:"4,keyasint"`
}

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.IndefLength = cbor.IndefLengthForbidden
	encOpts.TagsMd = cbor.TagsForbidden
	var err error
	if encMode, err = encOpts.EncMode(); err != nil {
		panic("filexfer: invalid CBOR encoding options: " + err.Error())
	}
	decOpts := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		BignumTag:         cbor.BignumTagForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		MaxNestedLevels:   4,
		MaxArrayElements:  16,
		MaxMapPairs:       16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}
	if decMode, err = decOpts.DecMode(); err != nil {
		panic("filexfer: invalid CBOR decoding options: " + err.Error())
	}
}

// decodeCanonical strictly decodes b into v and requires b to be the
// canonical encoding of v (see package e2e for the reasoning).
func decodeCanonical(b []byte, v any) error {
	if len(b) > maxWireSize {
		return fmt.Errorf("%w: %d bytes", ErrMalformed, len(b))
	}
	if err := decMode.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	canonical, err := encMode.Marshal(v)
	if err != nil || !bytes.Equal(canonical, b) {
		return fmt.Errorf("%w: non-canonical encoding", ErrMalformed)
	}
	return nil
}

// ChunksFor returns the number of chunks of a file of size bytes.
func ChunksFor(size int64) uint32 {
	if size <= 0 {
		return 0
	}
	return uint32((size + ChunkSize - 1) / ChunkSize)
}

// chunkLen returns the plaintext length of chunk index of a file of size
// bytes.
func chunkLen(size int64, index uint32) int {
	start := int64(index) * ChunkSize
	return int(min(size-start, ChunkSize))
}

// CheckSize reports whether a file of size bytes may be sent.
func CheckSize(size int64) error {
	switch {
	case size <= 0:
		return ErrEmpty
	case size > MaxFileSize:
		return ErrTooLarge
	}
	return nil
}

// NewOffer returns an offer for a file of size bytes with a fresh random
// file ID and key. SHA256 is left for the caller to fill in.
func NewOffer(name string, size int64, mime string) (Offer, error) {
	if err := CheckSize(size); err != nil {
		return Offer{}, err
	}
	o := Offer{Name: SanitizeName(name), Size: size, Chunks: ChunksFor(size), MIME: mime}
	if len(o.MIME) > MaxMIMESize || !utf8.ValidString(o.MIME) {
		o.MIME = ""
	}
	if _, err := rand.Read(o.FileID[:]); err != nil {
		return Offer{}, fmt.Errorf("filexfer: reading randomness: %w", err)
	}
	if _, err := rand.Read(o.Key[:]); err != nil {
		return Offer{}, fmt.Errorf("filexfer: reading randomness: %w", err)
	}
	return o, nil
}

func (o Offer) check() error {
	switch {
	case CheckSize(o.Size) != nil:
		return CheckSize(o.Size)
	case o.Chunks != ChunksFor(o.Size):
		return errors.New("chunk count does not match the size")
	case o.Name == "" || len(o.Name) > MaxNameSize || !utf8.ValidString(o.Name):
		return fmt.Errorf("name must be 1 to %d bytes of UTF-8", MaxNameSize)
	case len(o.MIME) > MaxMIMESize || !utf8.ValidString(o.MIME):
		return fmt.Errorf("media type must be at most %d bytes of UTF-8", MaxMIMESize)
	}
	return nil
}

// MarshalOffer returns the canonical encoding of o. The result contains
// the file key; the caller should clear it once it has been encrypted.
func MarshalOffer(o Offer) ([]byte, error) {
	if err := o.check(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return encMode.Marshal(offerWire{FileID: o.FileID[:], Name: o.Name, Size: o.Size, SHA256: o.SHA256[:], Chunks: o.Chunks, MIME: o.MIME, Key: o.Key[:]})
}

// ParseOffer decodes an offer and checks its limits.
func ParseOffer(b []byte) (Offer, error) {
	var w offerWire
	if err := decodeCanonical(b, &w); err != nil {
		return Offer{}, err
	}
	if len(w.FileID) != FileIDSize || len(w.SHA256) != 32 || len(w.Key) != KeySize {
		return Offer{}, fmt.Errorf("%w: field of wrong size", ErrMalformed)
	}
	o := Offer{FileID: [FileIDSize]byte(w.FileID), Name: w.Name, Size: w.Size, SHA256: [32]byte(w.SHA256), Chunks: w.Chunks, MIME: w.MIME, Key: [KeySize]byte(w.Key)}
	clear(w.Key)
	if err := o.check(); err != nil {
		return Offer{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return o, nil
}

// MarshalChunk returns the canonical encoding of c.
func MarshalChunk(c Chunk) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return encMode.Marshal(chunkWire{FileID: c.FileID[:], Index: c.Index, Total: c.Total, Sealed: c.Sealed})
}

// ParseChunk decodes a chunk and checks its limits. The returned Sealed does
// not alias b.
func ParseChunk(b []byte) (Chunk, error) {
	var w chunkWire
	if err := decodeCanonical(b, &w); err != nil {
		return Chunk{}, err
	}
	if len(w.FileID) != FileIDSize {
		return Chunk{}, fmt.Errorf("%w: file ID of wrong size", ErrMalformed)
	}
	c := Chunk{FileID: [FileIDSize]byte(w.FileID), Index: w.Index, Total: w.Total, Sealed: w.Sealed}
	if err := c.check(); err != nil {
		return Chunk{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return c, nil
}

func (c Chunk) check() error {
	switch {
	case c.Total == 0 || c.Total > MaxChunks:
		return fmt.Errorf("total must be 1 to %d", MaxChunks)
	case c.Index >= c.Total:
		return errors.New("index out of range")
	case len(c.Sealed) <= chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead || len(c.Sealed) > MaxSealedChunkSize:
		return errors.New("sealed chunk of wrong size")
	}
	return nil
}
