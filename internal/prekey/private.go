package prekey

import (
	"errors"
	"fmt"

	"github.com/Aepzie/qchat/internal/crypto/sealbox"
)

// PrivateVersion is the format version of the record produced by
// [MarshalPrivate].
const PrivateVersion = 1

// ErrMalformedPrivate reports a private prekey record that is not exactly in
// the format written by [MarshalPrivate].
var ErrMalformedPrivate = errors.New("prekey: malformed private prekey record")

// privateRecord is the stored form of a prekey private key. Priv is the
// 32-byte sealbox seed from which the full key pair is expanded, so the
// record is small and has a single valid encoding.
type privateRecord struct {
	Version uint8  `cbor:"1,keyasint"`
	KeyID   uint32 `cbor:"2,keyasint"`
	Priv    []byte `cbor:"3,keyasint"`
}

// MarshalPrivate returns the storage record of a prekey private key:
//
//	CBOR{1: version (=1), 2: key ID, 3: private key (32)}
//
// The same format serves signed and one-time prekeys; the caller keeps them
// apart (for example in different tables), because their key IDs are
// independent. The record is secret key material: it must only ever be
// stored encrypted (the client database is), and the caller should clear
// the returned slice once it has been written. Clearing is best effort; the
// CBOR encoder may leave copies in memory that cannot be reached from here.
func MarshalPrivate(keyID uint32, priv *sealbox.PrivateKey) ([]byte, error) {
	if keyID == 0 || priv == nil {
		return nil, fmt.Errorf("%w: zero key ID or nil key", ErrInvalidArgument)
	}
	seed := priv.Bytes()
	defer clear(seed)
	if len(seed) != sealbox.PrivateKeySize {
		return nil, fmt.Errorf("%w: unusable private key", ErrInvalidArgument)
	}
	record, err := encMode.Marshal(privateRecord{Version: PrivateVersion, KeyID: keyID, Priv: seed})
	if err != nil {
		return nil, fmt.Errorf("prekey: encoding private key: %w", err)
	}
	return record, nil
}

// UnmarshalPrivate parses a record produced by [MarshalPrivate]. It accepts
// only the exact canonical encoding of a version 1 record with a non-zero
// key ID and a 32-byte key, and returns [ErrMalformedPrivate] otherwise. The
// input is not retained; the caller may clear it afterwards.
func UnmarshalPrivate(b []byte) (uint32, *sealbox.PrivateKey, error) {
	var record privateRecord
	defer func() { clear(record.Priv) }()
	if len(b) == 0 || len(b) > 64 {
		return 0, nil, ErrMalformedPrivate
	}
	if err := decodeCanonical(b, &record); err != nil {
		return 0, nil, ErrMalformedPrivate
	}
	if record.Version != PrivateVersion || record.KeyID == 0 || len(record.Priv) != sealbox.PrivateKeySize {
		return 0, nil, ErrMalformedPrivate
	}
	priv, err := sealbox.NewPrivateKey(record.Priv)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrMalformedPrivate, err)
	}
	return record.KeyID, priv, nil
}
