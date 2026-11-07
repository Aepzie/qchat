package sealbox

import (
	"crypto/hpke"
	"fmt"
)

// SharedSecretSize is the size of the secret returned by [Encapsulate] and
// [Decapsulate].
const SharedSecretSize = 32

// kemExportContext is the HPKE exporter context from which the shared secret
// is derived. It is fixed so that the exported secret can never collide with
// any other secret exported from the same HPKE context.
const kemExportContext = "qchat/v1/kem"

// exportOnly is the HPKE "export-only" AEAD (ID 0xffff). A context created
// with it cannot seal or open messages; it only exports secrets.
var exportOnly = hpke.ExportOnly()

// Encapsulate runs HPKE base mode with the MLKEM768-X25519 / HKDF-SHA256 /
// export-only suite to pub under info and returns the encapsulated key (always
// [EncapsulatedKeySize] bytes) together with a fresh 32-byte shared secret,
// exported from the HPKE context with the context string "qchat/v1/kem".
//
// The secret is bound to info by the HPKE key schedule, so the recipient
// obtains the same secret only when it passes the identical info string to
// [Decapsulate]. info must not be empty: an empty string would leave the
// secret unbound to any purpose or participants.
//
// Like [Seal], Encapsulate provides no sender authentication; anyone who
// knows pub can produce an encapsulation. Callers authenticate the result by
// other means (signatures, or an AEAD keyed from an already authenticated
// chain).
//
// The caller owns the returned secret and should clear it once it has been
// fed into a key schedule.
func Encapsulate(pub *PublicKey, info []byte) (enc []byte, secret [SharedSecretSize]byte, err error) {
	if pub == nil {
		return nil, secret, ErrInvalidPublicKey
	}
	if len(info) == 0 {
		return nil, secret, ErrInvalidInfo
	}
	enc, sender, err := hpke.NewSender(pub.key, kdf, exportOnly, info)
	if err != nil {
		return nil, secret, fmt.Errorf("sealbox: encapsulating: %w", err)
	}
	exported, err := sender.Export(kemExportContext, SharedSecretSize)
	if err != nil {
		return nil, secret, fmt.Errorf("sealbox: exporting secret: %w", err)
	}
	defer clear(exported)
	if len(enc) != EncapsulatedKeySize || len(exported) != SharedSecretSize {
		return nil, secret, fmt.Errorf("sealbox: unexpected encapsulation sizes %d/%d", len(enc), len(exported))
	}
	copy(secret[:], exported)
	return enc, secret, nil
}

// Decapsulate recovers the shared secret of an encapsulation produced by
// [Encapsulate] for the public key of priv under the same info string.
//
// An encapsulation of the wrong length is rejected with [ErrDecrypt]. An
// encapsulation of the right length that was made for a different key, made
// under a different info string, or modified in transit does NOT necessarily
// produce an error: ML-KEM uses implicit rejection and HPKE has no key
// confirmation, so the result is simply an unrelated, unpredictable secret.
// Callers must therefore confirm the secret, for example by verifying an AEAD
// tag under a key derived from it, before committing any state.
func Decapsulate(priv *PrivateKey, enc, info []byte) (secret [SharedSecretSize]byte, err error) {
	if priv == nil || priv.key == nil {
		return secret, ErrInvalidPrivateKey
	}
	if len(info) == 0 {
		return secret, ErrInvalidInfo
	}
	if len(enc) != EncapsulatedKeySize {
		return secret, ErrDecrypt
	}
	recipient, err := hpke.NewRecipient(enc, priv.key, kdf, exportOnly, info)
	if err != nil {
		return secret, ErrDecrypt
	}
	exported, err := recipient.Export(kemExportContext, SharedSecretSize)
	if err != nil {
		return secret, ErrDecrypt
	}
	defer clear(exported)
	if len(exported) != SharedSecretSize {
		return secret, ErrDecrypt
	}
	copy(secret[:], exported)
	return secret, nil
}
