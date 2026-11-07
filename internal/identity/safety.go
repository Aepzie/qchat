package identity

import "github.com/craguS/qchat/internal/crypto/safety"

// SafetyNumber returns the 60-digit safety number of the conversation
// between the identities of bundles a and b, without separators (format it
// with safety.Grouped for display). It is computed by package safety from
// each party's ID and hybrid signing public key, and does not depend on the
// argument order, so both participants see the same number.
//
// Two users who compare their safety numbers over an independent channel
// (in person, by phone) and find them equal know that neither the relay
// nor anybody else substituted the other's keys: the number commits to the
// signing keys, which commit to the KEM keys through the bundle signature.
//
// a and b must come from [ParseBundle] or [ParseBundleForID].
func SafetyNumber(a, b *Bundle) string {
	return safety.Number(a.ID, a.SigningKey.Bytes(), b.ID, b.SigningKey.Bytes())
}

// SafetyQR returns the payload for the verification QR code of the
// conversation between a and b, "qchat-verify:1:<ID hex>:<ID hex>:<60
// digits>", independent of argument order. A scanned payload is checked
// with safety.VerifyQRPayload.
//
// a and b must come from [ParseBundle] or [ParseBundleForID].
func SafetyQR(a, b *Bundle) string {
	return safety.QRPayload(a.ID, a.SigningKey.Bytes(), b.ID, b.SigningKey.Bytes())
}
