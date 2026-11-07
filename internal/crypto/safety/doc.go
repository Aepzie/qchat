// Package safety computes qchat safety numbers, which two users compare (by
// reading them aloud or scanning a QR code) to confirm that each holds the
// other's genuine identity key and that no relay or network attacker has
// substituted one.
//
// # Construction
//
// The construction is Signal's displayable numeric fingerprint, with the
// qchat identity ID as the stable identifier. For each party:
//
//	h0 = u16be(0) || publicKey || ID
//	h(i) = SHA-512(h(i-1) || publicKey)     for i = 1 .. 5200
//	fingerprint = first 30 bytes of h(5200)
//
// where publicKey is the party's hybrid signature public key encoding
// (internal/crypto/hybridsig) and ID its 32-byte identity ID. The 30 bytes
// are rendered as six 5-digit decimal groups, each group being a 5-byte
// big-endian chunk reduced modulo 100000, giving 30 digits per party. The
// safety number is the two 30-digit halves concatenated with the half of the
// lexicographically smaller ID first: 60 digits, shown as 12 groups of 5.
// Because the order depends only on the IDs, both participants compute the
// identical number.
//
// The QR code encodes
//
//	qchat-verify:1:<smaller ID, hex>:<larger ID, hex>:<60 digits>
//
// using the same canonical order, so both devices also produce identical
// payloads and a scan can be checked with a single comparison.
//
// # Security properties
//
//   - Binding. Each half commits to both the public key and the ID of its
//     party, so a substituted key changes the number (and, since the ID is a
//     hash of the key, so would a substituted ID).
//   - Strength against targeted collisions. An attacker who wants a key
//     whose half matches a victim's must find a 100-bit (30 decimal digits)
//     second preimage of the iterated hash; the 5200 SHA-512 iterations make
//     each attempt about 5200 times more expensive than one hash, which is
//     the margin Signal chose for the same format.
//   - Comparisons of numbers and QR payloads are constant time. Safety
//     numbers are not secret, so this is defence in depth only.
//
// # Limits
//
//   - A safety number only helps if users actually compare it over a channel
//     the attacker does not control (in person, or a trusted call).
//   - The number changes whenever either party's identity key changes; a
//     client must then show the contact as unverified again.
//   - The package does not check that an ID matches its key. Callers pass
//     IDs they have already computed from the keys.
package safety
