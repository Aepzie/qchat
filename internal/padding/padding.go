// Package padding hides the length of end-to-end payloads from the relay by
// padding them to a small set of fixed size classes ("buckets").
//
// The padding scheme is the one of ISO/IEC 7816-4: a single 0x80 marker byte
// followed by as many zero bytes as needed. It is unambiguous for every
// plaintext, including empty ones and ones that end in 0x80 or 0x00, because
// at least the marker byte is always appended.
//
// Padding must be applied INSIDE the encryption: senders pad the plaintext
// and then seal it with the AEAD, and receivers open the AEAD and then unpad.
// The AEAD authenticates the padding, so a relay cannot tamper with it, and
// the AEAD overhead (tag, header, framing) does not depend on the plaintext
// length, so the relay only learns the bucket. Padding outside the AEAD would
// leave it unauthenticated and malleable.
//
// For small messages the ratchet header (about 2.4 KB, dominated by the
// hybrid KEM key and ciphertext) already outweighs the padded body; padding
// still removes the remaining length signal of the body itself.
package padding

import (
	"crypto/subtle"
	"errors"
)

// Buckets lists the allowed padded sizes in bytes, in increasing order:
// powers of two from 512 B to 256 KiB. Callers must not modify it.
var Buckets = []int{
	512,
	1 << 10,
	2 << 10,
	4 << 10,
	8 << 10,
	16 << 10,
	32 << 10,
	64 << 10,
	128 << 10,
	256 << 10,
}

// MaxPlaintextLen is the largest plaintext Pad accepts: the largest bucket
// minus the one marker byte.
const MaxPlaintextLen = 256<<10 - 1

const marker = 0x80

var (
	// ErrTooLarge is returned by Pad for plaintexts longer than
	// MaxPlaintextLen.
	ErrTooLarge = errors.New("padding: plaintext too large")
	// ErrMalformed is returned by Unpad for inputs that are not a bucket
	// size or do not end in a 0x80 marker followed only by zero bytes.
	ErrMalformed = errors.New("padding: malformed padding")
)

// BucketFor returns the padded size Pad produces for a plaintext of n bytes:
// the smallest bucket of at least n+1 bytes. It returns ErrTooLarge if n
// exceeds MaxPlaintextLen and ErrMalformed if n is negative.
func BucketFor(n int) (int, error) {
	if n < 0 {
		return 0, ErrMalformed
	}
	for _, size := range Buckets {
		if n < size {
			return size, nil
		}
	}
	return 0, ErrTooLarge
}

// Pad returns a new slice holding plaintext, a 0x80 marker and zero bytes up
// to the smallest bucket that fits len(plaintext)+1 bytes. The input is not
// modified. It returns ErrTooLarge if the plaintext exceeds MaxPlaintextLen.
func Pad(plaintext []byte) ([]byte, error) {
	size, err := BucketFor(len(plaintext))
	if err != nil {
		return nil, err
	}
	padded := make([]byte, size)
	copy(padded, plaintext)
	padded[len(plaintext)] = marker
	return padded, nil
}

// Unpad strips the padding added by Pad and returns the plaintext as a
// sub-slice of padded (sharing its memory, with capacity clipped to its
// length).
//
// It is strict: len(padded) must be exactly one of Buckets, and the input
// must end in a 0x80 marker followed only by zero bytes; anything else yields
// ErrMalformed. Bytes before the marker are plaintext and unrestricted. A
// bucket larger than the minimal one for the plaintext is accepted, so a
// sender may pad further than Pad does.
//
// The scan runs from the end over the whole input and uses constant-time
// byte comparisons and selects, so its running time depends only on
// len(padded), which is the bucket size the relay already sees, and not on
// the position of the marker (the plaintext length). Only the final
// accept/reject branch and the returned slice depend on the content. This is
// a best-effort property of the Go code, not a guarantee about the compiled
// machine code.
func Unpad(padded []byte) ([]byte, error) {
	if !isBucket(len(padded)) {
		return nil, ErrMalformed
	}
	found := 0
	invalid := 0
	markerIndex := 0
	for i := len(padded) - 1; i >= 0; i-- {
		searching := found ^ 1
		isZero := subtle.ConstantTimeByteEq(padded[i], 0)
		isMarker := subtle.ConstantTimeByteEq(padded[i], marker)
		hit := searching & isMarker
		markerIndex = subtle.ConstantTimeSelect(hit, i, markerIndex)
		allowed := isZero | isMarker
		invalid |= searching & (allowed ^ 1)
		found |= hit
	}
	if found&(invalid^1) != 1 {
		return nil, ErrMalformed
	}
	return padded[:markerIndex:markerIndex], nil
}

func isBucket(n int) bool {
	for _, size := range Buckets {
		if n == size {
			return true
		}
	}
	return false
}
