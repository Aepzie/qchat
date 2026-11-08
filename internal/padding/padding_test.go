package padding

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func plaintextOf(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*7 + 1)
	}
	return p
}

func roundTrip(t *testing.T, plaintext []byte, wantSize int) {
	t.Helper()
	padded, err := Pad(plaintext)
	if err != nil {
		t.Fatalf("Pad(%d bytes): %v", len(plaintext), err)
	}
	if len(padded) != wantSize {
		t.Fatalf("Pad(%d bytes) = %d bytes, want %d", len(plaintext), len(padded), wantSize)
	}
	if !bytes.Equal(padded[:len(plaintext)], plaintext) {
		t.Fatal("padded output does not start with the plaintext")
	}
	if padded[len(plaintext)] != 0x80 {
		t.Fatalf("marker byte = %#x", padded[len(plaintext)])
	}
	if len(bytes.Trim(padded[len(plaintext)+1:], "\x00")) != 0 {
		t.Fatal("padding contains non-zero bytes after the marker")
	}
	got, err := Unpad(padded)
	if err != nil {
		t.Fatalf("Unpad after Pad(%d bytes): %v", len(plaintext), err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip of %d bytes returned %d different bytes", len(plaintext), len(got))
	}
	if cap(got) != len(got) {
		t.Fatalf("Unpad capacity %d not clipped to length %d", cap(got), len(got))
	}
}

func TestBucketsAscendingPowersOfTwo(t *testing.T) {
	if len(Buckets) != 10 || Buckets[0] != 512 || Buckets[len(Buckets)-1] != 256*1024 {
		t.Fatalf("unexpected Buckets %v", Buckets)
	}
	for i := 1; i < len(Buckets); i++ {
		if Buckets[i] != 2*Buckets[i-1] {
			t.Fatalf("Buckets[%d] = %d, want %d", i, Buckets[i], 2*Buckets[i-1])
		}
	}
	if MaxPlaintextLen != Buckets[len(Buckets)-1]-1 {
		t.Fatalf("MaxPlaintextLen = %d", MaxPlaintextLen)
	}
}

func TestRoundTripEveryBoundary(t *testing.T) {
	previous := 0
	for _, size := range Buckets {
		lengths := []int{previous, previous + 1, size - 2, size - 1}
		if previous == 0 {
			lengths = []int{0, 1, size - 2, size - 1}
		}
		for _, n := range lengths {
			roundTrip(t, plaintextOf(n), size)
		}
		if size != Buckets[len(Buckets)-1] {
			roundTrip(t, plaintextOf(size), 2*size)
		}
		previous = size
	}
}

func TestRoundTripTrickyPlaintexts(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x80},
		{0x00},
		{0x80, 0x00, 0x00},
		bytes.Repeat([]byte{0x80}, 511),
		bytes.Repeat([]byte{0x00}, 511),
		bytes.Repeat([]byte{0x00}, 512),
	}
	for _, p := range cases {
		size, err := BucketFor(len(p))
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, p, size)
	}
}

func TestPadDoesNotModifyInput(t *testing.T) {
	p := make([]byte, 3, 100)
	copy(p, "abc")
	before := append([]byte(nil), p[:cap(p)]...)
	if _, err := Pad(p); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p[:cap(p)], before) {
		t.Fatal("Pad wrote into the caller's backing array")
	}
}

func TestPadTooLarge(t *testing.T) {
	roundTrip(t, plaintextOf(MaxPlaintextLen), 256*1024)
	for _, n := range []int{MaxPlaintextLen + 1, 256 * 1024, 1 << 20} {
		padded, err := Pad(make([]byte, n))
		if !errors.Is(err, ErrTooLarge) || padded != nil {
			t.Fatalf("Pad(%d bytes) = %d bytes, %v; want ErrTooLarge", n, len(padded), err)
		}
	}
}

func TestBucketFor(t *testing.T) {
	cases := []struct {
		n    int
		want int
		err  error
	}{
		{0, 512, nil},
		{511, 512, nil},
		{512, 1024, nil},
		{1023, 1024, nil},
		{2400, 4096, nil},
		{MaxPlaintextLen, 256 * 1024, nil},
		{MaxPlaintextLen + 1, 0, ErrTooLarge},
		{-1, 0, ErrMalformed},
	}
	for _, c := range cases {
		got, err := BucketFor(c.n)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("BucketFor(%d) = %d, %v; want %d, %v", c.n, got, err, c.want, c.err)
		}
	}
}

func TestUnpadAcceptsLargerBucket(t *testing.T) {
	padded := make([]byte, 4096)
	copy(padded, "hi")
	padded[2] = 0x80
	got, err := Unpad(padded)
	if err != nil || string(got) != "hi" {
		t.Fatalf("Unpad = %q, %v", got, err)
	}
}

func TestUnpadMalformed(t *testing.T) {
	valid := func() []byte {
		p, err := Pad([]byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string][]byte{
		"nil":                 nil,
		"empty":               {},
		"marker only":         {0x80},
		"not a bucket 511":    append([]byte{0x80}, make([]byte, 510)...),
		"not a bucket 513":    append(valid(), 0x00),
		"not a bucket 1000":   append([]byte{0x80}, make([]byte, 999)...),
		"above largest":       append([]byte{0x80}, make([]byte, 512*1024-1)...),
		"all zeros":           make([]byte, 512),
		"all zeros largest":   make([]byte, 256*1024),
		"no marker":           bytes.Repeat([]byte{0x41}, 512),
		"trailing 0x01":       func() []byte { p := valid(); p[511] = 0x01; return p }(),
		"non-zero in padding": func() []byte { p := valid(); p[100] = 0x01; return p }(),
		"wrong marker 0x81":   func() []byte { p := valid(); p[5] = 0x81; return p }(),
		"wrong marker 0x01":   func() []byte { p := valid(); p[5] = 0x01; return p }(),
		"last byte 0xff":      func() []byte { p := make([]byte, 1024); p[0] = 0x80; p[1023] = 0xff; return p }(),
	}
	for name, input := range cases {
		got, err := Unpad(input)
		if !errors.Is(err, ErrMalformed) || got != nil {
			t.Errorf("%s: Unpad = %d bytes, %v; want ErrMalformed", name, len(got), err)
		}
	}
}

func TestUnpadMarkerPositions(t *testing.T) {
	for _, size := range Buckets {
		for _, pos := range []int{0, 1, size / 2, size - 2, size - 1} {
			padded := bytes.Repeat([]byte{0x80}, size)
			for i := pos + 1; i < size; i++ {
				padded[i] = 0
			}
			got, err := Unpad(padded)
			if err != nil || len(got) != pos {
				t.Fatalf("size %d, marker at %d: Unpad = %d bytes, %v", size, pos, len(got), err)
			}
		}
	}
}

// TestKnownAnswer pins the exact encoding of one padded value.
func TestKnownAnswer(t *testing.T) {
	padded, err := Pad([]byte("qchat"))
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x71, 0x63, 0x68, 0x61, 0x74, 0x80}, make([]byte, 506)...)
	if !bytes.Equal(padded, want) {
		t.Fatalf("Pad(\"qchat\") = %x", padded)
	}
	const wantDigest = "410a9ed759affa54b2110be91940f0f4191a52df45b5fe857ad3043f134d37bb"
	digest := sha256.Sum256(padded)
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("SHA-256 of padded value = %s, want %s", got, wantDigest)
	}
}

func BenchmarkUnpad(b *testing.B) {
	padded, err := Pad(plaintextOf(1000))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(padded)))
	for b.Loop() {
		if _, err := Unpad(padded); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzUnpad(f *testing.F) {
	for _, n := range []int{0, 5, 511, 512} {
		p, err := Pad(plaintextOf(n))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(p)
	}
	f.Add([]byte{})
	f.Add([]byte{0x80})
	f.Add(make([]byte, 512))
	f.Add(bytes.Repeat([]byte{0x80}, 512))
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := Unpad(input)
		if err != nil {
			if !errors.Is(err, ErrMalformed) || got != nil {
				t.Fatalf("unexpected failure result %d bytes, %v", len(got), err)
			}
			if size, bucketErr := BucketFor(len(input)); bucketErr == nil {
				repadded, padErr := Pad(input)
				if padErr != nil || len(repadded) != size {
					t.Fatalf("Pad of %d bytes: %d bytes, %v", len(input), len(repadded), padErr)
				}
				back, unpadErr := Unpad(repadded)
				if unpadErr != nil || !bytes.Equal(back, input) {
					t.Fatalf("round trip of fuzz input failed: %v", unpadErr)
				}
			}
			return
		}
		if !isBucket(len(input)) {
			t.Fatalf("accepted non-bucket length %d", len(input))
		}
		if len(got) >= len(input) || input[len(got)] != 0x80 {
			t.Fatalf("accepted input without marker at %d", len(got))
		}
		if len(bytes.Trim(input[len(got)+1:], "\x00")) != 0 {
			t.Fatal("accepted non-zero bytes after the marker")
		}
		if !bytes.Equal(got, input[:len(got)]) {
			t.Fatal("returned plaintext differs from the input prefix")
		}
		repadded, err := Pad(got)
		if err != nil || len(repadded) > len(input) || !bytes.Equal(repadded, input[:len(repadded)]) {
			t.Fatalf("Pad of the unpadded plaintext is not a prefix of the input: %v", err)
		}
	})
}
