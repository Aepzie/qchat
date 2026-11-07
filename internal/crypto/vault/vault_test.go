package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	testPassphrase = []byte("correct horse battery staple")
	testSecret     = []byte("qchat vault known-answer secret")
)

const (
	// katBlobHex is the blob for testPassphrase/testSecret with katSalt,
	// katNonce and TestParams. It pins the header encoding, the Argon2id
	// derivation and the AEAD construction together.
	katBlobHex = "a701010201030104184005010650000102030405060708090a0b0c0d0e0f075818101112131415161718191a1b1c1d1e1f202122232425262779e0e174bc04d09919eb08d12c8340d06d12b701ad7d9e6d867a982ea3772ebfced6c5ec0fc7c42627577ff5902c15"

	// katDefaultBlobHash is SHA-256 of the same blob sealed with
	// DefaultParams, exercising Argon2id at production cost.
	katDefaultBlobHash = "161e06f4ea123c923ad2e32bb1010eb934573fd828e4ad899c9bbf143acfbe13"
)

func katSalt() []byte {
	salt := make([]byte, SaltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	return salt
}

func katNonce() []byte {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x10 + i)
	}
	return nonce
}

// withProductionRules makes the test observe the rules that apply outside
// test binaries, where weak parameters are refused.
func withProductionRules(t *testing.T) {
	t.Helper()
	saved := insecureParamsAllowed
	insecureParamsAllowed = func() bool { return false }
	t.Cleanup(func() { insecureParamsAllowed = saved })
}

func sealTest(t testing.TB, params Params) []byte {
	t.Helper()
	blob, err := Seal(testPassphrase, testSecret, params)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return blob
}

// rawHeader encodes an arbitrary header map with the package's canonical
// encoder, letting tests craft headers the package itself would never write.
func rawHeader(t *testing.T, fields map[int]any) []byte {
	t.Helper()
	b, err := encMode.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func validFields(params Params) map[int]any {
	return map[int]any{
		1: Version, 2: KDFArgon2id,
		3: params.Time, 4: params.MemoryKiB, 5: params.Threads,
		6: katSalt(), 7: katNonce(),
	}
}

func TestRoundTripTestParams(t *testing.T) {
	for _, secret := range [][]byte{{}, []byte("x"), bytes.Repeat([]byte{0xee}, 5000)} {
		blob, err := Seal(testPassphrase, secret, TestParams())
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(testPassphrase, blob)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, secret) {
			t.Errorf("round trip of %d bytes failed", len(secret))
		}
	}
}

func TestRoundTripDefaultParams(t *testing.T) {
	withProductionRules(t)
	blob := sealTest(t, DefaultParams())
	got, err := Open(testPassphrase, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, testSecret) {
		t.Error("round trip with default parameters failed")
	}
}

func TestDefaultParams(t *testing.T) {
	p := DefaultParams()
	if p.Time != 3 || p.MemoryKiB != 64*1024 || p.Threads != 4 {
		t.Errorf("DefaultParams = %+v, want t=3 m=65536 p=4", p)
	}
	if err := p.check(false); err != nil {
		t.Errorf("DefaultParams rejected under production rules: %v", err)
	}
}

func TestKnownAnswer(t *testing.T) {
	blob, err := sealWith(testPassphrase, testSecret, TestParams(), katSalt(), katNonce())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(blob); got != katBlobHex {
		t.Errorf("KAT blob = %s, want %s", got, katBlobHex)
	}
	want, err := hex.DecodeString(katBlobHex)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := Open(testPassphrase, want)
	if err != nil || !bytes.Equal(secret, testSecret) {
		t.Errorf("committed KAT blob does not open: %v", err)
	}
}

func TestKnownAnswerDefaultParams(t *testing.T) {
	blob, err := sealWith(testPassphrase, testSecret, DefaultParams(), katSalt(), katNonce())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	if got := hex.EncodeToString(sum[:]); got != katDefaultBlobHash {
		t.Errorf("SHA-256(default-params KAT blob) = %s, want %s", got, katDefaultBlobHash)
	}
}

func TestSealIsRandomised(t *testing.T) {
	a := sealTest(t, TestParams())
	b := sealTest(t, TestParams())
	if bytes.Equal(a, b) {
		t.Error("two seals of the same secret are identical")
	}
	ha, _, _, err := parse(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, _, _, err := parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ha.Salt, hb.Salt) || bytes.Equal(ha.Nonce, hb.Nonce) {
		t.Error("salt or nonce repeated between seals")
	}
}

func TestWrongPassphrase(t *testing.T) {
	blob := sealTest(t, TestParams())
	for _, pass := range [][]byte{nil, {}, []byte("correct horse battery stapl"), []byte("correct horse battery staple "), []byte("Correct horse battery staple")} {
		got, err := Open(pass, blob)
		if !errors.Is(err, ErrWrongPassphrase) || got != nil {
			t.Errorf("passphrase %q: got %q, err = %v, want ErrWrongPassphrase", pass, got, err)
		}
	}
}

func TestEmptyPassphraseRefused(t *testing.T) {
	for _, pass := range [][]byte{nil, {}} {
		if _, err := Seal(pass, testSecret, TestParams()); !errors.Is(err, ErrEmptyPassphrase) {
			t.Errorf("err = %v, want ErrEmptyPassphrase", err)
		}
	}
}

// TestTamperEveryByte flips one bit in every byte of a blob. Every variant
// must fail and none may leak the secret. Ciphertext and tag changes must
// surface as ErrWrongPassphrase.
func TestTamperEveryByte(t *testing.T) {
	blob := sealTest(t, TestParams())
	_, headerBytes, _, err := parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	for pos := range blob {
		tampered := bytes.Clone(blob)
		tampered[pos] ^= 0x01
		got, err := Open(testPassphrase, tampered)
		if err == nil || got != nil {
			t.Fatalf("byte %d: tampered blob opened", pos)
		}
		if pos >= len(headerBytes) && !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("ciphertext byte %d: err = %v, want ErrWrongPassphrase", pos, err)
		}
	}
}

// TestHeaderIsAuthenticated rewrites header fields into a different but
// perfectly well-formed header and keeps the original ciphertext. This must
// fail with ErrWrongPassphrase, proving the header is bound as AAD; in
// particular the KDF cost cannot be downgraded.
func TestHeaderIsAuthenticated(t *testing.T) {
	params := Params{Time: 2, MemoryKiB: 128, Threads: 2, insecure: true}
	blob, err := sealWith(testPassphrase, testSecret, params, katSalt(), katNonce())
	if err != nil {
		t.Fatal(err)
	}
	_, headerBytes, ciphertext, err := parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawHeader(t, validFields(params)), headerBytes) {
		t.Fatal("test header construction does not match Seal")
	}

	otherSalt := katSalt()
	otherSalt[0] ^= 1
	otherNonce := katNonce()
	otherNonce[23] ^= 1
	edits := map[string]func(map[int]any){
		"time":    func(f map[int]any) { f[3] = uint32(1) },
		"memory":  func(f map[int]any) { f[4] = uint32(64) },
		"threads": func(f map[int]any) { f[5] = uint8(1) },
		"salt":    func(f map[int]any) { f[6] = otherSalt },
		"nonce":   func(f map[int]any) { f[7] = otherNonce },
	}
	for name, edit := range edits {
		fields := validFields(params)
		edit(fields)
		forged := append(rawHeader(t, fields), ciphertext...)
		got, err := Open(testPassphrase, forged)
		if !errors.Is(err, ErrWrongPassphrase) || got != nil {
			t.Errorf("%s changed: err = %v, want ErrWrongPassphrase", name, err)
		}
	}
}

func TestTruncationAndExtension(t *testing.T) {
	blob := sealTest(t, TestParams())
	for n := 0; n < len(blob); n++ {
		if got, err := Open(testPassphrase, blob[:n]); err == nil || got != nil {
			t.Fatalf("blob truncated to %d bytes opened", n)
		}
	}
	extended := append(bytes.Clone(blob), 0)
	if _, err := Open(testPassphrase, extended); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("extended blob: err = %v, want ErrWrongPassphrase", err)
	}
}

func TestMalformedHeaders(t *testing.T) {
	params := TestParams()
	tag := make([]byte, TagSize)
	canonical := rawHeader(t, validFields(params))

	withField := func(key int, value any) []byte {
		fields := validFields(params)
		fields[key] = value
		return append(rawHeader(t, fields), tag...)
	}
	without := func(key int) []byte {
		fields := validFields(params)
		delete(fields, key)
		return append(rawHeader(t, fields), tag...)
	}

	nonMinimal := bytes.Clone(canonical)
	if nonMinimal[0] != 0xa7 || nonMinimal[1] != 0x01 || nonMinimal[2] != 0x01 {
		t.Fatalf("unexpected header prefix %x", nonMinimal[:3])
	}
	nonMinimal = append([]byte{0xa7, 0x01, 0x18, 0x01}, nonMinimal[3:]...)

	duplicate := append([]byte{0xa8}, canonical[1:]...)
	duplicate = append(duplicate, 0x01, 0x01)

	indefinite := append([]byte{0xbf}, canonical[1:]...)
	indefinite = append(indefinite, 0xff)

	cases := map[string][]byte{
		"nil":               nil,
		"empty":             {},
		"not a map":         {0x83, 0x01, 0x02, 0x03},
		"garbage":           bytes.Repeat([]byte{0xff}, 64),
		"missing tag":       canonical,
		"short tag":         append(bytes.Clone(canonical), tag[:TagSize-1]...),
		"non-minimal int":   append(nonMinimal, tag...),
		"duplicate key":     append(duplicate, tag...),
		"indefinite map":    append(indefinite, tag...),
		"unknown field":     withField(8, 1),
		"short salt":        withField(6, make([]byte, SaltSize-1)),
		"long salt":         withField(6, make([]byte, SaltSize+1)),
		"short nonce":       withField(7, make([]byte, NonceSize-1)),
		"salt as text":      withField(6, "0123456789abcdef"),
		"salt as array":     withField(6, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}),
		"threads overflow":  withField(5, 256),
		"negative time":     withField(3, -1),
		"missing salt":      without(6),
		"missing nonce":     without(7),
		"version as string": withField(1, "1"),
		"tagged salt":       append(bytes.Replace(canonical, []byte{0x06, 0x50}, []byte{0x06, 0xc2, 0x50}, 1), tag...),
	}
	for name, blob := range cases {
		got, err := Open(testPassphrase, blob)
		if got != nil || err == nil {
			t.Errorf("%s: opened", name)
			continue
		}
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestUnsupportedVersionAndKDF(t *testing.T) {
	params := TestParams()
	tag := make([]byte, TagSize)
	cases := map[string]map[int]any{}

	v2 := validFields(params)
	v2[1] = 2
	cases["version 2"] = v2

	v2Extra := validFields(params)
	v2Extra[1] = 2
	v2Extra[9] = "future field"
	cases["version 2 with new field"] = v2Extra

	v0 := validFields(params)
	v0[1] = 0
	cases["version 0"] = v0

	kdf := validFields(params)
	kdf[2] = 2
	cases["kdf 2"] = kdf

	for name, fields := range cases {
		_, err := Open(testPassphrase, append(rawHeader(t, fields), tag...))
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("%s: err = %v, want ErrUnsupportedVersion", name, err)
		}
	}
}

// TestHostileParamsRejectedBeforeKDF feeds headers demanding enormous Argon2
// cost. They must be refused without running the KDF, which the time limit
// makes observable: actually deriving with these parameters would take many
// seconds and gigabytes of memory.
func TestHostileParamsRejectedBeforeKDF(t *testing.T) {
	tag := make([]byte, TagSize)
	hostile := []Params{
		{Time: 1, MemoryKiB: MaxMemoryKiB + 1, Threads: 4},
		{Time: 1, MemoryKiB: 0xffffffff, Threads: 4},
		{Time: MaxTime + 1, MemoryKiB: 64 * 1024, Threads: 4},
		{Time: 0xffffffff, MemoryKiB: 64 * 1024, Threads: 4},
		{Time: 3, MemoryKiB: 64 * 1024, Threads: MaxThreads + 1},
		{Time: 3, MemoryKiB: 64 * 1024, Threads: 255},
		{Time: 0, MemoryKiB: 64 * 1024, Threads: 4},
		{Time: 3, MemoryKiB: 64 * 1024, Threads: 0},
		{Time: 3, MemoryKiB: 0, Threads: 4},
		{Time: 3, MemoryKiB: 31, Threads: 4},
	}
	start := time.Now()
	for _, p := range hostile {
		_, err := Open(testPassphrase, append(rawHeader(t, validFields(p)), tag...))
		if !errors.Is(err, ErrUnsafeParams) {
			t.Errorf("%+v: err = %v, want ErrUnsafeParams", p, err)
		}
		if _, err := Seal(testPassphrase, testSecret, p); !errors.Is(err, ErrUnsafeParams) {
			t.Errorf("Seal %+v: err = %v, want ErrUnsafeParams", p, err)
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("rejecting hostile parameters took %v; the KDF probably ran", elapsed)
	}
}

func TestProductionFloor(t *testing.T) {
	withProductionRules(t)
	if _, err := Seal(testPassphrase, testSecret, TestParams()); !errors.Is(err, ErrUnsafeParams) {
		t.Errorf("Seal with TestParams outside tests: err = %v, want ErrUnsafeParams", err)
	}

	weak, err := hex.DecodeString(katBlobHex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(testPassphrase, weak); !errors.Is(err, ErrUnsafeParams) {
		t.Errorf("Open of weak blob outside tests: err = %v, want ErrUnsafeParams", err)
	}

	cases := []struct {
		p  Params
		ok bool
	}{
		{DefaultParams(), true},
		{Params{Time: 1, MemoryKiB: 96 * 1024, Threads: 4}, true},
		{Params{Time: 2, MemoryKiB: 48 * 1024, Threads: 1}, true},
		{Params{Time: 3, MemoryKiB: 32 * 1024, Threads: 2}, true},
		{Params{Time: MaxTime, MemoryKiB: MaxMemoryKiB, Threads: MaxThreads}, true},
		{Params{Time: 2, MemoryKiB: 32 * 1024, Threads: 4}, false},
		{Params{Time: 10, MemoryKiB: 32*1024 - 1, Threads: 4}, false},
		{Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 4}, false},
		{Params{Time: 3, MemoryKiB: 64, Threads: 1}, false},
	}
	for _, tc := range cases {
		err := tc.p.check(false)
		if (err == nil) != tc.ok {
			t.Errorf("%+v: err = %v, want ok=%v", tc.p, err, tc.ok)
		}
	}

	// Weak parameters built by hand (without TestParams) are refused even
	// inside test binaries.
	insecureParamsAllowed = func() bool { return true }
	if _, err := Seal(testPassphrase, testSecret, Params{Time: 1, MemoryKiB: 64, Threads: 1}); !errors.Is(err, ErrUnsafeParams) {
		t.Errorf("hand-made weak params: err = %v, want ErrUnsafeParams", err)
	}
}

func TestRandomKey(t *testing.T) {
	a, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || a == [KeySize]byte{} {
		t.Error("RandomKey returned a repeated or zero key")
	}
}

func FuzzOpen(f *testing.F) {
	valid, err := sealWith(testPassphrase, testSecret, TestParams(), katSalt(), katNonce())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(testPassphrase, valid)
	f.Add(testPassphrase, valid[:len(valid)-1])
	f.Add([]byte("wrong"), valid)
	f.Add([]byte{}, []byte{})
	f.Add(testPassphrase, []byte{0xa7, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, passphrase, blob []byte) {
		// Keep each execution cheap: inputs that pass validation but ask
		// for more Argon2 work than the test parameters are only parsed.
		// The bounds themselves are covered by the unit tests above.
		if hdr, _, _, err := parse(blob); err == nil && uint64(hdr.Time)*uint64(hdr.MemoryKiB) > 4*1024 {
			return
		}
		secret, err := Open(passphrase, blob)
		if err != nil {
			if secret != nil {
				t.Fatal("secret returned together with an error")
			}
			return
		}
		if !bytes.Equal(blob, valid) || !bytes.Equal(passphrase, testPassphrase) || !bytes.Equal(secret, testSecret) {
			t.Fatalf("unexpected blob opened: %x", blob)
		}
	})
}

// TestConstructionMatchesSpec decrypts the KAT blob with the primitives
// called directly, following the documented format: Argon2id over the
// passphrase and salt, then XChaCha20-Poly1305 with the exact header bytes as
// associated data.
func TestConstructionMatchesSpec(t *testing.T) {
	blob, err := hex.DecodeString(katBlobHex)
	if err != nil {
		t.Fatal(err)
	}
	headerBytes := rawHeader(t, validFields(TestParams()))
	if !bytes.HasPrefix(blob, headerBytes) {
		t.Fatal("blob does not start with the documented header")
	}
	key := argon2.IDKey(testPassphrase, katSalt(), 1, 64, 1, 32)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := aead.Open(nil, katNonce(), blob[len(headerBytes):], headerBytes)
	if err != nil {
		t.Fatalf("manual decryption failed: %v", err)
	}
	if !bytes.Equal(secret, testSecret) {
		t.Error("manual decryption returned a different secret")
	}
	if _, err := aead.Open(nil, katNonce(), blob[len(headerBytes):], nil); err == nil {
		t.Error("ciphertext opens without the header as associated data")
	}
}
