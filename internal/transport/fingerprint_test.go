package transport

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

// sha256("abc"), a standard test vector.
const abcHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func abcFingerprint(t testing.TB) Fingerprint {
	t.Helper()
	return FingerprintOf(&x509.Certificate{RawSubjectPublicKeyInfo: []byte("abc")})
}

func TestFingerprintOfKnownVector(t *testing.T) {
	f := abcFingerprint(t)
	if got, want := f.String(), "sha256:"+abcHex; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if !FingerprintOf(nil).IsZero() {
		t.Fatal("FingerprintOf(nil) should be zero")
	}
}

func TestFingerprintGrouped(t *testing.T) {
	f := abcFingerprint(t)
	want := "ba78 16bf 8f01 cfea 4141 40de 5dae 2223 b003 61a3 9617 7a9c b410 ff61 f200 15ad"
	if got := f.Grouped(); got != want {
		t.Fatalf("Grouped() = %q, want %q", got, want)
	}
	if groups := strings.Fields(f.Grouped()); len(groups) != 16 {
		t.Fatalf("Grouped() has %d groups, want 16", len(groups))
	}
}

func TestParseFingerprintAcceptedForms(t *testing.T) {
	want := abcFingerprint(t)
	var colon []string
	for i := 0; i < len(abcHex); i += 2 {
		colon = append(colon, strings.ToUpper(abcHex[i:i+2]))
	}

	inputs := []string{
		"sha256:" + abcHex,
		"SHA256:" + abcHex,
		"Sha256:" + strings.ToUpper(abcHex),
		abcHex,
		strings.ToUpper(abcHex),
		strings.Join(colon, ":"),
		"sha256:" + strings.Join(colon, ":"),
		want.Grouped(),
		"  sha256:" + want.Grouped() + "\n",
		"ba7816bf8f01cfea414140de5dae2223\nb00361a396177a9cb410ff61f20015ad",
	}
	for _, in := range inputs {
		got, err := ParseFingerprint(in)
		if err != nil {
			t.Errorf("ParseFingerprint(%q) error: %v", in, err)
			continue
		}
		if !got.Equal(want) {
			t.Errorf("ParseFingerprint(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestParseFingerprintRejected(t *testing.T) {
	inputs := []string{
		"",
		"sha256:",
		"   ",
		abcHex[:63],
		abcHex + "0",
		abcHex + "00",
		"g" + abcHex[1:],
		"sha256:sha256:" + abcHex,
		"sha512:" + abcHex,
		"sha256-" + abcHex,
		"0x" + abcHex,
		abcHex[:32] + "-" + abcHex[32:],
		abcHex[:32] + "é" + abcHex[32:],
		"ſha256:" + abcHex,
		strings.Repeat("0", 64),
		"sha256:" + strings.Repeat("00:", 31) + "00",
		strings.Repeat(" ", 600) + abcHex,
	}
	for _, in := range inputs {
		f, err := ParseFingerprint(in)
		if err == nil {
			t.Errorf("ParseFingerprint(%q) = %s, want error", in, f)
			continue
		}
		if !errors.Is(err, errInvalidFingerprint) {
			t.Errorf("ParseFingerprint(%q) error %v does not wrap errInvalidFingerprint", in, err)
		}
		if !f.IsZero() {
			t.Errorf("ParseFingerprint(%q) returned non-zero value on error", in)
		}
	}
}

func TestFingerprintEqualAndIsZero(t *testing.T) {
	a := abcFingerprint(t)
	b := a
	if !a.Equal(b) {
		t.Fatal("identical fingerprints not Equal")
	}
	b[31] ^= 1
	if a.Equal(b) {
		t.Fatal("fingerprints differing in last byte reported Equal")
	}
	c := a
	c[0] ^= 0x80
	if a.Equal(c) {
		t.Fatal("fingerprints differing in first byte reported Equal")
	}
	if a.IsZero() {
		t.Fatal("non-zero fingerprint reported IsZero")
	}
	var zero Fingerprint
	if !zero.IsZero() {
		t.Fatal("zero fingerprint not IsZero")
	}
}

func TestFingerprintRoundTrip(t *testing.T) {
	f := abcFingerprint(t)
	for _, s := range []string{f.String(), f.Grouped()} {
		got, err := ParseFingerprint(s)
		if err != nil {
			t.Fatalf("ParseFingerprint(%q): %v", s, err)
		}
		if got != f {
			t.Fatalf("round trip of %q gave %s", s, got)
		}
	}
}

func FuzzParseFingerprint(f *testing.F) {
	seed := abcFingerprint(f)
	f.Add(seed.String())
	f.Add(seed.Grouped())
	f.Add(strings.ToUpper(abcHex))
	f.Add("sha256:" + strings.Repeat("00", 32))
	f.Add("sha256:")
	f.Add("")
	f.Add(":::: \t\n")
	f.Add("SHA256:AB:CD")

	f.Fuzz(func(t *testing.T, in string) {
		fp, err := ParseFingerprint(in)
		if err != nil {
			if !fp.IsZero() {
				t.Fatalf("non-zero result alongside error for %q", in)
			}
			return
		}
		if fp.IsZero() {
			t.Fatalf("zero fingerprint accepted for %q", in)
		}

		s := fp.String()
		if len(s) != len("sha256:")+64 || !strings.HasPrefix(s, "sha256:") || strings.ToLower(s) != s {
			t.Fatalf("malformed String() %q", s)
		}
		for _, form := range []string{s, fp.Grouped(), strings.ToUpper(s)} {
			back, err := ParseFingerprint(form)
			if err != nil {
				t.Fatalf("re-parse of %q failed: %v", form, err)
			}
			if !back.Equal(fp) {
				t.Fatalf("re-parse of %q gave %s, want %s", form, back, fp)
			}
		}
	})
}
