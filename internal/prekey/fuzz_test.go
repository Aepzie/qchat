package prekey

import (
	"bytes"
	"testing"
)

func FuzzParseSignedPrekey(f *testing.F) {
	s := newTestSigner(f)
	pair, err := GenerateSignedPrekey(s, testNow, testLifetime)
	if err != nil {
		f.Fatal(err)
	}
	opks, err := GenerateOneTimePrekeys(s, 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pair.Public.Raw)
	f.Add(opks[0].Public.Raw)
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		parsed, err := ParseSignedPrekey(raw, s.bundle, testNow)
		if err == nil {
			if !bytes.Equal(parsed.Raw, raw) || parsed.Owner != s.ID() || parsed.KeyID == 0 ||
				!parsed.Expires.After(parsed.Created) || !testNow.Before(parsed.Expires) ||
				parsed.Created.After(testNow.Add(MaxClockSkew)) {
				t.Fatalf("accepted prekey violates invariants: %+v", parsed)
			}
		}
		if opk, err := ParseOneTimePrekey(raw, s.bundle); err == nil && !bytes.Equal(opk.Raw, raw) {
			t.Fatal("one-time prekey Raw differs from input")
		}
		_, _, _ = UnmarshalPrivate(raw)
	})
}
