package identity

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func FuzzParseID(f *testing.F) {
	f.Add("qc1-a2us-rgnf-kggl-gea5-7icx-yxfe-oyfj-f6rk-42st-5qqc-7eia-v3ip-odwa")
	f.Add("A2USRGNFKGGLGEA57ICXYXFEOYFJF6RK42ST5QQC7EIAV3IPODWA")
	f.Add(strings.Repeat("a", idChars-1) + "b")
	f.Add("qc1-K")
	f.Fuzz(func(t *testing.T, input string) {
		id, err := ParseID(input)
		if err != nil {
			return
		}
		again, err := ParseID(id.String())
		if err != nil || again != id {
			t.Fatalf("String/ParseID round trip failed for %q: %v", input, err)
		}
	})
}

func FuzzParseBundle(f *testing.F) {
	identity, err := fromSeeds(katSeeds())
	if err != nil {
		f.Fatal(err)
	}
	raw, err := identity.Bundle(katSerial, time.Unix(katCreated, 0))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add(raw[:len(raw)/2])
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, input []byte) {
		bundle, err := ParseBundle(input)
		if err != nil {
			if bundle != nil {
				t.Fatal("non-nil bundle with error")
			}
			return
		}
		if !bytes.Equal(bundle.Raw, input) || bundle.ID != IDFromSigningKey(bundle.SigningKey) || bundle.Serial == 0 {
			t.Fatalf("accepted bundle is inconsistent: %+v", bundle)
		}
		if _, err := ParseBundleForID(input, bundle.ID); err != nil {
			t.Fatalf("ParseBundleForID rejects own ID: %v", err)
		}
	})
}
