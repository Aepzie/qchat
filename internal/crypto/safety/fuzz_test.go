package safety

import (
	"encoding/hex"
	"strings"
	"testing"
)

func FuzzParseQRPayload(f *testing.F) {
	idA, pubA, idB, pubB := katParties()
	f.Add(QRPayload(idA, pubA, idB, pubB))
	f.Add(QRPrefix)
	f.Add(QRPrefix + strings.Repeat(":", 64))
	f.Add(QRPrefix + strings.Repeat("0", 64) + ":" + strings.Repeat("0", 64) + ":" + strings.Repeat("1", Digits) + ":")
	f.Fuzz(func(t *testing.T, payload string) {
		first, second, number, err := ParseQRPayload(payload)
		if err != nil {
			if first != [IDSize]byte{} || second != [IDSize]byte{} || number != "" {
				t.Fatal("non-zero results with error")
			}
			return
		}
		rebuilt := QRPrefix + hex.EncodeToString(first[:]) + ":" + hex.EncodeToString(second[:]) + ":" + number
		if rebuilt != payload {
			t.Fatalf("accepted %q, which rebuilds as %q", payload, rebuilt)
		}
	})
}
