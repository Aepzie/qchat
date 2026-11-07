package e2e

import (
	"testing"

	"github.com/craguS/qchat/internal/crypto/sealbox"
)

// FuzzOpen feeds arbitrary plaintexts, correctly sealed to the recipient
// for the relay-reported pair, into Open. Sealing inside the target lets
// the fuzzer reach the Inner decoder and every check after decryption,
// which random ciphertext never would. Raw mode passes the input as the
// payload itself to exercise the size checks and the HPKE layer.
func FuzzOpen(f *testing.F) {
	alice, bob := newParty(f), newParty(f)
	aliceID, bobID := alice.identity.ID(), bob.identity.ID()
	lookup := directory(alice, bob)

	valid, err := encMode.Marshal(craft(aliceID, bobID))
	if err != nil {
		f.Fatal(err)
	}
	payload, _, err := Seal(alice.identity, bob.bundle, KindText, []byte("seed"), testNow)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(false, valid)
	f.Add(true, payload)
	f.Add(false, []byte{0xa8})
	f.Fuzz(func(t *testing.T, raw bool, input []byte) {
		box := input
		if !raw {
			box, err = sealbox.Seal(bob.bundle.KEMKey, messageInfo(aliceID, bobID), input)
			if err != nil {
				t.Fatal(err)
			}
		}
		msg, err := Open(bob.identity, aliceID, box, lookup, testNow)
		if err != nil {
			if msg != nil {
				t.Fatal("message returned with an error")
			}
			return
		}
		if msg.From != aliceID || msg.To != bobID || msg.Kind != KindText || len(msg.Body) == 0 {
			t.Fatalf("accepted inconsistent message %+v", msg)
		}
	})
}
