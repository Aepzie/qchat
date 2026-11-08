package app

import (
	"bytes"
	"testing"
)

// FuzzParseControlMessage checks that parseControlMessage never panics and
// that whatever it accepts encodes back to exactly the same bytes.
func FuzzParseControlMessage(f *testing.F) {
	for _, m := range []controlMessage{
		{Control: []byte{1, 2, 3}},
		{History: [][]byte{{4}, {5, 6}}},
		{Control: []byte("control"), History: [][]byte{[]byte("one")}},
	} {
		seed, err := marshalControlMessage(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte{0xa1, 0x02, 0x81, 0x40})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := parseControlMessage(b)
		if err != nil {
			return
		}
		again, err := marshalControlMessage(m)
		if err != nil {
			t.Fatalf("accepted message does not encode: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("round trip changed %x to %x", b, again)
		}
	})
}
