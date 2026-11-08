package client

import "testing"

func FuzzSanitizeASCII(f *testing.F) {
	f.Add("ok \x1b[31mred\x07", 0)
	f.Add("abcdef", 3)
	f.Add("\xff\xfe\u202e", 2)
	f.Add("", -1)
	f.Fuzz(func(t *testing.T, input string, maxLen int) {
		out := SanitizeASCII(input, maxLen)
		for i := 0; i < len(out); i++ {
			if out[i] < 0x20 || out[i] > 0x7e {
				t.Fatalf("SanitizeASCII(%q, %d) = %q contains byte 0x%02x", input, maxLen, out, out[i])
			}
		}
		if maxLen > 0 && len(out) > maxLen {
			t.Fatalf("SanitizeASCII(%q, %d) returned %d bytes", input, maxLen, len(out))
		}
		if maxLen <= 0 && len(out) != len(input) {
			t.Fatalf("SanitizeASCII(%q, %d) changed the length to %d", input, maxLen, len(out))
		}
	})
}
