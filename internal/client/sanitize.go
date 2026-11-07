package client

import "strings"

// SanitizeASCII returns s reduced to printable ASCII (0x20 to 0x7e), with
// every other byte replaced by '?', truncated to at most maxLen bytes
// (no limit if maxLen <= 0). Text that arrives from the network passes
// through it before it is shown, so a hostile server cannot inject terminal
// escape sequences or misleading Unicode.
func SanitizeASCII(s string, maxLen int) string {
	if maxLen > 0 && len(s) > maxLen {
		s = s[:maxLen]
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			b.WriteByte('?')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
