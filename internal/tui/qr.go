package tui

import (
	"strings"

	"rsc.io/qr"
)

// encodeQR encodes payload, or returns nil for an empty or unencodable one.
func encodeQR(payload string, level qr.Level) *qr.Code {
	if payload == "" {
		return nil
	}
	code, err := qr.Encode(payload, level)
	if err != nil {
		return nil
	}
	return code
}

// qrSize returns the width and height in cells of a code drawn by qrLines.
func qrSize(code *qr.Code, quiet int) (int, int) {
	n := code.Size + 2*quiet
	return n, (n + 1) / 2
}

// qrLines draws a QR code with Unicode half blocks, two module rows per
// text line, surrounded by a quiet zone of the given number of modules.
// Light modules are the drawn (foreground) parts, so with a light
// foreground on a dark background the code has the normal polarity
// scanners expect, whatever the terminal's own colors are.
func qrLines(code *qr.Code, quiet int) []string {
	n := code.Size + 2*quiet
	light := func(x, y int) bool {
		if y >= n {
			return false
		}
		return !code.Black(x-quiet, y-quiet)
	}
	lines := make([]string, 0, (n+1)/2)
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		b.Reset()
		for x := 0; x < n; x++ {
			top, bottom := light(x, y), light(x, y+1)
			switch {
			case top && bottom:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bottom:
				b.WriteRune('▄')
			default:
				b.WriteByte(' ')
			}
		}
		lines = append(lines, b.String())
	}
	return lines
}
