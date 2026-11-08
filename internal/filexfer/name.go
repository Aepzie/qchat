package filexfer

import (
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxSanitizedName bounds a sanitised name in bytes, leaving room for the
// " (n)" a unique name may add within common 255-byte limits.
const maxSanitizedName = 200

// fallbackName replaces a name that sanitises to nothing.
const fallbackName = "file"

// reservedNames are the device names Windows reserves in every directory,
// with or without an extension.
var reservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true, "CONIN$": true, "CONOUT$": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"COM¹": true, "COM²": true, "COM³": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	"LPT¹": true, "LPT²": true, "LPT³": true,
}

// SanitizeName turns a name chosen by a sender into a single, harmless
// file name component on every platform:
//
//   - only the part after the last '/' or '\' is kept;
//   - control and format characters (terminal escapes, bidirectional
//     overrides, zero-width characters) and invalid UTF-8 are removed;
//   - characters Windows forbids in names (<>:"|?*) become '_';
//   - leading dots and spaces and trailing dots and spaces are removed, so
//     the name is neither hidden nor "." or "..";
//   - a Windows device name (CON, NUL, COM1, ...), with any extension, gets
//     a '_' prefix;
//   - the result is at most 200 bytes, keeping the extension, and never
//     empty ("file" stands in).
func SanitizeName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r == utf8.RuneError, unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
		case strings.ContainsRune(`<>:"|?*`, r):
			b.WriteRune('_')
		case unicode.IsSpace(r):
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	clean := strings.TrimRight(strings.TrimLeft(b.String(), ". "), ". ")
	clean = shorten(clean, maxSanitizedName)
	if clean == "" {
		return fallbackName
	}
	stem, _, _ := strings.Cut(clean, ".")
	if reservedNames[strings.ToUpper(strings.TrimRight(stem, " "))] {
		clean = "_" + clean
	}
	return clean
}

// shorten cuts name to at most limit bytes on a rune boundary, keeping a
// short extension.
func shorten(name string, limit int) string {
	if len(name) <= limit {
		return name
	}
	ext := filepath.Ext(name)
	if len(ext) > 16 || !utf8.ValidString(ext) {
		ext = ""
	}
	stem := name[:len(name)-len(ext)]
	cut := limit - len(ext)
	for cut > 0 && !utf8.RuneStart(stem[cut]) {
		cut--
	}
	return strings.TrimRight(stem[:cut], ". ") + ext
}
