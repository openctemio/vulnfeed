package model

import "strings"

// Sanitize makes source text safe to carry: invalid UTF-8 is dropped, line
// breaks and tabs become spaces, and control, zero-width and bidirectional
// formatting characters are removed (they can disguise text). The platform
// renders text safely, but the bundle does not rely on it.
func Sanitize(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t' || r == '\r' || r == 0x2028 || r == 0x2029:
			return ' '
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			return -1
		case (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0xfeff:
			return -1
		}
		return r
	}, s)
}

// Clip cuts s to at most n bytes without splitting a character.
func Clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// CleanText is Sanitize, trimmed and clipped to n bytes.
func CleanText(s string, n int) string {
	return Clip(strings.TrimSpace(Sanitize(s)), n)
}
