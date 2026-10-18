// Package alias builds the alias dictionary: it maps the vendor and
// product names a CNA writes (and deprecated or alternate CPE names) to
// the canonical CPE identity of the product, so a CVE whose record names
// its product only by those strings matches the software platforms see.
//
// Inputs are public advisory text and therefore untrusted: every string is
// sanitised, normalised into the CPE naming convention and capped, and a
// learned mapping needs repeated, consistent evidence.
//
// Design: OpenCTEM RFC-066 §5.6.
package alias

import (
	"strings"

	"github.com/openctemio/vulnfeed/internal/model"
)

// Placeholder vendor or product names that identify nothing.
var placeholders = map[string]bool{"n/a": true, "na": true, "n_a": true, "unknown": true, "unspecified": true,
	"various": true, "multiple": true, "none": true, "-": true, "*": true, "not_applicable": true, "n.a": true}

// Legal-form words dropped from the end of a vendor name ("Google Inc.",
// "Microsoft Corporation", "Foo Co., Ltd.").
var legalSuffixes = map[string]bool{"inc": true, "incorporated": true, "corp": true, "corporation": true,
	"ltd": true, "limited": true, "gmbh": true, "co": true, "llc": true, "l.l.c": true, "s.a": true, "sa": true,
	"ag": true, "plc": true, "b.v": true, "bv": true, "oy": true, "ab": true, "s.r.l": true, "srl": true,
	"pty": true, "s.p.a": true, "spa": true, "k.k": true, "kk": true, "a.s": true, "sas": true, "s.a.s": true}

// Key turns a name into the CPE naming convention: lower case, spaces and
// slashes as underscores, only letters, digits and . _ - kept. A
// placeholder or a name longer than a CPE component gives "".
func Key(s string) string {
	s = strings.ToLower(model.CleanText(s, 4*model.MaxFieldLen))
	if placeholders[s] {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		case r == '_' || r == ' ' || r == '/' || r == ',':
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "_") {
				b.WriteByte('_')
			}
		}
	}
	k := strings.Trim(b.String(), "_.-")
	if len(k) > model.MaxFieldLen || placeholders[k] {
		return ""
	}
	return k
}

// VendorKey is Key without trailing legal-form words.
func VendorKey(s string) string {
	k := Key(s)
	parts := strings.Split(k, "_")
	for len(parts) > 1 && legalSuffixes[strings.Trim(parts[len(parts)-1], ".")] {
		parts = parts[:len(parts)-1]
	}
	return strings.Trim(strings.Join(parts, "_"), "_.-")
}

// ProductKey is Key without parenthesised qualifiers ("Windows Server
// 2019 (Server Core installation)" is the product Windows Server 2019).
func ProductKey(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '(' || r == '[':
			depth++
		case (r == ')' || r == ']') && depth > 0:
			depth--
		case depth == 0:
			b.WriteRune(r)
		}
	}
	if k := Key(b.String()); k != "" {
		return k
	}
	return Key(s)
}
