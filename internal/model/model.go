// Package model is the bundle's record model and its validation.
//
// The rules are the ones the OpenCTEM importer applies (RFC-066 §5.5): a
// bundle with one record the importer would refuse is refused whole, so the
// collector refuses to publish it first.
package model

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Limits.
const (
	MaxVersionLen     = 64
	MaxFieldLen       = 128
	MaxNameLen        = 200
	MaxDescriptionLen = 4000
	MaxQualifierLen   = 64
	MaxCWEs           = 16
	MaxVector         = 200
)

var (
	vulnIDRE   = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	cweRE      = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
	vectorRE   = regexp.MustCompile(`^[A-Za-z0-9:/.\-_()]{1,200}$`)
	severities = map[string]bool{"none": true, "low": true, "medium": true, "high": true, "critical": true}
	schemes    = map[string]bool{"generic": true}
	sources    = map[string]bool{"nvd": true}
)

// Product is a public product named by the bundle.
type Product struct {
	Key        string `json:"key"`
	Part       string `json:"part"`
	Vendor     string `json:"vendor"`
	Name       string `json:"name"`
	CPEVendor  string `json:"cpe_vendor"`
	CPEProduct string `json:"cpe_product"`
}

// Vuln is one vulnerability record.
type Vuln struct {
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	Published   *time.Time `json:"published,omitempty"`
	Modified    *time.Time `json:"modified,omitempty"`
	Description string     `json:"description"`
	CVSS        *CVSS      `json:"cvss,omitempty"`
	Severity    string     `json:"severity,omitempty"`
	CWEs        []string   `json:"cwes"`
}

// CVSS is the primary score.
type CVSS struct {
	Version string  `json:"version"`
	Score   float64 `json:"score"`
	Vector  string  `json:"vector"`
}

// Range is one affected range of a product.
type Range struct {
	Vuln      string `json:"vuln"`
	Product   string `json:"product"`
	Scheme    string `json:"scheme"`
	Exact     string `json:"exact,omitempty"`
	Start     string `json:"start,omitempty"`
	StartIncl bool   `json:"start_incl"`
	End       string `json:"end,omitempty"`
	EndIncl   bool   `json:"end_incl"`
	Edition   string `json:"edition"`
	Target    string `json:"target"`
	Condition string `json:"condition,omitempty"`
	Source    string `json:"source"`
}

// ProductKey builds "cpe:<part>:<vendor>:<product>".
func ProductKey(part, vendor, product string) string {
	return "cpe:" + part + ":" + vendor + ":" + product
}

// ValidProductKey reports whether k is a well-formed product key with a
// concrete, lower-case vendor and product.
func ValidProductKey(k string) bool {
	if len(k) > 2*MaxFieldLen+8 || !strings.HasPrefix(k, "cpe:") {
		return false
	}
	parts := strings.SplitN(k[4:], ":", 3)
	if len(parts) != 3 || (parts[0] != "a" && parts[0] != "o" && parts[0] != "h") {
		return false
	}
	return concrete(parts[1]) && concrete(parts[2]) && !strings.Contains(parts[2], ":") && strings.ToLower(k) == k
}

func concrete(v string) bool {
	if v == "" || len(v) > MaxFieldLen || v == "*" || v == "-" || strings.ContainsAny(v, "*?") {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ValidVersion reports whether v is a comparable version the platform
// accepts: at most 64 characters of letters, digits and . - _ + ~, starting
// with a digit, or a letter and a digit (r24), after an optional leading v.
func ValidVersion(v string) bool {
	if v == "" || len(v) > MaxVersionLen || strings.TrimSpace(v) != v {
		return false
	}
	t := strings.ToLower(v)
	if len(t) > 1 && t[0] == 'v' && isDigit(t[1]) {
		t = t[1:]
	}
	if !isDigit(t[0]) && (len(t) < 2 || t[0] < 'a' || t[0] > 'z' || !isDigit(t[1])) {
		return false
	}
	segs := 0
	prev := byte(0)
	for i := 0; i < len(t); i++ {
		c := t[i]
		kind := byte(0)
		switch {
		case isDigit(c):
			kind = 'd'
		case c >= 'a' && c <= 'z':
			kind = 'a'
		case c == '.' || c == '-' || c == '_' || c == '+' || c == '~':
			prev = 0
			continue
		default:
			return false
		}
		if kind != prev {
			segs++
			prev = kind
		}
	}
	if segs > 16 {
		return false
	}
	// A number of more than 18 significant digits does not fit the
	// comparator.
	for i := 0; i < len(t); {
		if !isDigit(t[i]) {
			i++
			continue
		}
		j := i
		for j < len(t) && isDigit(t[j]) {
			j++
		}
		if len(strings.TrimLeft(t[i:j], "0")) > 18 {
			return false
		}
		i = j
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Validate checks a product.
func (p Product) Validate() error {
	switch {
	case !ValidProductKey(p.Key):
		return fmt.Errorf("product key %q", p.Key)
	case p.Key != ProductKey(p.Part, p.CPEVendor, p.CPEProduct):
		return fmt.Errorf("product %q: key does not match its CPE fields", p.Key)
	case p.Name == "" || len(p.Name) > MaxNameLen || len(p.Vendor) > MaxFieldLen:
		return fmt.Errorf("product %q: name or vendor length", p.Key)
	}
	return nil
}

// Validate checks a vulnerability record.
func (v Vuln) Validate() error {
	switch {
	case !vulnIDRE.MatchString(v.ID):
		return fmt.Errorf("vuln id %q", v.ID)
	case len(v.Status) > 32:
		return fmt.Errorf("vuln %s: status length", v.ID)
	case len(v.Description) > MaxDescriptionLen || strings.ContainsAny(v.Description, "\x00\r\n"):
		return fmt.Errorf("vuln %s: description", v.ID)
	case v.Severity != "" && !severities[v.Severity]:
		return fmt.Errorf("vuln %s: severity %q", v.ID, v.Severity)
	case len(v.CWEs) > MaxCWEs:
		return fmt.Errorf("vuln %s: too many CWEs", v.ID)
	}
	for _, c := range v.CWEs {
		if !cweRE.MatchString(c) {
			return fmt.Errorf("vuln %s: cwe %q", v.ID, c)
		}
	}
	if c := v.CVSS; c != nil {
		if c.Score < 0 || c.Score > 10 || len(c.Version) > 8 || (c.Vector != "" && !vectorRE.MatchString(c.Vector)) {
			return fmt.Errorf("vuln %s: cvss", v.ID)
		}
	}
	return nil
}

// Validate checks a range.
func (r Range) Validate() error {
	switch {
	case !vulnIDRE.MatchString(r.Vuln):
		return fmt.Errorf("range vuln %q", r.Vuln)
	case !ValidProductKey(r.Product):
		return fmt.Errorf("range %s: product %q", r.Vuln, r.Product)
	case !schemes[r.Scheme]:
		return fmt.Errorf("range %s: scheme %q", r.Vuln, r.Scheme)
	case !sources[r.Source]:
		return fmt.Errorf("range %s: source %q", r.Vuln, r.Source)
	case r.Condition != "" && !ValidProductKey(r.Condition):
		return fmt.Errorf("range %s: condition %q", r.Vuln, r.Condition)
	case len(r.Edition) > MaxQualifierLen || len(r.Target) > MaxQualifierLen ||
		strings.ToLower(r.Edition) != r.Edition || strings.ToLower(r.Target) != r.Target:
		return fmt.Errorf("range %s: edition or target", r.Vuln)
	case r.Exact != "" && (r.Start != "" || r.End != ""):
		return fmt.Errorf("range %s: exact version together with bounds", r.Vuln)
	}
	for _, v := range []string{r.Exact, r.Start, r.End} {
		if v != "" && !ValidVersion(v) {
			return fmt.Errorf("range %s: version %q", r.Vuln, v)
		}
	}
	if r.Start == "" && r.StartIncl {
		return fmt.Errorf("range %s: start_incl without start", r.Vuln)
	}
	if r.End == "" && r.EndIncl {
		return fmt.Errorf("range %s: end_incl without end", r.Vuln)
	}
	return nil
}
