// Package intel reads the two public exploitation signals a platform
// weighs next to a CVE: the CISA Known Exploited Vulnerabilities catalog
// (KEV) and the FIRST Exploit Prediction Scoring System (EPSS).
//
// Both are read in full on every build, validated record by record
// (identifier shape, ranges, duplicates, size caps) and handed to the bundle
// writer, which signs them as a side manifest next to the corpus. A source
// that fails a check is not published: the caller carries the previous
// release's copy forward, so a platform sees an older data date (and falls
// back to its own fetch) instead of bad data.
package intel

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Stream names, as they appear in the signed manifest.
const (
	StreamKEV  = "kev"
	StreamEPSS = "epss"
)

// Caps (the platform enforces the same).
const (
	MaxKEVRecords  = 20_000
	MaxEPSSRecords = 1_500_000
	// MinKEVRecords and MinEPSSRecords are absolute floors: a feed below
	// them is a truncated or emptied response, never a real catalog.
	MinKEVRecords  = 500
	MinEPSSRecords = 100_000
	// ShrinkFloor: a snapshot under this share of the previous release's
	// record count is refused (truncation guard).
	ShrinkFloor = 0.90

	maxStringLen = 4096
)

// Attribution travels with each stream in the signed manifest.
var attribution = map[string]string{
	StreamKEV:  "CISA Known Exploited Vulnerabilities Catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
	StreamEPSS: "EPSS, Forum of Incident Response and Security Teams (https://www.first.org/epss), used with attribution",
}

// Attribution returns the attribution line of a stream.
func Attribution(stream string) string { return attribution[stream] }

var cveRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

// ValidCVE reports whether s is a CVE id.
func ValidCVE(s string) bool { return len(s) <= 32 && cveRe.MatchString(s) }

// KEVEntry is one KEV record (a line of the stream file).
type KEVEntry struct {
	CVE         string   `json:"cve"`
	Vendor      string   `json:"vendor"`
	Product     string   `json:"product"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	DateAdded   string   `json:"date_added"`
	DueDate     string   `json:"due_date,omitempty"`
	Ransomware  string   `json:"ransomware"`
	Notes       string   `json:"notes,omitempty"`
	CWEs        []string `json:"cwes"`
}

// KEV is a validated catalog: entries sorted by CVE id, the catalog's
// release time and version.
type KEV struct {
	AsOf    time.Time
	Version string
	Entries []KEVEntry
}

// EPSSEntry is one EPSS record. Percentile is the published fraction (0-1).
type EPSSEntry struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

// EPSS is a validated daily score file: entries sorted by CVE id, the score
// date and model version.
type EPSS struct {
	AsOf    time.Time
	Version string
	Entries []EPSSEntry
}

// ErrEmpty is returned for a feed with too few records.
var ErrEmpty = errors.New("intel: feed has too few records")

// CheckShrink refuses a snapshot far smaller than the previous release's.
func CheckShrink(stream string, n, prev int) error {
	if prev > 0 && float64(n) < ShrinkFloor*float64(prev) {
		return fmt.Errorf("intel: %s has %d records, under %.0f%% of the previous release's %d (refused as truncated)",
			stream, n, 100*ShrinkFloor, prev)
	}
	return nil
}
