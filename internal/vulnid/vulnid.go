// Package vulnid builds the vulnerability id alias map: GHSA and OSV
// ecosystem advisory ids → the one CVE each aliases, read from the GitHub
// Advisory Database. A platform uses it to key a report that only knows a
// GHSA- or OSV id on the CVE, so two tools reporting the same flaw agree on
// one canonical id.
//
// An advisory names exactly one CVE or it is not published: one whose
// aliases name two or more different CVEs (over-broad) would fuse unrelated
// CVEs and is omitted, as is one with no CVE alias, a withdrawn one, a
// malicious-package one (MAL-) and any id outside the advisory databases
// below (distro advisories never become ids). Only the `aliases` field
// counts, never `related` or `upstream`.
package vulnid

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Caps (the platform enforces the same).
const (
	MaxEntries   = 2_000_000
	MaxFileBytes = 32 << 20 // compressed entries file
	MaxIDLen     = 64
)

// Sources of an entry.
const (
	SourceGHSA = "ghsa"
	SourceOSV  = "osv"
)

// Entry is one line of the entries file.
type Entry struct {
	ID     string `json:"id"`
	CVE    string `json:"cve"`
	Source string `json:"source"`
}

// Stats counts what a build read.
type Stats struct {
	Advisories int `json:"advisories"` // advisories with an id the map may hold, withdrawn ones excluded
	Published  int `json:"published"`  // entries
	OverBroad  int `json:"over_broad"` // omitted: aliases name two or more CVEs (or files disagree)
	NoCVE      int `json:"no_cve"`     // omitted: no CVE alias
}

var (
	ghsaPattern = regexp.MustCompile(`^GHSA-[23456789cfghjmpqrvwx]{4}(-[23456789cfghjmpqrvwx]{4}){2}$`)
	osvPattern  = regexp.MustCompile(`^(PYSEC|GO|RUSTSEC|GSD|OSV)-[A-Za-z0-9._-]{1,50}$`)
	cvePattern  = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
)

// ValidID reports whether id may be an entry id.
func ValidID(id string) bool { return classify(id) != "" }

// ValidCVE reports whether s is a CVE id in canonical (upper-case) form.
func ValidCVE(s string) bool { return cvePattern.MatchString(s) }

// classify returns the source of an id, or "" when it may not be an entry.
func classify(id string) string {
	if len(id) > MaxIDLen {
		return ""
	}
	switch {
	case ghsaPattern.MatchString(id):
		return SourceGHSA
	case osvPattern.MatchString(id):
		return SourceOSV
	}
	return ""
}

// normalizeID upper-cases the GHSA prefix and lower-cases its body.
func normalizeID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) > 5 && strings.EqualFold(id[:5], "GHSA-") {
		return "GHSA-" + strings.ToLower(id[5:])
	}
	return id
}

type advisory struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Withdrawn string   `json:"withdrawn"`
}

type state struct {
	cve  string
	kind int
}

const (
	stNoCVE = iota
	stOK
	stOverBroad
)

// Builder collects advisories into the map.
type Builder struct{ ids map[string]state }

// NewBuilder returns an empty builder.
func NewBuilder() *Builder { return &Builder{ids: map[string]state{}} }

// Add reads one OSV JSON advisory. A document that is not JSON is an error;
// one that may not be an entry is skipped. Copies of one id (the same
// advisory in two files) must agree on the CVE, else the id is omitted as
// over-broad.
func (b *Builder) Add(doc []byte) error {
	var a advisory
	if err := json.Unmarshal(doc, &a); err != nil {
		return fmt.Errorf("vulnid: %w", err)
	}
	id := normalizeID(a.ID)
	if classify(id) == "" || strings.TrimSpace(a.Withdrawn) != "" {
		return nil
	}
	cves := map[string]bool{}
	for _, al := range a.Aliases {
		if c := strings.ToUpper(strings.TrimSpace(al)); cvePattern.MatchString(c) {
			cves[c] = true
		}
	}
	cur := state{}
	switch len(cves) {
	case 0:
	case 1:
		for c := range cves {
			cur = state{cve: c, kind: stOK}
		}
	default:
		cur = state{kind: stOverBroad}
	}
	old, seen := b.ids[id]
	switch {
	case !seen:
		b.ids[id] = cur
	case old.kind == stOverBroad || cur.kind == stNoCVE:
		// stays as it was
	case old.kind == stNoCVE:
		b.ids[id] = cur
	case cur.kind == stOverBroad || old.cve != cur.cve:
		b.ids[id] = state{kind: stOverBroad}
	}
	return nil
}

// Result returns the entries sorted by id and the stats.
func (b *Builder) Result() ([]Entry, Stats, error) {
	var st Stats
	out := make([]Entry, 0, len(b.ids))
	for id, s := range b.ids {
		st.Advisories++
		switch s.kind {
		case stOK:
			out = append(out, Entry{ID: id, CVE: s.cve, Source: classify(id)})
		case stOverBroad:
			st.OverBroad++
		default:
			st.NoCVE++
		}
	}
	if len(out) > MaxEntries {
		return nil, Stats{}, errors.New("vulnid: over the entry cap")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	st.Published = len(out)
	return out, st, nil
}
