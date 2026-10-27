package intel

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

type kevFile struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CVEID       string   `json:"cveID"`
		Vendor      string   `json:"vendorProject"`
		Product     string   `json:"product"`
		Name        string   `json:"vulnerabilityName"`
		Description string   `json:"shortDescription"`
		DateAdded   string   `json:"dateAdded"`
		DueDate     string   `json:"dueDate"`
		Ransomware  string   `json:"knownRansomwareCampaignUse"`
		Notes       string   `json:"notes"`
		CWEs        []string `json:"cwes"`
	} `json:"vulnerabilities"`
}

func parseTime(s string) (time.Time, error) {
	for _, l := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable time %q", s)
}

func clip(s string) string {
	if len(s) > maxStringLen {
		return s[:maxStringLen]
	}
	return s
}

// ParseKEV validates a CISA KEV catalog document. The catalog must carry a
// release time, enough entries, and no malformed or duplicate id; its own
// `count` must match when present.
func ParseKEV(r io.Reader) (*KEV, error) {
	var f kevFile
	if err := json.NewDecoder(io.LimitReader(r, 64<<20)).Decode(&f); err != nil {
		return nil, fmt.Errorf("intel: kev json: %w", err)
	}
	asOf, err := parseTime(f.DateReleased)
	if err != nil {
		return nil, fmt.Errorf("intel: kev dateReleased: %w", err)
	}
	if asOf.After(time.Now().Add(48 * time.Hour)) {
		return nil, errors.New("intel: kev dateReleased is in the future")
	}
	if len(f.Vulnerabilities) < MinKEVRecords {
		return nil, fmt.Errorf("%w (kev: %d)", ErrEmpty, len(f.Vulnerabilities))
	}
	if len(f.Vulnerabilities) > MaxKEVRecords {
		return nil, fmt.Errorf("intel: kev has %d records, over the cap", len(f.Vulnerabilities))
	}
	if f.Count != 0 && f.Count != len(f.Vulnerabilities) {
		return nil, fmt.Errorf("intel: kev count %d does not match %d entries", f.Count, len(f.Vulnerabilities))
	}
	seen := map[string]bool{}
	out := &KEV{AsOf: asOf, Version: clip(f.CatalogVersion)}
	for _, v := range f.Vulnerabilities {
		if !ValidCVE(v.CVEID) || seen[v.CVEID] {
			return nil, fmt.Errorf("intel: kev entry %q is malformed or duplicated", v.CVEID)
		}
		seen[v.CVEID] = true
		added, err := parseTime(v.DateAdded)
		if err != nil {
			return nil, fmt.Errorf("intel: kev %s dateAdded: %w", v.CVEID, err)
		}
		e := KEVEntry{CVE: v.CVEID, Vendor: clip(v.Vendor), Product: clip(v.Product), Name: clip(v.Name),
			Description: clip(v.Description), DateAdded: added.Format("2006-01-02"), Ransomware: clip(v.Ransomware),
			Notes: clip(v.Notes), CWEs: []string{}}
		if v.DueDate != "" {
			due, err := parseTime(v.DueDate)
			if err != nil {
				return nil, fmt.Errorf("intel: kev %s dueDate: %w", v.CVEID, err)
			}
			e.DueDate = due.Format("2006-01-02")
		}
		for _, c := range v.CWEs {
			if c != "" && len(c) <= 32 {
				e.CWEs = append(e.CWEs, c)
			}
		}
		out.Entries = append(out.Entries, e)
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].CVE < out.Entries[j].CVE })
	return out, nil
}

// ParseEPSS validates the (decompressed) FIRST scores CSV: a leading
// `#model_version:...,score_date:...` line, the `cve,epss,percentile` header,
// then one row per CVE. A malformed row, a score outside 0-1 or a duplicate
// id fails the file.
func ParseEPSS(r io.Reader) (*EPSS, error) {
	sc := bufio.NewScanner(io.LimitReader(r, 1<<30))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	if !sc.Scan() {
		return nil, errors.New("intel: epss: empty file")
	}
	first := strings.TrimSpace(sc.Text())
	if !strings.HasPrefix(first, "#") {
		return nil, errors.New("intel: epss: the metadata comment line is missing")
	}
	out := &EPSS{}
	for _, part := range strings.Split(strings.TrimPrefix(first, "#"), ",") {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "model_version":
			out.Version = clip(strings.TrimSpace(v))
		case "score_date":
			t, err := parseTime(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("intel: epss score_date: %w", err)
			}
			out.AsOf = t
		}
	}
	if out.AsOf.IsZero() {
		return nil, errors.New("intel: epss: no score_date")
	}
	if out.AsOf.After(time.Now().Add(48 * time.Hour)) {
		return nil, errors.New("intel: epss score_date is in the future")
	}
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != "cve,epss,percentile" {
		return nil, errors.New("intel: epss: unexpected header")
	}
	seen := map[string]struct{}{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Split(line, ",")
		if len(f) != 3 || !ValidCVE(f[0]) {
			return nil, fmt.Errorf("intel: epss: bad row %q", clip(line))
		}
		s, err1 := strconv.ParseFloat(f[1], 64)
		p, err2 := strconv.ParseFloat(f[2], 64)
		if err1 != nil || err2 != nil || math.IsNaN(s) || math.IsNaN(p) || s < 0 || s > 1 || p < 0 || p > 1 {
			return nil, fmt.Errorf("intel: epss: bad score in %q", clip(line))
		}
		if _, dup := seen[f[0]]; dup {
			return nil, fmt.Errorf("intel: epss: duplicate %s", f[0])
		}
		seen[f[0]] = struct{}{}
		if len(out.Entries) >= MaxEPSSRecords {
			return nil, errors.New("intel: epss: too many rows")
		}
		out.Entries = append(out.Entries, EPSSEntry{CVE: f[0], Score: s, Percentile: p})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("intel: epss: %w", err)
	}
	if len(out.Entries) < MinEPSSRecords {
		return nil, fmt.Errorf("%w (epss: %d)", ErrEmpty, len(out.Entries))
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].CVE < out.Entries[j].CVE })
	return out, nil
}
