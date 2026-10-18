// Package cve5 reads the CVE List (CVE JSON 5.x records of the CVE Program,
// github.com/CVEProject/cvelistV5) and converts each record's CNA container
// into bundle records: the vulnerability, its state (published or rejected)
// and the affected ranges the CNA states.
//
// Everything read is untrusted: a record is capped in size and decoded on
// its own, text is sanitised and clipped, and an affected statement that
// does not parse into a comparable range is dropped rather than widened.
package cve5

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/vulnfeed/internal/model"
	"github.com/openctemio/vulnfeed/internal/nvd"
)

// Caps on one record.
const (
	MaxRecordBytes     = 4 << 20
	MaxAffected        = 500
	MaxVersionsPerItem = 2000
	MaxCPEsPerItem     = 32
	MaxReferences      = 64
	MaxReferenceURL    = 2048
	MaxReferenceName   = 200
	MaxTags            = 16
	MaxTagLen          = 64
	MaxADP             = 16
	MaxRawField        = 256
	MaxChanges         = 64
)

// States of a CVE record, as carried in the bundle's status field.
const (
	StatusPublished = "Published"
	StatusRejected  = "Rejected"
)

var (
	cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	cwePattern   = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
	cvssVector   = regexp.MustCompile(`^[A-Za-z0-9:/.\-_()]{1,200}$`)
	// A commit hash given as a version: not comparable.
	hashLike = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
	// Placeholder vendor or product names that identify nothing.
	placeholders = map[string]bool{"n/a": true, "na": true, "n_a": true, "unknown": true, "unspecified": true,
		"various": true, "multiple": true, "none": true, "-": true, "*": true}
	// Version types the generic comparator orders correctly. Others (git,
	// rpm, maven, python, ...) have their own ordering and are skipped.
	versionTypes = map[string]bool{"": true, "custom": true, "semver": true}
)

// ErrNotARecord is returned for JSON that is not a CVE JSON 5.x record.
var ErrNotARecord = errors.New("cve5: not a CVE JSON 5.x record")

// Reference is one reference of the CNA container, validated. References
// are not part of the bundle's record format yet; they are kept here,
// already cleaned, for the format version that carries them.
type Reference struct {
	URL  string
	Name string
	Tags []string
}

// Affected is one affected item as its container states it, cleaned and
// capped but not interpreted: every field is kept, including statements
// that do not become ranges (packages, other version orderings, status
// changes, default status). It is the input for product identity work
// (aliases, package products) that the bundle format does not carry yet.
type Affected struct {
	Vendor        string
	Product       string
	PackageName   string
	CollectionURL string
	DefaultStatus string
	CPEs          []string
	Platforms     []string
	Versions      []Version
}

// Version is one version statement of an affected item.
type Version struct {
	Version         string
	Status          string
	VersionType     string
	LessThan        string
	LessThanOrEqual string
	Changes         []Change
}

// Change is a status change at a version inside a version statement.
type Change struct {
	At     string
	Status string
}

// ADP is one Authorized Data Publisher container (for example the CISA
// ADP enrichment): its score, CWEs, affected items (with their CPEs) and
// SSVC decision points. Kept apart from the CNA's data; not carried in the
// bundle format yet.
type ADP struct {
	ShortName string
	CVSS      *model.CVSS
	Severity  string
	CWEs      []string
	Affected  []Affected
	SSVC      *SSVC
}

// SSVC holds the SSVC decision points an ADP publishes.
type SSVC struct {
	Version         string
	Exploitation    string
	Automatable     string
	TechnicalImpact string
}

// Record is one converted CVE record.
type Record struct {
	Vuln       model.Vuln
	Ranges     []model.Range
	Products   map[string]model.Product
	References []Reference
	// Affected is the CNA's affected list in full; ADP the ADP containers.
	Affected []Affected
	ADP      []ADP
	Rejected bool
	// TooManyRanges: more statements than a bundle carries; the record is
	// kept with its previous ranges.
	TooManyRanges bool
}

type cveJSON struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	Metadata    struct {
		ID            string `json:"cveId"`
		State         string `json:"state"`
		DatePublished string `json:"datePublished"`
		DateUpdated   string `json:"dateUpdated"`
		DateRejected  string `json:"dateRejected"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cnaJSON   `json:"cna"`
		ADP []cnaJSON `json:"adp"`
	} `json:"containers"`
}

type langValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type cnaJSON struct {
	ProviderMetadata struct {
		ShortName string `json:"shortName"`
	} `json:"providerMetadata"`
	Descriptions    []langValue    `json:"descriptions"`
	RejectedReasons []langValue    `json:"rejectedReasons"`
	Affected        []affectedJSON `json:"affected"`
	ProblemTypes    []struct {
		Descriptions []struct {
			CWEID string `json:"cweId"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
	Metrics []struct {
		V40   *metricJSON `json:"cvssV4_0"`
		V31   *metricJSON `json:"cvssV3_1"`
		V30   *metricJSON `json:"cvssV3_0"`
		Other *struct {
			Type    string `json:"type"`
			Content struct {
				Version string              `json:"version"`
				Options []map[string]string `json:"options"`
			} `json:"content"`
		} `json:"other"`
	} `json:"metrics"`
	References []struct {
		URL  string   `json:"url"`
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	} `json:"references"`
}

type metricJSON struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type affectedJSON struct {
	Vendor        string        `json:"vendor"`
	Product       string        `json:"product"`
	PackageName   string        `json:"packageName"`
	CollectionURL string        `json:"collectionURL"`
	CPEs          []string      `json:"cpes"`
	Platforms     []string      `json:"platforms"`
	DefaultStatus string        `json:"defaultStatus"`
	Versions      []versionJSON `json:"versions"`
}

type versionJSON struct {
	Version         string `json:"version"`
	Status          string `json:"status"`
	VersionType     string `json:"versionType"`
	LessThan        string `json:"lessThan"`
	LessThanOrEqual string `json:"lessThanOrEqual"`
	Changes         []struct {
		At     string `json:"at"`
		Status string `json:"status"`
	} `json:"changes"`
}

// Decode reads one record of at most MaxRecordBytes from r and converts
// it. ok is false for a record in a state the bundle does not carry (a
// reserved id has no record to carry).
func Decode(r io.Reader) (rec Record, ok bool, err error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxRecordBytes+1))
	if err != nil {
		return Record{}, false, fmt.Errorf("cve5: read: %w", err)
	}
	if len(b) > MaxRecordBytes {
		return Record{}, false, fmt.Errorf("cve5: record over %d bytes", MaxRecordBytes)
	}
	var c cveJSON
	if err := json.Unmarshal(b, &c); err != nil {
		return Record{}, false, fmt.Errorf("cve5: decode: %w", err)
	}
	return Convert(c)
}

// Convert validates and converts one decoded record.
func Convert(c cveJSON) (Record, bool, error) {
	if c.DataType != "CVE_RECORD" || !strings.HasPrefix(c.DataVersion, "5.") {
		return Record{}, false, ErrNotARecord
	}
	id := strings.TrimSpace(c.Metadata.ID)
	if !cveIDPattern.MatchString(id) {
		return Record{}, false, fmt.Errorf("cve5: id %q", model.Clip(model.Sanitize(id), 40))
	}
	rec := Record{Products: map[string]model.Product{}}
	v := &rec.Vuln
	v.ID = id
	v.CWEs = []string{}
	cna := c.Containers.CNA
	switch strings.ToUpper(strings.TrimSpace(c.Metadata.State)) {
	case "PUBLISHED":
		v.Status = StatusPublished
		v.Description = english(cna.Descriptions)
	case "REJECTED":
		v.Status, rec.Rejected = StatusRejected, true
		v.Description = english(cna.RejectedReasons)
	default:
		return Record{}, false, nil
	}
	v.Published = parseTime(c.Metadata.DatePublished)
	v.Modified = parseTime(c.Metadata.DateUpdated)
	if v.Modified == nil && rec.Rejected {
		v.Modified = parseTime(c.Metadata.DateRejected)
	}
	if rec.Rejected {
		return rec, true, nil
	}
	v.CVSS, v.Severity = pickCVSS(cna)
	v.CWEs = cwes(cna)
	rec.References = references(cna)
	rec.Affected = affectedList(cna.Affected)
	for i, a := range c.Containers.ADP {
		if i >= MaxADP {
			break
		}
		adp := ADP{ShortName: model.CleanText(a.ProviderMetadata.ShortName, MaxRawField), CWEs: cwes(a),
			Affected: affectedList(a.Affected), SSVC: ssvc(a)}
		adp.CVSS, adp.Severity = pickCVSS(a)
		rec.ADP = append(rec.ADP, adp)
	}
	for i, a := range cna.Affected {
		if i >= MaxAffected {
			break
		}
		rec.addAffected(id, a)
		if len(rec.Ranges) > nvd.MaxRangesPerCVE {
			rec.Ranges, rec.TooManyRanges = nil, true
			rec.Products = map[string]model.Product{}
			break
		}
	}
	return rec, true, nil
}

func cwes(c cnaJSON) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, p := range c.ProblemTypes {
		for _, d := range p.Descriptions {
			if w := strings.TrimSpace(d.CWEID); cwePattern.MatchString(w) && !seen[w] && len(out) < model.MaxCWEs {
				seen[w] = true
				out = append(out, w)
			}
		}
	}
	return out
}

func rawField(s string) string { return model.CleanText(s, MaxRawField) }

// affectedList keeps an affected list as stated, cleaned and capped.
func affectedList(in []affectedJSON) []Affected {
	var out []Affected
	for i, a := range in {
		if i >= MaxAffected {
			break
		}
		x := Affected{Vendor: rawField(a.Vendor), Product: rawField(a.Product), PackageName: rawField(a.PackageName),
			DefaultStatus: rawField(a.DefaultStatus)}
		if u, err := url.Parse(strings.TrimSpace(a.CollectionURL)); err == nil && (u.Scheme == "https" || u.Scheme == "http") &&
			u.Host != "" && u.User == nil && len(a.CollectionURL) <= MaxReferenceURL {
			x.CollectionURL = u.String()
		}
		for j, c := range a.CPEs {
			if j >= MaxCPEsPerItem {
				break
			}
			if c = strings.TrimSpace(c); c != "" && len(c) <= nvd.MaxCPELen && model.Sanitize(c) == c {
				x.CPEs = append(x.CPEs, c)
			}
		}
		for j, p := range a.Platforms {
			if j >= MaxTags {
				break
			}
			if p = rawField(p); p != "" {
				x.Platforms = append(x.Platforms, p)
			}
		}
		for j, v := range a.Versions {
			if j >= MaxVersionsPerItem {
				break
			}
			y := Version{Version: rawField(v.Version), Status: rawField(v.Status), VersionType: rawField(v.VersionType),
				LessThan: rawField(v.LessThan), LessThanOrEqual: rawField(v.LessThanOrEqual)}
			for k, ch := range v.Changes {
				if k >= MaxChanges {
					break
				}
				y.Changes = append(y.Changes, Change{At: rawField(ch.At), Status: rawField(ch.Status)})
			}
			x.Versions = append(x.Versions, y)
		}
		out = append(out, x)
	}
	return out
}

// ssvc reads the SSVC decision points of a container's metrics.
func ssvc(c cnaJSON) *SSVC {
	for _, m := range c.Metrics {
		if m.Other == nil || !strings.EqualFold(m.Other.Type, "ssvc") {
			continue
		}
		s := &SSVC{Version: rawField(m.Other.Content.Version)}
		for _, opt := range m.Other.Content.Options {
			for k, val := range opt {
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "exploitation":
					s.Exploitation = rawField(val)
				case "automatable":
					s.Automatable = rawField(val)
				case "technical impact":
					s.TechnicalImpact = rawField(val)
				}
			}
		}
		return s
	}
	return nil
}

func english(vals []langValue) string {
	for _, d := range vals {
		if l := strings.ToLower(strings.TrimSpace(d.Lang)); l == "en" || strings.HasPrefix(l, "en-") || strings.HasPrefix(l, "en_") {
			return model.CleanText(d.Value, model.MaxDescriptionLen)
		}
	}
	return ""
}

// target is one product identity an affected item names.
type target struct {
	product model.Product
	cpe     *nvd.CPE
}

// addAffected turns one affected item into ranges. The product identity
// is each CPE the item lists or, without one, its vendor and product
// names in the CPE naming convention. A package (packageName) is not a
// CPE product and is skipped.
func (rec *Record) addAffected(id string, a affectedJSON) {
	var targets []target
	for i, s := range a.CPEs {
		if i >= MaxCPEsPerItem {
			break
		}
		c, err := nvd.ParseCPE(s)
		if err != nil || strings.Contains(c.Product, ":") || !model.ValidProductKey(c.Key()) {
			continue
		}
		cc := c
		targets = append(targets, target{product: nvd.ProductOf(c), cpe: &cc})
	}
	if len(targets) == 0 {
		if strings.TrimSpace(a.PackageName) != "" {
			return
		}
		p, ok := nameProduct(a.Vendor, a.Product)
		if !ok {
			return
		}
		targets = append(targets, target{product: p})
	}
	for _, t := range targets {
		var ranges []model.Range
		base := model.Range{Vuln: id, Product: t.product.Key, Scheme: "generic", Source: "cve5"}
		if t.cpe != nil {
			base.Edition, base.Target = nvd.Qualifier(t.cpe.SWEdition), nvd.Qualifier(t.cpe.TargetSW)
		}
		for i, ver := range a.Versions {
			if i >= MaxVersionsPerItem {
				break
			}
			if r, ok := versionRange(base, ver); ok {
				ranges = append(ranges, r)
			}
		}
		// A CPE with a concrete version and no version list names one
		// version.
		if len(a.Versions) == 0 && t.cpe != nil && t.cpe.Version != nvd.Any && t.cpe.Version != nvd.NA {
			r := base
			r.Exact = t.cpe.Version
			if u := nvd.Qualifier(t.cpe.Update); u != "" {
				r.Exact += u
			}
			if comparable(r.Exact) && r.Validate() == nil {
				ranges = append(ranges, r)
			}
		}
		if len(ranges) == 0 {
			continue
		}
		rec.Products[t.product.Key] = t.product
		rec.Ranges = append(rec.Ranges, ranges...)
	}
}

// versionRange converts one version statement. Only "affected" statements
// become ranges; a statement with status changes, an ordering the generic
// comparator does not know or a version that is not comparable is
// dropped (never widened to "all versions").
func versionRange(base model.Range, v versionJSON) (model.Range, bool) {
	if !strings.EqualFold(strings.TrimSpace(v.Status), "affected") || len(v.Changes) > 0 ||
		!versionTypes[strings.ToLower(strings.TrimSpace(v.VersionType))] {
		return model.Range{}, false
	}
	r := base
	ver := strings.TrimSpace(v.Version)
	lt, le := strings.TrimSpace(v.LessThan), strings.TrimSpace(v.LessThanOrEqual)
	switch {
	case lt != "" || le != "":
		if lt != "" && le != "" {
			return model.Range{}, false
		}
		r.End, r.EndIncl = lt, false
		if le != "" {
			r.End, r.EndIncl = le, true
		}
		if r.End == "*" {
			r.End, r.EndIncl = "", false
		}
		if ver != "" && ver != "0" && ver != "*" {
			r.Start, r.StartIncl = ver, true
		}
	case ver == "" || ver == "0" || ver == "*":
		return model.Range{}, false
	default:
		r.Exact = ver
	}
	for _, b := range []string{r.Exact, r.Start, r.End} {
		if b != "" && !comparable(b) {
			return model.Range{}, false
		}
	}
	return r, r.Validate() == nil
}

func comparable(v string) bool {
	return model.ValidVersion(v) && !hashLike.MatchString(strings.ToLower(v))
}

// nameProduct builds a product from a CNA's vendor and product names in
// the CPE naming convention: lower case, spaces as underscores, only
// letters, digits and . _ - kept.
func nameProduct(vendor, product string) (model.Product, bool) {
	vk, pk := nameKey(vendor), nameKey(product)
	if vk == "" || pk == "" {
		return model.Product{}, false
	}
	p := model.Product{Key: model.ProductKey("a", vk, pk), Part: "a", Vendor: model.CleanText(vendor, model.MaxFieldLen),
		Name: model.CleanText(product, model.MaxNameLen), CPEVendor: vk, CPEProduct: pk}
	if p.Validate() != nil {
		return model.Product{}, false
	}
	return p, true
}

func nameKey(s string) string {
	s = strings.ToLower(model.CleanText(s, 4*model.MaxFieldLen))
	if placeholders[s] {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		case r == '_' || r == ' ' || r == '/':
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

func pickCVSS(cna cnaJSON) (*model.CVSS, string) {
	pick := func(get func(i int) *metricJSON) *metricJSON {
		for i := range cna.Metrics {
			if m := get(i); m != nil {
				return m
			}
		}
		return nil
	}
	for _, get := range []func(int) *metricJSON{
		func(i int) *metricJSON { return cna.Metrics[i].V40 },
		func(i int) *metricJSON { return cna.Metrics[i].V31 },
		func(i int) *metricJSON { return cna.Metrics[i].V30 },
	} {
		m := pick(get)
		if m == nil {
			continue
		}
		if m.BaseScore < 0 || m.BaseScore > 10 {
			return nil, ""
		}
		sev := strings.ToLower(strings.TrimSpace(m.BaseSeverity))
		switch sev {
		case "none", "low", "medium", "high", "critical":
		default:
			sev = severityFromScore(m.BaseScore)
		}
		vector := strings.TrimSpace(m.VectorString)
		if !cvssVector.MatchString(vector) {
			vector = ""
		}
		return &model.CVSS{Version: model.Clip(model.Sanitize(strings.TrimSpace(m.Version)), 8), Score: m.BaseScore, Vector: vector}, sev
	}
	return nil, ""
}

func severityFromScore(s float64) string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 4:
		return "medium"
	case s > 0:
		return "low"
	}
	return "none"
}

func references(cna cnaJSON) []Reference {
	var out []Reference
	for _, r := range cna.References {
		if len(out) >= MaxReferences {
			break
		}
		raw := strings.TrimSpace(r.URL)
		if raw == "" || len(raw) > MaxReferenceURL || model.Sanitize(raw) != raw || strings.ContainsAny(raw, " <>\"`") {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			continue
		}
		ref := Reference{URL: u.String(), Name: model.CleanText(r.Name, MaxReferenceName)}
		for _, t := range r.Tags {
			if len(ref.Tags) >= MaxTags {
				break
			}
			if t = model.CleanText(t, MaxTagLen); t != "" {
				ref.Tags = append(ref.Tags, t)
			}
		}
		out = append(out, ref)
	}
	return out
}

func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}
