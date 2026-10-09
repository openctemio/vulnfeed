// Package nvd reads the NVD CVE API 2.0 and converts each CVE into bundle
// records: the vulnerability and its affected ranges per CPE product.
//
// Everything read is untrusted: bodies are capped and decoded one CVE at a
// time, strings are bounded and checked, and a statement that does not
// parse is dropped rather than widened.
package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/vulnfeed/internal/model"
)

// BaseURL is the NVD CVE API 2.0.
const BaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// API limits and caps.
const (
	PageSize           = 2000
	MaxWindow          = 120 * 24 * time.Hour
	maxPageBytes       = 256 << 20
	MaxRangesPerCVE    = 2000
	paceWithoutKey     = 6 * time.Second
	paceWithKey        = 700 * time.Millisecond
	rateLimitedBackoff = 30 * time.Second
	maxAttempts        = 5
)

var (
	cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	cwePattern   = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
	cvssVector   = regexp.MustCompile(`^[A-Za-z0-9:/.\-_()]{1,200}$`)
)

// ErrRateLimited is returned when the API keeps refusing requests.
var ErrRateLimited = errors.New("nvd: rate limited")

// Client reads pages of the API.
type Client struct {
	HTTP    *http.Client
	BaseURL string
	APIKey  string
	Pace    time.Duration
	Sleep   func(context.Context, time.Duration) error
	last    time.Time
}

// NewClient returns a client of the public API; apiKey may be empty.
func NewClient(apiKey string) *Client {
	pace := paceWithoutKey
	if apiKey != "" {
		pace = paceWithKey
	}
	return &Client{
		HTTP:    &http.Client{Timeout: 10 * time.Minute},
		BaseURL: BaseURL,
		APIKey:  apiKey,
		Pace:    pace,
		Sleep:   sleepCtx,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Query selects one page: the whole corpus or CVEs modified in a window of
// at most 120 days.
type Query struct {
	StartIndex  int
	ModifiedGTE time.Time
	ModifiedLT  time.Time
}

// Record is one converted CVE.
type Record struct {
	Vuln     model.Vuln
	Ranges   []model.Range
	Products map[string]model.Product
	Rejected bool
	// TooManyRanges: more statements than a bundle carries; the record is
	// kept with its previous ranges.
	TooManyRanges bool
}

// Page is one decoded page.
type Page struct {
	TotalResults int
	Count        int
	Records      []Record
}

// FetchPage reads one page, paced and retried on rate limiting.
func (c *Client) FetchPage(ctx context.Context, q Query) (*Page, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("nvd url: %w", err)
	}
	params := url.Values{}
	params.Set("resultsPerPage", strconv.Itoa(PageSize))
	params.Set("startIndex", strconv.Itoa(q.StartIndex))
	if !q.ModifiedGTE.IsZero() {
		if q.ModifiedLT.Sub(q.ModifiedGTE) > MaxWindow || !q.ModifiedLT.After(q.ModifiedGTE) {
			return nil, fmt.Errorf("nvd: invalid modified window %s - %s", q.ModifiedGTE, q.ModifiedLT)
		}
		params.Set("lastModStartDate", q.ModifiedGTE.UTC().Format("2006-01-02T15:04:05.000Z"))
		params.Set("lastModEndDate", q.ModifiedLT.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	u.RawQuery = params.Encode()
	for attempt := 1; ; attempt++ {
		if wait := c.Pace - time.Since(c.last); !c.last.IsZero() && wait > 0 {
			if err := c.Sleep(ctx, wait); err != nil {
				return nil, err
			}
		}
		c.last = time.Now()
		page, retry, err := c.get(ctx, u.String())
		if err == nil {
			return page, nil
		}
		if !retry || attempt >= maxAttempts {
			return nil, err
		}
		if err := c.Sleep(ctx, rateLimitedBackoff*time.Duration(attempt)); err != nil {
			return nil, err
		}
	}
}

func (c *Client) get(ctx context.Context, rawURL string) (*Page, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("nvd request: %w", err)
	}
	req.Header.Set("User-Agent", "openctemio-vulnfeed (https://github.com/openctemio/vulnfeed)")
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("nvd fetch: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, true, fmt.Errorf("%w (status %d)", ErrRateLimited, resp.StatusCode)
	default:
		return nil, false, fmt.Errorf("nvd: unexpected status %d", resp.StatusCode)
	}
	page, err := DecodePage(&capped{r: resp.Body, left: maxPageBytes})
	if err != nil {
		return nil, true, err
	}
	return page, false, nil
}

// capped fails instead of truncating once more than left bytes are read.
type capped struct {
	r    io.Reader
	left int64
}

func (c *capped) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errors.New("nvd: response over the size cap")
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// DecodePage decodes a response one vulnerability at a time.
func DecodePage(r io.Reader) (*Page, error) {
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	page := &Page{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("nvd: decode: %w", err)
		}
		key, ok := t.(string)
		if !ok {
			return nil, errors.New("nvd: expected an object key")
		}
		switch key {
		case "totalResults":
			if err := dec.Decode(&page.TotalResults); err != nil {
				return nil, fmt.Errorf("nvd: totalResults: %w", err)
			}
			if page.TotalResults < 0 || page.TotalResults > 10_000_000 {
				return nil, fmt.Errorf("nvd: implausible totalResults %d", page.TotalResults)
			}
		case "vulnerabilities":
			if err := expectDelim(dec, '['); err != nil {
				return nil, err
			}
			for dec.More() {
				var item struct {
					CVE nvdCVE `json:"cve"`
				}
				if err := dec.Decode(&item); err != nil {
					return nil, fmt.Errorf("nvd: vulnerability %d: %w", page.Count, err)
				}
				page.Count++
				if page.Count > PageSize {
					return nil, fmt.Errorf("nvd: more than %d vulnerabilities on a page", PageSize)
				}
				if rec, ok := Convert(item.CVE); ok {
					page.Records = append(page.Records, rec)
				}
			}
			if err := expectDelim(dec, ']'); err != nil {
				return nil, err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, fmt.Errorf("nvd: %s: %w", key, err)
			}
		}
	}
	return page, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return fmt.Errorf("nvd: decode: %w", err)
	}
	if d, ok := t.(json.Delim); !ok || d != want {
		return fmt.Errorf("nvd: expected %q", want)
	}
	return nil
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Operator string    `json:"operator"`
		Negate   bool      `json:"negate"`
		Nodes    []nvdNode `json:"nodes"`
	} `json:"configurations"`
}

type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

type nvdMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []nvdMatch `json:"cpeMatch"`
}

// Convert validates and converts one CVE object.
func Convert(n nvdCVE) (Record, bool) {
	id := strings.TrimSpace(n.ID)
	if !cveIDPattern.MatchString(id) {
		return Record{}, false
	}
	rec := Record{Products: map[string]model.Product{}}
	v := &rec.Vuln
	v.ID = id
	v.Status = clip(strings.TrimSpace(sanitize(n.VulnStatus)), 32)
	rec.Rejected = strings.EqualFold(v.Status, "Rejected")
	v.Published, v.Modified = parseTime(n.Published), parseTime(n.LastModified)
	for _, d := range n.Descriptions {
		if d.Lang == "en" {
			v.Description = clip(sanitize(d.Value), model.MaxDescriptionLen)
			break
		}
	}
	v.CVSS, v.Severity = pickCVSS(n)
	v.CWEs = []string{}
	seen := map[string]bool{}
	for _, w := range n.Weaknesses {
		for _, d := range w.Description {
			if c := strings.TrimSpace(d.Value); cwePattern.MatchString(c) && !seen[c] && len(v.CWEs) < model.MaxCWEs {
				seen[c] = true
				v.CWEs = append(v.CWEs, c)
			}
		}
	}
	if rec.Rejected {
		return rec, true
	}
	for _, cfg := range n.Configurations {
		if cfg.Negate {
			continue
		}
		rec.addConfig(id, cfg.Operator, cfg.Nodes)
		if len(rec.Ranges) > MaxRangesPerCVE {
			rec.Ranges, rec.TooManyRanges = nil, true
			rec.Products = map[string]model.Product{}
			break
		}
	}
	return rec, true
}

// addConfig reads one configuration: each vulnerable statement is a range;
// in an AND configuration the first non-vulnerable statement of the nodes
// is the platform the product must run on.
func (rec *Record) addConfig(id, operator string, nodes []nvdNode) {
	var condition *CPE
	if strings.EqualFold(operator, "AND") {
	find:
		for _, n := range nodes {
			if n.Negate {
				continue
			}
			for _, m := range n.CPEMatch {
				if !m.Vulnerable {
					if c, err := ParseCPE(m.Criteria); err == nil && model.ValidProductKey(c.Key()) {
						condition = &c
						break find
					}
				}
			}
		}
	}
	for _, n := range nodes {
		if n.Negate {
			continue
		}
		for _, m := range n.CPEMatch {
			if !m.Vulnerable {
				continue
			}
			r, c, ok := rangeOf(id, m)
			if !ok {
				continue
			}
			rec.Products[c.Key()] = productOf(c)
			if condition != nil && condition.Key() != c.Key() {
				r.Condition = condition.Key()
				rec.Products[condition.Key()] = productOf(*condition)
			}
			if r.Validate() != nil {
				continue
			}
			rec.Ranges = append(rec.Ranges, r)
		}
	}
}

func productOf(c CPE) model.Product {
	return model.Product{Key: c.Key(), Part: c.Part, Vendor: c.Vendor, Name: clip(strings.ReplaceAll(c.Product, "_", " "), model.MaxNameLen),
		CPEVendor: c.Vendor, CPEProduct: c.Product}
}

// rangeOf turns one vulnerable statement into a range: the criteria's
// version (plus update: 8.2 + p1 → 8.2p1) is an exact version, otherwise
// the bound fields give the range, with neither it covers every version.
func rangeOf(id string, m nvdMatch) (model.Range, CPE, bool) {
	c, err := ParseCPE(m.Criteria)
	if err != nil || c.Version == NA || strings.Contains(c.Product, ":") {
		return model.Range{}, CPE{}, false
	}
	r := model.Range{Vuln: id, Product: c.Key(), Scheme: "generic", Source: "nvd", Edition: qualifier(c.SWEdition), Target: qualifier(c.TargetSW)}
	bounded := m.VersionStartIncluding != "" || m.VersionStartExcluding != "" || m.VersionEndIncluding != "" || m.VersionEndExcluding != ""
	if c.Version != Any {
		if bounded {
			return model.Range{}, CPE{}, false
		}
		r.Exact = c.Version
		if u := qualifier(c.Update); u != "" {
			r.Exact += u
		}
		return r, c, model.ValidVersion(r.Exact)
	}
	switch {
	case m.VersionStartIncluding != "":
		r.Start, r.StartIncl = m.VersionStartIncluding, true
	case m.VersionStartExcluding != "":
		r.Start = m.VersionStartExcluding
	}
	switch {
	case m.VersionEndIncluding != "":
		r.End, r.EndIncl = m.VersionEndIncluding, true
	case m.VersionEndExcluding != "":
		r.End = m.VersionEndExcluding
	}
	for _, b := range []string{r.Start, r.End} {
		if b != "" && !model.ValidVersion(b) {
			return model.Range{}, CPE{}, false
		}
	}
	return r, c, true
}

func qualifier(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == Any || s == NA || len(s) > model.MaxQualifierLen {
		return ""
	}
	return s
}

func pickCVSS(n nvdCVE) (*model.CVSS, string) {
	for _, set := range [][]nvdMetric{n.Metrics.V40, n.Metrics.V31, n.Metrics.V30, n.Metrics.V2} {
		if len(set) == 0 {
			continue
		}
		m := set[0]
		for _, x := range set {
			if strings.EqualFold(x.Type, "Primary") {
				m = x
				break
			}
		}
		score := m.CVSSData.BaseScore
		if score < 0 || score > 10 {
			return nil, ""
		}
		sev := strings.ToLower(m.CVSSData.BaseSeverity)
		if sev == "" {
			sev = strings.ToLower(m.BaseSeverity)
		}
		switch sev {
		case "none", "low", "medium", "high", "critical":
		default:
			sev = severityFromScore(score)
		}
		vector := m.CVSSData.VectorString
		if !cvssVector.MatchString(vector) {
			vector = ""
		}
		return &model.CVSS{Version: clip(m.CVSSData.Version, 8), Score: score, Vector: vector}, sev
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

func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

func sanitize(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == '\r' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
