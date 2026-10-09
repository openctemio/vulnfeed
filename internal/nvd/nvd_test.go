package nvd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func loadPage(t *testing.T) *Page {
	t.Helper()
	f, err := os.Open("testdata/nvd_page.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := DecodePage(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDecodePage(t *testing.T) {
	p := loadPage(t)
	if p.TotalResults != 7 || p.Count != 5 || len(p.Records) != 4 {
		t.Fatalf("total=%d count=%d records=%d", p.TotalResults, p.Count, len(p.Records))
	}
	byID := map[string]Record{}
	for _, r := range p.Records {
		byID[r.Vuln.ID] = r
	}
	n := byID["CVE-2021-23017"]
	if n.Vuln.CVSS == nil || n.Vuln.CVSS.Score != 7.7 || n.Vuln.Severity != "high" || len(n.Vuln.CWEs) != 1 {
		t.Errorf("record %+v", n.Vuln)
	}
	if strings.ContainsAny(n.Vuln.Description, "\n\a") {
		t.Errorf("description %q", n.Vuln.Description)
	}
	// Wildcard criteria and an unparseable bound dropped; the negated
	// configuration skipped; the AND configuration carries its platform.
	if len(n.Ranges) != 3 {
		t.Fatalf("ranges %+v", n.Ranges)
	}
	if r := n.Ranges[0]; r.Product != "cpe:a:f5:nginx" || r.Start != "0.6.18" || !r.StartIncl || r.End != "1.20.1" || r.EndIncl {
		t.Errorf("range 0 %+v", r)
	}
	if r := n.Ranges[1]; r.Exact != "1.21.0" {
		t.Errorf("range 1 %+v", r)
	}
	if r := n.Ranges[2]; r.Product != "cpe:a:f5:nginx_plus" || r.End != "r24" || !r.EndIncl || r.Condition != "cpe:o:canonical:ubuntu_linux" {
		t.Errorf("range 2 %+v", r)
	}
	if _, ok := n.Products["cpe:o:canonical:ubuntu_linux"]; !ok || len(n.Products) != 3 {
		t.Errorf("products %+v", n.Products)
	}
	for _, r := range n.Ranges {
		if err := r.Validate(); err != nil {
			t.Errorf("invalid range kept: %v", err)
		}
	}
	g := byID["CVE-2023-0001"]
	if len(g.Ranges) != 3 || g.Ranges[0].Edition != "community" || g.Ranges[2].Edition != "enterprise" || g.Vuln.Severity != "critical" {
		t.Errorf("gitlab %+v", g)
	}
	if !byID["CVE-2020-9999"].Rejected || len(byID["CVE-2020-9999"].Ranges) != 0 {
		t.Error("rejected")
	}
	if len(byID["CVE-2026-12345"].Ranges) != 0 {
		t.Error("deferred")
	}
}

func TestDecodePage_Refuses(t *testing.T) {
	for name, body := range map[string]string{
		"not json":        `<html>`,
		"array":           `[]`,
		"bad item":        `{"vulnerabilities":[{"cve": 5}]}`,
		"negative total":  `{"totalResults": -1}`,
		"huge total":      `{"totalResults": 99999999}`,
		"truncated":       `{"vulnerabilities":[{"cve":{"id":"CVE-2021-1`,
		"vulns not array": `{"vulnerabilities": {}}`,
	} {
		if _, err := DecodePage(strings.NewReader(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var b strings.Builder
	b.WriteString(`{"vulnerabilities":[`)
	for i := 0; i <= PageSize; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"cve":{"id":"CVE-2020-%05d"}}`, i)
	}
	b.WriteString(`]}`)
	if _, err := DecodePage(strings.NewReader(b.String())); err == nil {
		t.Error("more than a page accepted")
	}
}

func TestTooManyRanges(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"vulnerabilities":[{"cve":{"id":"CVE-2022-0001","configurations":[{"nodes":[{"operator":"OR","cpeMatch":[`)
	for i := 0; i <= MaxRangesPerCVE; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"vulnerable":true,"criteria":"cpe:2.3:a:v:p%d:1.0:*:*:*:*:*:*:*"}`, i)
	}
	b.WriteString(`]}]}]}}]}`)
	p, err := DecodePage(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Records) != 1 || !p.Records[0].TooManyRanges || len(p.Records[0].Ranges) != 0 {
		t.Fatalf("%+v", p.Records)
	}
}

func TestRangeOf(t *testing.T) {
	cases := []struct {
		m    nvdMatch
		ok   bool
		want string
	}{
		{nvdMatch{Criteria: "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*"}, true, "exact=8.2p1"},
		{nvdMatch{Criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", VersionStartExcluding: "1.0", VersionEndIncluding: "1.5"}, true, "1.0<..<=1.5"},
		{nvdMatch{Criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}, true, "all"},
		{nvdMatch{Criteria: "cpe:2.3:o:v:fw:-:*:*:*:*:*:*:*"}, false, ""},
		{nvdMatch{Criteria: "cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*", VersionEndExcluding: "2"}, false, ""},
		{nvdMatch{Criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", VersionEndExcluding: "n/a"}, false, ""},
		{nvdMatch{Criteria: `cpe:2.3:a:v:prod\:uct:*:*:*:*:*:*:*:*`}, false, ""},
	}
	for i, c := range cases {
		r, _, ok := rangeOf("CVE-2020-0001", c.m)
		if ok != c.ok {
			t.Errorf("case %d: ok=%v", i, ok)
			continue
		}
		if !ok {
			continue
		}
		var got string
		switch {
		case r.Exact != "":
			got = "exact=" + r.Exact
		case r.Start == "" && r.End == "":
			got = "all"
		default:
			got = r.Start + "<..<=" + r.End
			if !r.EndIncl || r.StartIncl {
				got += "?"
			}
		}
		if got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}

func TestClient(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		q := r.URL.Query()
		if q.Get("resultsPerPage") != "2000" || q.Get("startIndex") != "4000" || q.Get("lastModStartDate") != "2026-01-01T00:00:00.000Z" || r.Header.Get("apiKey") != "k" {
			t.Errorf("request %s %v", r.URL.RawQuery, r.Header)
		}
		_, _ = w.Write([]byte(`{"totalResults": 1, "vulnerabilities": []}`))
	}))
	defer srv.Close()
	c := NewClient("k")
	c.HTTP, c.BaseURL = srv.Client(), srv.URL
	var slept []time.Duration
	c.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p, err := c.FetchPage(context.Background(), Query{StartIndex: 4000, ModifiedGTE: from, ModifiedLT: from.AddDate(0, 1, 0)})
	if err != nil || p.TotalResults != 1 || calls.Load() != 2 || len(slept) == 0 {
		t.Fatalf("%v %+v %d %v", err, p, calls.Load(), slept)
	}
	if _, err := c.FetchPage(context.Background(), Query{ModifiedGTE: from, ModifiedLT: from.Add(MaxWindow + time.Hour)}); err == nil {
		t.Fatal("window over 120 days accepted")
	}
	nf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer nf.Close()
	c.BaseURL, c.HTTP = nf.URL, nf.Client()
	slept = nil
	if _, err := c.FetchPage(context.Background(), Query{}); err == nil || len(slept) > 1 {
		t.Fatalf("404 retried or accepted: %v %v", err, slept)
	}
}

func FuzzDecodePage(f *testing.F) {
	raw, _ := os.ReadFile("testdata/nvd_page.json")
	f.Add(string(raw))
	f.Add(`{"vulnerabilities":[{"cve":{"id":"CVE-2021-0001","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:a:b:*"}]}]}]}}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		p, err := DecodePage(strings.NewReader(s))
		if err != nil {
			return
		}
		for _, r := range p.Records {
			if err := r.Vuln.Validate(); err != nil {
				t.Fatalf("invalid record kept: %v", err)
			}
			for _, rg := range r.Ranges {
				if err := rg.Validate(); err != nil {
					t.Fatalf("invalid range kept: %v", err)
				}
			}
		}
	})
}
