package intel

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func kevDoc(n int, released string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"title":"x","catalogVersion":"2026.10.24","dateReleased":%q,"count":%d,"vulnerabilities":[`, released, n)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"cveID":"CVE-2021-%05d","vendorProject":"V","product":"P","vulnerabilityName":"N","shortDescription":"D","dateAdded":"2022-03-03","dueDate":"2022-03-24","knownRansomwareCampaignUse":"Unknown","notes":"","cwes":["CWE-79"]}`, 10000+i)
	}
	b.WriteString("]}")
	return b.String()
}

func epssDoc(n int, date string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#model_version:v2025.03.14,score_date:%s\ncve,epss,percentile\n", date)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "CVE-2020-%05d,0.%05d,0.5\n", i, i%100000)
	}
	return b.String()
}

func TestParseKEV(t *testing.T) {
	k, err := ParseKEV(strings.NewReader(kevDoc(600, "2026-10-24T14:30:01.9444Z")))
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Entries) != 600 || k.Version != "2026.10.24" || k.AsOf.Format(time.RFC3339) != "2026-10-24T14:30:01Z" {
		t.Fatalf("%d %q %v", len(k.Entries), k.Version, k.AsOf)
	}
	if k.Entries[0].DateAdded != "2022-03-03" || k.Entries[0].CWEs[0] != "CWE-79" {
		t.Fatalf("%+v", k.Entries[0])
	}
}

func TestParseKEVRefusals(t *testing.T) {
	good := kevDoc(600, "2026-10-24T14:30:01Z")
	cases := map[string]string{
		"too few":     kevDoc(3, "2026-10-24T14:30:01Z"),
		"empty":       `{"dateReleased":"2026-10-24T14:30:01Z","vulnerabilities":[]}`,
		"no key":      `{"dateReleased":"2026-10-24T14:30:01Z"}`,
		"no date":     strings.Replace(good, `"dateReleased":"2026-10-24T14:30:01Z"`, `"dateReleased":""`, 1),
		"future":      kevDoc(600, time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339)),
		"bad id":      strings.Replace(good, "CVE-2021-10001", "CVE-21-1", 1),
		"duplicate":   strings.Replace(good, "CVE-2021-10001", "CVE-2021-10000", 1),
		"count wrong": strings.Replace(good, `"count":600`, `"count":601`, 1),
		"not json":    "<html>blocked</html>",
	}
	for name, doc := range cases {
		if _, err := ParseKEV(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestParseEPSS(t *testing.T) {
	e, err := ParseEPSS(strings.NewReader(epssDoc(100_000, "2026-10-26T12:55:00Z")))
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Entries) != 100_000 || e.Version != "v2025.03.14" || e.AsOf.Format("2006-01-02") != "2026-10-26" {
		t.Fatalf("%d %q %v", len(e.Entries), e.Version, e.AsOf)
	}
	if _, err := ParseEPSS(strings.NewReader(epssDoc(100_000, "2026-10-26"))); err != nil {
		t.Fatalf("date-only score_date: %v", err)
	}
}

func TestParseEPSSRefusals(t *testing.T) {
	good := epssDoc(100_000, "2026-10-26")
	cases := map[string]string{
		"too few":     epssDoc(50, "2026-10-26"),
		"no comment":  strings.TrimPrefix(good, good[:strings.Index(good, "\n")+1]),
		"no date":     strings.Replace(good, "score_date:2026-10-26", "x:1", 1),
		"bad header":  strings.Replace(good, "cve,epss,percentile", "cve,score", 1),
		"score high":  good + "CVE-2030-00001,1.5,0.5\n",
		"score nan":   good + "CVE-2030-00001,NaN,0.5\n",
		"bad id":      good + "XYZ,0.1,0.5\n",
		"short row":   good + "CVE-2030-00001,0.1\n",
		"duplicate":   good + "CVE-2020-00001,0.1,0.5\n",
		"future date": epssDoc(100_000, time.Now().Add(30*24*time.Hour).Format("2006-01-02")),
	}
	for name, doc := range cases {
		if _, err := ParseEPSS(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestCheckShrink(t *testing.T) {
	if err := CheckShrink("kev", 89, 100); err == nil {
		t.Error("89 of 100 must be refused")
	}
	if err := CheckShrink("kev", 90, 100); err != nil {
		t.Error(err)
	}
	if err := CheckShrink("kev", 1, 0); err != nil {
		t.Error("no baseline: nothing to compare")
	}
}

func testClient(t *testing.T, h http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	c := &Client{Sleep: func(context.Context, time.Duration) error { return nil }}
	c.HTTP = srv.Client()
	c.HTTP.CheckRedirect = c.checkRedirect
	c.extraHost = strings.TrimPrefix(srv.URL, "https://")
	return c, srv
}

func TestFetchKEVFallsBackToTheMirror(t *testing.T) {
	var hits []string
	c, srv := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if r.URL.Path == "/waf" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(kevDoc(600, "2026-10-24T14:30:01Z")))
	}))
	c.KEVURLs = []string{srv.URL + "/waf", srv.URL + "/mirror"}
	k, err := c.FetchKEV(context.Background())
	if err != nil || len(k.Entries) != 600 {
		t.Fatal(k, err)
	}
	if len(hits) != 2 || hits[0] != "/waf" || hits[1] != "/mirror" {
		t.Fatalf("hits %v (a 403 is not retried, the mirror is tried next)", hits)
	}
}

func TestFetchKEVBadDocumentFromEverySourceFails(t *testing.T) {
	c, srv := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"dateReleased":"2026-10-24T14:30:01Z","vulnerabilities":[]}`))
	}))
	c.KEVURLs = []string{srv.URL + "/a", srv.URL + "/b"}
	if _, err := c.FetchKEV(context.Background()); !errors.Is(err, ErrEmpty) {
		t.Fatalf("want ErrEmpty, got %v", err)
	}
}

func TestFetchEPSSAndRetry(t *testing.T) {
	n := 0
	c, srv := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(epssDoc(100_000, "2026-10-26T12:55:00Z")))
		_ = gz.Close()
	}))
	c.EPSSURL = srv.URL + "/e.csv.gz"
	e, err := c.FetchEPSS(context.Background())
	if err != nil || len(e.Entries) != 100_000 || n != 2 {
		t.Fatal(e, err, n)
	}
}

func TestFetchRefusesForeignHostsAndRedirects(t *testing.T) {
	c, srv := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/x", http.StatusFound)
	}))
	c.KEVURLs = []string{srv.URL + "/k", "https://evil.example/k"}
	if _, err := c.FetchKEV(context.Background()); err == nil {
		t.Fatal("a redirect off the allowed hosts must fail")
	}
	c.EPSSURL = "https://evil.example/e.csv.gz"
	if _, err := c.FetchEPSS(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("a foreign host must be refused, got %v", err)
	}
}
