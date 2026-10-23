package vulnid

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func read(t *testing.T, names ...string) *Builder {
	t.Helper()
	b := NewBuilder()
	for _, n := range names {
		doc, err := os.ReadFile(filepath.Join("testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Add(doc); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func TestBuilder(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  []Entry
		stats Stats
	}{
		{"body lower-cased, related ignored", []string{"ok.json"},
			[]Entry{{"GHSA-8gq3-9chp-cf2j", "CVE-2024-1234", "ghsa"}}, Stats{Advisories: 1, Published: 1}},
		{"over-broad omitted", []string{"overbroad.json"}, []Entry{}, Stats{Advisories: 1, OverBroad: 1}},
		{"no CVE alias omitted (related does not count)", []string{"nocve.json"}, []Entry{}, Stats{Advisories: 1, NoCVE: 1}},
		{"withdrawn omitted", []string{"withdrawn.json"}, []Entry{}, Stats{}},
		{"malicious-package ids skipped", []string{"mal.json"}, []Entry{}, Stats{}},
		{"distro ids never emitted", []string{"distro.json", "debian.json"}, []Entry{}, Stats{}},
		{"osv ecosystem id", []string{"pysec.json"},
			[]Entry{{"PYSEC-2024-12", "CVE-2024-0008", "osv"}}, Stats{Advisories: 1, Published: 1}},
		{"same id twice agreeing is one entry", []string{"dupe_a.json", "dupe_b.json"},
			[]Entry{{"GHSA-jjjj-mmmm-pqrv", "CVE-2024-0010", "ghsa"}}, Stats{Advisories: 1, Published: 1}},
		{"same id twice disagreeing is omitted, in either order", []string{"dupe_conflict_a.json", "dupe_conflict_b.json", "dupe_conflict_a.json"},
			[]Entry{}, Stats{Advisories: 1, OverBroad: 1}},
		{"id outside the GHSA alphabet is not an id", []string{"badid.json"}, []Entry{}, Stats{}},
		{"malformed CVE aliases are not CVEs", []string{"badcve.json"}, []Entry{}, Stats{Advisories: 1, NoCVE: 1}},
		{"sorted by id", []string{"pysec.json", "ok.json", "dupe_a.json"},
			[]Entry{{"GHSA-8gq3-9chp-cf2j", "CVE-2024-1234", "ghsa"}, {"GHSA-jjjj-mmmm-pqrv", "CVE-2024-0010", "ghsa"}, {"PYSEC-2024-12", "CVE-2024-0008", "osv"}},
			Stats{Advisories: 3, Published: 3}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, st, err := read(t, tc.files...).Result()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) || st != tc.stats {
				t.Fatalf("got %+v %+v, want %+v %+v", got, st, tc.want, tc.stats)
			}
		})
	}
}

func TestAddNotJSON(t *testing.T) {
	if err := NewBuilder().Add([]byte("{")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestIDLength(t *testing.T) {
	if ValidID("PYSEC-" + strings.Repeat("1", 60)) {
		t.Fatal("over 64 characters")
	}
}

func archive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestReadArchiveOnlyReviewed(t *testing.T) {
	ok, _ := os.ReadFile("testdata/ok.json")
	other, _ := os.ReadFile("testdata/dupe_a.json")
	a := archive(t, map[string]string{
		"advisory-database-main/advisories/github-reviewed/2024/05/GHSA-8gq3-9chp-cf2j/GHSA-8gq3-9chp-cf2j.json": string(ok),
		"advisory-database-main/advisories/unreviewed/2024/05/x/x.json":                                          string(other),
		"advisory-database-main/README.md":                                                                       "x",
	})
	b := NewBuilder()
	if err := ReadArchive(bytes.NewReader(a), b); err != nil {
		t.Fatal(err)
	}
	got, _, _ := b.Result()
	if len(got) != 1 || got[0].ID != "GHSA-8gq3-9chp-cf2j" {
		t.Fatalf("got %+v", got)
	}
	if err := ReadArchive(bytes.NewReader(archive(t, map[string]string{"r/README.md": "x"})), NewBuilder()); err == nil {
		t.Fatal("an archive without advisories must fail")
	}
}

func TestFetch(t *testing.T) {
	ok, _ := os.ReadFile("testdata/ok.json")
	a := archive(t, map[string]string{"r/advisories/github-reviewed/a.json": string(ok)})
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(a)
	}))
	defer srv.Close()
	c := NewClient()
	c.HTTP = srv.Client()
	c.HTTP.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server
	c.Archive = srv.URL
	c.extraHost = strings.TrimPrefix(srv.URL, "https://")
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	got, st, err := c.Fetch(context.Background())
	if err != nil || len(got) != 1 || st.Published != 1 || hits != 2 {
		t.Fatalf("got %+v %+v %v after %d requests", got, st, err, hits)
	}
	c.Archive = "https://example.com/x.tar.gz"
	if _, _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("a foreign host must be refused")
	}
	c.Archive = srv.URL
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "gone", http.StatusNotFound) })
	if _, _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("a 404 must fail")
	}
}
