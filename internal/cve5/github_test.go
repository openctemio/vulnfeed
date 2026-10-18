package cve5

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	commitNew = "1111111111111111111111111111111111111111"
	commitOld = "2222222222222222222222222222222222222222"
	pathA     = "cves/2026/10xxx/CVE-2026-10001.json"
)

type fakeRepo struct {
	t        *testing.T
	files    map[string][]byte // "<commit>/<path>" -> content
	commits  []string
	changes  map[string][]map[string]string
	baseline []byte
	digest   string
	hits     map[string]int
	tokens   map[string]string
}

func newFakeRepo(t *testing.T) *fakeRepo {
	pub, _ := os.ReadFile("testdata/published.json")
	upd, _ := os.ReadFile("testdata/updated.json")
	return &fakeRepo{
		t:       t,
		files:   map[string][]byte{commitOld + "/" + pathA: pub, commitNew + "/" + pathA: upd},
		commits: []string{commitNew, commitOld},
		changes: map[string][]map[string]string{
			commitNew: {{"filename": pathA, "status": "modified", "sha": gitBlobID(upd)}, {"filename": "README.md", "status": "modified", "sha": commitNew}},
			commitOld: {{"filename": pathA, "status": "added", "sha": gitBlobID(pub)}},
		},
		hits:   map[string]int{},
		tokens: map[string]string{},
	}
}

func (f *fakeRepo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits[r.URL.Path]++
	f.tokens[r.URL.Path] = r.Header.Get("Authorization")
	switch {
	case r.URL.Path == "/api/repos/CVEProject/cvelistV5/commits":
		if r.URL.Query().Get("page") != "1" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		var list []map[string]string
		for _, c := range f.commits {
			list = append(list, map[string]string{"sha": c})
		}
		_ = json.NewEncoder(w).Encode(list)
	case strings.HasPrefix(r.URL.Path, "/api/repos/CVEProject/cvelistV5/commits/"):
		sha := strings.TrimPrefix(r.URL.Path, "/api/repos/CVEProject/cvelistV5/commits/")
		_ = json.NewEncoder(w).Encode(map[string]any{"files": f.changes[sha]})
	case r.URL.Path == "/api/repos/CVEProject/cvelistV5/releases/latest":
		_ = json.NewEncoder(w).Encode(map[string]any{"assets": []map[string]any{
			{"name": "2026-10-18_delta_CVEs_at_1600Z.zip", "size": 10, "digest": "sha256:00", "browser_download_url": "https://" + r.Host + "/dl/delta.zip"},
			{"name": "2026-10-18_all_CVEs_at_midnight.zip.zip", "size": len(f.baseline), "digest": "sha256:" + f.digest, "browser_download_url": "https://" + r.Host + "/dl/baseline.zip.zip"},
		}})
	case r.URL.Path == "/dl/baseline.zip.zip":
		_, _ = w.Write(f.baseline)
	case strings.HasPrefix(r.URL.Path, "/raw/CVEProject/cvelistV5/"):
		b, ok := f.files[strings.TrimPrefix(r.URL.Path, "/raw/CVEProject/cvelistV5/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	default:
		http.NotFound(w, r)
	}
}

func testClient(t *testing.T, f http.Handler) *Client {
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	c := NewClient("tok")
	c.HTTP = srv.Client()
	c.API, c.Raw = srv.URL+"/api", srv.URL+"/raw"
	c.TmpDir = t.TempDir()
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func TestChangedTakesNewestVersionAndVerifiesBlobs(t *testing.T) {
	f := newFakeRepo(t)
	c := testClient(t, f)
	var got []Record
	if err := c.Changed(context.Background(), time.Now().Add(-time.Hour), time.Now(), func(r Record) { got = append(got, r) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.HasSuffix(got[0].Vuln.Description, "(updated).") {
		t.Fatalf("got %+v", got)
	}
	if f.hits["/raw/CVEProject/cvelistV5/"+commitOld+"/"+pathA] != 0 {
		t.Fatal("an older version was fetched")
	}
	// The token goes to the API only.
	if f.tokens["/api/repos/CVEProject/cvelistV5/commits"] != "Bearer tok" || f.tokens["/raw/CVEProject/cvelistV5/"+commitNew+"/"+pathA] != "" {
		t.Fatalf("token sent where it must not be: %v", f.tokens)
	}

	// A file whose bytes are not the committed blob fails the read.
	f.files[commitNew+"/"+pathA] = append([]byte(nil), f.files[commitOld+"/"+pathA]...)
	err := c.Changed(context.Background(), time.Now().Add(-time.Hour), time.Now(), func(Record) {})
	if err == nil || !strings.Contains(err.Error(), "blob") {
		t.Fatalf("tampered file: %v", err)
	}
}

func TestChangedSkipsMisfiledRecord(t *testing.T) {
	f := newFakeRepo(t)
	other := "cves/2026/10xxx/CVE-2026-10002.json"
	b := f.files[commitNew+"/"+pathA]
	f.files[commitNew+"/"+other] = b
	f.changes[commitNew] = []map[string]string{{"filename": other, "status": "added", "sha": gitBlobID(b)}}
	f.changes[commitOld] = nil
	var n int
	if err := testClient(t, f).Changed(context.Background(), time.Now().Add(-time.Hour), time.Now(), func(Record) { n++ }); err != nil || n != 0 {
		t.Fatalf("misfiled record: n %d err %v", n, err)
	}
}

func TestChangedTooMany(t *testing.T) {
	// Every commit page is full: past the page cap it is too many.
	c := testClient(t, &pagedRepo{newFakeRepo(t)})
	err := c.Changed(context.Background(), time.Now().Add(-time.Hour), time.Now(), func(Record) {})
	if !errors.Is(err, ErrTooManyChanges) {
		t.Fatalf("got %v", err)
	}
}

// pagedRepo answers every commit list page with 100 commits.
type pagedRepo struct{ *fakeRepo }

func (p *pagedRepo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/repos/CVEProject/cvelistV5/commits" {
		var list []map[string]string
		for i := 0; i < 100; i++ {
			list = append(list, map[string]string{"sha": fmt.Sprintf("%040x", i)})
		}
		_ = json.NewEncoder(w).Encode(list)
		return
	}
	p.fakeRepo.ServeHTTP(w, r)
}

func baselineZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var inner bytes.Buffer
	zw := zip.NewWriter(&inner)
	for name, b := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(b)
	}
	_ = zw.Close()
	var outer bytes.Buffer
	ow := zip.NewWriter(&outer)
	w, _ := ow.Create("cves.zip")
	_, _ = w.Write(inner.Bytes())
	_ = ow.Close()
	return outer.Bytes()
}

func TestBaseline(t *testing.T) {
	pub, _ := os.ReadFile("testdata/published.json")
	rej, _ := os.ReadFile("testdata/rejected.json")
	rej = bytes.Replace(rej, []byte("CVE-2026-10001"), []byte("CVE-2026-10003"), 1)
	f := newFakeRepo(t)
	f.baseline = baselineZip(t, map[string][]byte{
		"cves/2026/10xxx/CVE-2026-10001.json": pub,
		"cves/2026/10xxx/CVE-2026-10003.json": rej,
		"cves/2026/10xxx/CVE-2026-10009.json": pub, // filed under another id
		"cves/deltaLog.json":                  []byte(`{}`),
	})
	sum := sha256.Sum256(f.baseline)
	f.digest = hex.EncodeToString(sum[:])
	c := testClient(t, f)
	var ids []string
	asOf, err := c.Baseline(context.Background(), func(r Record) { ids = append(ids, r.Vuln.ID) })
	if err != nil {
		t.Fatal(err)
	}
	if !asOf.Equal(time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)) || len(ids) != 2 {
		t.Fatalf("as of %v ids %v", asOf, ids)
	}

	// A baseline that does not match the published digest is refused.
	f.digest = strings.Repeat("0", 64)
	if _, err := c.Baseline(context.Background(), func(Record) {}); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("digest mismatch: %v", err)
	}
}

func TestBaselineZipRefusesUnexpectedLayout(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range []string{"a.zip", "b.zip"} {
		w, _ := zw.Create(n)
		_, _ = w.Write([]byte("x"))
	}
	_ = zw.Close()
	if err := ReadBaselineZip(bytes.NewReader(buf.Bytes()), int64(buf.Len()), t.TempDir(), func(Record) {}, nil); err == nil {
		t.Fatal("two entries accepted")
	}
}

func TestRefusesOtherHostsAndRedirects(t *testing.T) {
	c := testClient(t, newFakeRepo(t))
	if err := c.get(context.Background(), "https://example.com/x", false, 10, nil); err == nil {
		t.Fatal("fetch from an unknown host")
	}
	if err := c.get(context.Background(), "http://raw.githubusercontent.com/x", false, 10, nil); err == nil {
		t.Fatal("plain http accepted")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://evil.example/x", nil)
	if checkRedirect(req, nil) == nil {
		t.Fatal("redirect to an unknown host followed")
	}
	req, _ = http.NewRequest(http.MethodGet, "https://objects.githubusercontent.com/x", nil)
	req.Header.Set("Authorization", "Bearer tok")
	if checkRedirect(req, nil) != nil || req.Header.Get("Authorization") != "" {
		t.Fatal("token kept on a redirect off the API host")
	}
}

func TestResponseCap(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte("a"), 100))
	}))
	defer srv.Close()
	c := NewClient("")
	c.HTTP, c.API = srv.Client(), srv.URL
	err := c.get(context.Background(), srv.URL+"/x", false, 10, func(r io.Reader) error {
		_, err := bytes.NewBuffer(nil).ReadFrom(r)
		return err
	})
	if err == nil {
		t.Fatal("over-cap response accepted")
	}
}
