package cve5

// Reading the CVE List from its GitHub repository.
//
// Changes: the commits in a time window, each commit's changed record
// files with their git blob ids, and each file fetched at the commit that
// last changed it. The fetched bytes must hash to the blob id the API
// named, so a file is exactly the one committed. Baseline: the daily
// "all CVEs at midnight" release asset, checked against the SHA-256
// digest the release API publishes for it.
//
// Only HTTPS to the GitHub hosts below is followed; the token, when set,
// goes to the API host only.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git blob ids are SHA-1; the id is the source's own checksum
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Repository and hosts.
const (
	DefaultRepo = "CVEProject/cvelistV5"
	APIBase     = "https://api.github.com"
	RawBase     = "https://raw.githubusercontent.com"
)

// Caps.
const (
	maxAPIBytes        = 64 << 20
	maxCommitPages     = 50 // 100 commits a page
	maxFilePages       = 30 // 100 files a page (the API lists at most 3000)
	maxChangedFiles    = 50_000
	maxBaselineBytes   = 2 << 30
	maxInnerZipBytes   = 4 << 30
	maxBaselineEntries = 2_000_000
	maxAttempts        = 4
	retryBackoff       = 10 * time.Second
)

var (
	allowedHosts = map[string]bool{"api.github.com": true, "github.com": true, "raw.githubusercontent.com": true,
		"objects.githubusercontent.com": true, "release-assets.githubusercontent.com": true}
	recordPath   = regexp.MustCompile(`^cves/[0-9]{4}/[0-9]{1,15}xxx/CVE-[0-9]{4}-[0-9]{4,19}\.json$`)
	recordName   = regexp.MustCompile(`(^|/)CVE-[0-9]{4}-[0-9]{4,19}\.json$`)
	baselineName = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2})_all_CVEs_at_midnight\.zip\.zip$`)
	shaPattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repoPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
)

// ErrTooManyChanges is returned when a window changes more than the
// incremental reader takes; the caller reads the baseline instead.
var ErrTooManyChanges = errors.New("cve5: too many changes for an incremental read")

// Client reads the CVE List repository.
type Client struct {
	HTTP   *http.Client
	API    string
	Raw    string
	Repo   string
	Token  string
	TmpDir string
	Sleep  func(context.Context, time.Duration) error
	Log    func(format string, args ...any)
}

// NewClient returns a client of the public repository; token (a GitHub
// token with no scopes is enough) raises the API rate limit.
func NewClient(token string) *Client {
	return &Client{
		HTTP:  &http.Client{Timeout: 30 * time.Minute, CheckRedirect: checkRedirect},
		API:   APIBase,
		Raw:   RawBase,
		Repo:  DefaultRepo,
		Token: token,
		Sleep: sleepCtx,
	}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("cve5: too many redirects")
	}
	if req.URL.Scheme != "https" || !allowedHosts[req.URL.Hostname()] {
		return fmt.Errorf("cve5: redirect to %s refused", req.URL.Redacted())
	}
	if req.URL.Hostname() != "api.github.com" {
		req.Header.Del("Authorization")
	}
	return nil
}

// allowed reports whether a host may be fetched from: a GitHub host, or
// the host of a configured base (a test server).
func (c *Client) allowed(host string) bool {
	if allowedHosts[host] {
		return true
	}
	for _, b := range []string{c.API, c.Raw} {
		if u, err := url.Parse(b); err == nil && u.Host == host {
			return true
		}
	}
	return false
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

func (c *Client) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log(format, args...)
	}
}

// get fetches rawURL into w, at most limit bytes, retrying on rate
// limiting and server errors. api marks a request to the API host.
func (c *Client) get(ctx context.Context, rawURL string, api bool, limit int64, w func(io.Reader) error) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || !c.allowed(u.Host) {
		return fmt.Errorf("cve5: refusing to fetch %q", rawURL)
	}
	for attempt := 1; ; attempt++ {
		retry, err := c.once(ctx, u.String(), api, limit, w)
		if err == nil || !retry || attempt >= maxAttempts {
			return err
		}
		c.logf("cve5: %v; retrying", err)
		if err := c.Sleep(ctx, retryBackoff*time.Duration(attempt)); err != nil {
			return err
		}
	}
}

func (c *Client) once(ctx context.Context, rawURL string, api bool, limit int64, w func(io.Reader) error) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "openctemio-vulnfeed (https://github.com/openctemio/vulnfeed)")
	if api {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return true, fmt.Errorf("cve5 fetch: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode == http.StatusForbidden, resp.StatusCode >= 500:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return true, fmt.Errorf("cve5: status %d from %s", resp.StatusCode, req.URL.Host)
	default:
		return false, fmt.Errorf("cve5: status %d from %s", resp.StatusCode, req.URL.Host)
	}
	if resp.ContentLength > limit {
		return false, fmt.Errorf("cve5: response of %d bytes over the %d cap", resp.ContentLength, limit)
	}
	lr := &capped{r: resp.Body, left: limit}
	if err := w(lr); err != nil {
		return false, err
	}
	// The whole body must be consumed within the cap.
	if _, err := io.Copy(io.Discard, lr); err != nil {
		return false, err
	}
	return false, nil
}

// capped fails instead of truncating once more than left bytes are read.
type capped struct {
	r    io.Reader
	left int64
}

func (c *capped) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var one [1]byte
		if n, _ := c.r.Read(one[:]); n > 0 {
			return 0, errors.New("cve5: response over the size cap")
		}
		return 0, io.EOF
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

func (c *Client) getJSON(ctx context.Context, rawURL string, v any) error {
	return c.get(ctx, rawURL, true, maxAPIBytes, func(r io.Reader) error {
		if err := json.NewDecoder(r).Decode(v); err != nil {
			return fmt.Errorf("cve5: decode %s: %w", path.Base(strings.SplitN(rawURL, "?", 2)[0]), err)
		}
		return nil
	})
}

func (c *Client) repo() (string, error) {
	if !repoPattern.MatchString(c.Repo) {
		return "", fmt.Errorf("cve5: repository %q", c.Repo)
	}
	return c.Repo, nil
}

type changedFile struct {
	name, blob, commit string
}

// Changed reads every record changed by commits in [from, to) and calls fn
// with each, in file name order. A record that fails to decode is logged
// and skipped; one whose bytes do not match the committed blob fails the
// read.
func (c *Client) Changed(ctx context.Context, from, to time.Time, fn func(Record)) error {
	files, err := c.changedFiles(ctx, from, to)
	if err != nil {
		return err
	}
	repo, _ := c.repo()
	skipped := 0
	for i, f := range files {
		var rec Record
		var ok bool
		var decodeErr error
		raw := c.Raw + "/" + repo + "/" + f.commit + "/" + f.name
		err := c.get(ctx, raw, false, MaxRecordBytes, func(r io.Reader) error {
			b, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			if got := gitBlobID(b); got != f.blob {
				return fmt.Errorf("cve5: %s at %s: blob %s, the commit names %s", f.name, f.commit[:12], got, f.blob)
			}
			rec, ok, decodeErr = Decode(bytes.NewReader(b))
			if decodeErr == nil && ok && !strings.HasSuffix(f.name, "/"+rec.Vuln.ID+".json") {
				decodeErr = fmt.Errorf("record %s filed under another id", rec.Vuln.ID)
			}
			return nil
		})
		if err != nil {
			return err
		}
		switch {
		case decodeErr != nil:
			skipped++
			c.logf("cve5: %s skipped: %v", f.name, decodeErr)
		case ok:
			fn(rec)
		}
		if (i+1)%500 == 0 {
			c.logf("cve5: %d/%d changed records", i+1, len(files))
		}
	}
	c.logf("cve5: %d changed records read, %d skipped", len(files)-skipped, skipped)
	return nil
}

func (c *Client) changedFiles(ctx context.Context, from, to time.Time) ([]changedFile, error) {
	repo, err := c.repo()
	if err != nil {
		return nil, err
	}
	if !to.After(from) {
		return nil, nil
	}
	var commits []string
	for page := 1; ; page++ {
		if page > maxCommitPages {
			return nil, ErrTooManyChanges
		}
		q := url.Values{}
		q.Set("since", from.UTC().Format(time.RFC3339))
		q.Set("until", to.UTC().Format(time.RFC3339))
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		var list []struct {
			SHA string `json:"sha"`
		}
		if err := c.getJSON(ctx, c.API+"/repos/"+repo+"/commits?"+q.Encode(), &list); err != nil {
			return nil, err
		}
		for _, x := range list {
			if !shaPattern.MatchString(x.SHA) {
				return nil, fmt.Errorf("cve5: commit id %q", x.SHA)
			}
			commits = append(commits, x.SHA)
		}
		if len(list) < 100 {
			break
		}
	}
	// Newest commit first: the first commit that names a file is the one
	// whose version is current at the end of the window.
	byName := map[string]changedFile{}
	removed := map[string]bool{}
	for _, sha := range commits {
		for page := 1; ; page++ {
			if page > maxFilePages {
				return nil, ErrTooManyChanges
			}
			var commit struct {
				Files []struct {
					Filename string `json:"filename"`
					Status   string `json:"status"`
					SHA      string `json:"sha"`
				} `json:"files"`
			}
			if err := c.getJSON(ctx, fmt.Sprintf("%s/repos/%s/commits/%s?per_page=100&page=%d", c.API, repo, sha, page), &commit); err != nil {
				return nil, err
			}
			for _, f := range commit.Files {
				if !recordPath.MatchString(f.Filename) {
					continue
				}
				if _, seen := byName[f.Filename]; seen || removed[f.Filename] {
					continue
				}
				// Removed at the end of the window: an older commit's
				// version must not bring it back.
				if f.Status == "removed" {
					removed[f.Filename] = true
					continue
				}
				if !shaPattern.MatchString(f.SHA) {
					return nil, fmt.Errorf("cve5: blob id %q", f.SHA)
				}
				byName[f.Filename] = changedFile{name: f.Filename, blob: f.SHA, commit: sha}
				if len(byName)+len(removed) > maxChangedFiles {
					return nil, ErrTooManyChanges
				}
			}
			if len(commit.Files) < 100 {
				break
			}
		}
	}
	files := make([]changedFile, 0, len(byName))
	for _, f := range byName {
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	c.logf("cve5: %d commits, %d changed records between %s and %s", len(commits), len(files),
		from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	return files, nil
}

// gitBlobID is git's object id of a blob with content b.
func gitBlobID(b []byte) string {
	h := sha1.New() //nolint:gosec // see the import
	fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// Baseline reads every record of the newest daily baseline and calls fn
// with each. It returns the time the baseline is as of (its midnight,
// UTC); the changes since then come from Changed.
func (c *Client) Baseline(ctx context.Context, fn func(Record)) (time.Time, error) {
	repo, err := c.repo()
	if err != nil {
		return time.Time{}, err
	}
	var rel struct {
		Assets []struct {
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			Digest string `json:"digest"`
			URL    string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := c.getJSON(ctx, c.API+"/repos/"+repo+"/releases/latest", &rel); err != nil {
		return time.Time{}, err
	}
	for _, a := range rel.Assets {
		m := baselineName.FindStringSubmatch(a.Name)
		if m == nil {
			continue
		}
		asOf, err := time.Parse("2006-01-02", m[1])
		if err != nil {
			return time.Time{}, fmt.Errorf("cve5: baseline date %q", m[1])
		}
		want, ok := strings.CutPrefix(a.Digest, "sha256:")
		if !ok || len(want) != 64 {
			return time.Time{}, fmt.Errorf("cve5: baseline %s has no SHA-256 digest", a.Name)
		}
		if a.Size <= 0 || a.Size > maxBaselineBytes {
			return time.Time{}, fmt.Errorf("cve5: baseline of %d bytes", a.Size)
		}
		c.logf("cve5: reading baseline %s (%d bytes)", a.Name, a.Size)
		if err := c.readBaseline(ctx, a.URL, want, a.Size, fn); err != nil {
			return time.Time{}, err
		}
		return asOf.UTC(), nil
	}
	return time.Time{}, errors.New("cve5: the newest release has no baseline asset")
}

func (c *Client) readBaseline(ctx context.Context, rawURL, wantSHA string, size int64, fn func(Record)) error {
	dir, err := os.MkdirTemp(c.TmpDir, "cve5-baseline-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	outer, err := os.Create(dir + "/baseline.zip")
	if err != nil {
		return err
	}
	defer outer.Close()
	h := sha256.New()
	if err := c.get(ctx, rawURL, false, size, func(r io.Reader) error {
		_, err := io.Copy(io.MultiWriter(outer, h), r)
		return err
	}); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
		return fmt.Errorf("cve5: baseline SHA-256 %s, the release names %s", got, wantSHA)
	}
	return ReadBaselineZip(outer, size, dir, fn, c.logf)
}

// ReadBaselineZip reads a baseline archive (a zip holding one zip of
// record files) of size bytes, using dir for the inner archive.
func ReadBaselineZip(ra io.ReaderAt, size int64, dir string, fn func(Record), logf func(string, ...any)) error {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return fmt.Errorf("cve5: baseline: %w", err)
	}
	if len(zr.File) != 1 || !strings.HasSuffix(zr.File[0].Name, ".zip") {
		return fmt.Errorf("cve5: baseline holds %d entries, expected one zip", len(zr.File))
	}
	in, err := zr.File[0].Open()
	if err != nil {
		return err
	}
	inner, err := os.Create(dir + "/inner.zip")
	if err != nil {
		in.Close()
		return err
	}
	defer inner.Close()
	n, err := io.Copy(inner, &capped{r: in, left: maxInnerZipBytes})
	in.Close()
	if err != nil {
		return fmt.Errorf("cve5: baseline: %w", err)
	}
	ir, err := zip.NewReader(inner, n)
	if err != nil {
		return fmt.Errorf("cve5: baseline inner archive: %w", err)
	}
	if len(ir.File) > maxBaselineEntries {
		return fmt.Errorf("cve5: baseline of %d entries", len(ir.File))
	}
	read, skipped := 0, 0
	for _, f := range ir.File {
		if f.FileInfo().IsDir() || !recordName.MatchString(f.Name) {
			continue
		}
		if f.UncompressedSize64 > MaxRecordBytes {
			skipped++
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("cve5: baseline %s: %w", path.Base(f.Name), err)
		}
		rec, ok, err := Decode(rc)
		rc.Close()
		if err == nil && ok && path.Base(f.Name) != rec.Vuln.ID+".json" {
			err = fmt.Errorf("record %s filed under another id", rec.Vuln.ID)
		}
		switch {
		case err != nil:
			skipped++
			if logf != nil && skipped <= 50 {
				logf("cve5: baseline %s skipped: %v", path.Base(f.Name), err)
			}
		case ok:
			read++
			fn(rec)
		}
	}
	if logf != nil {
		logf("cve5: baseline: %d records read, %d skipped", read, skipped)
	}
	return nil
}
