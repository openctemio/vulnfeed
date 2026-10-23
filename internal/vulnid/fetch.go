package vulnid

// Reading the GitHub Advisory Database: one tar.gz of the default branch
// from codeload, streamed (an entry at a time, never held whole). Only
// HTTPS to the GitHub hosts below is followed.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Source repository and archive URL.
const (
	DefaultArchive = "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main"
	reviewedDir    = "advisories/github-reviewed/"

	maxArchiveBytes = 1 << 30 // compressed
	maxTarBytes     = 8 << 30 // uncompressed
	maxFileBytes    = 4 << 20
	maxAttempts     = 3
)

var allowedHosts = map[string]bool{"codeload.github.com": true, "github.com": true}

// Client fetches the advisory archive.
type Client struct {
	HTTP    *http.Client
	Archive string
	Sleep   func(context.Context, time.Duration) error
	Log     func(format string, args ...any)
	// extraHost admits a test server's host.
	extraHost string
}

// NewClient returns a client of the public repository.
func NewClient() *Client {
	c := &Client{Archive: DefaultArchive, Sleep: func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}}
	c.HTTP = &http.Client{Timeout: 30 * time.Minute, CheckRedirect: c.checkRedirect}
	return c
}

func (c *Client) ok(u *url.URL) bool {
	return u.Scheme == "https" && (allowedHosts[u.Hostname()] || (c.extraHost != "" && u.Host == c.extraHost))
}

func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("vulnid: too many redirects")
	}
	if !c.ok(req.URL) {
		return fmt.Errorf("vulnid: redirect to %s refused", req.URL.Redacted())
	}
	return nil
}

// Fetch downloads the archive and builds the map. A failed download is
// retried; a failure after that is returned (the caller publishes without
// the map).
func (c *Client) Fetch(ctx context.Context) ([]Entry, Stats, error) {
	u, err := url.Parse(c.Archive)
	if err != nil || !c.ok(u) {
		return nil, Stats{}, fmt.Errorf("vulnid: refusing to fetch %q", c.Archive)
	}
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		b := NewBuilder()
		retry, err := c.once(ctx, u.String(), b)
		if err == nil {
			return b.Result()
		}
		lastErr = err
		if !retry || attempt == maxAttempts {
			break
		}
		if c.Log != nil {
			c.Log("vulnid: %v; retrying", err)
		}
		if err := c.Sleep(ctx, 10*time.Second*time.Duration(attempt)); err != nil {
			return nil, Stats{}, err
		}
	}
	return nil, Stats{}, lastErr
}

func (c *Client) once(ctx context.Context, rawURL string, b *Builder) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "openctemio-vulnfeed (https://github.com/openctemio/vulnfeed)")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return true, fmt.Errorf("vulnid fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500,
			fmt.Errorf("vulnid: status %d from %s", resp.StatusCode, resp.Request.URL.Host)
	}
	if err := ReadArchive(io.LimitReader(resp.Body, maxArchiveBytes+1), b); err != nil {
		return true, err
	}
	return false, nil
}

// ReadArchive streams a gzip tar of the repository into b: the JSON files
// under advisories/github-reviewed/ (below the archive's top directory).
func ReadArchive(r io.Reader, b *Builder) error {
	cr := &countReader{r: r, max: maxArchiveBytes}
	gz, err := gzip.NewReader(cr)
	if err != nil {
		return fmt.Errorf("vulnid: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(&countReader{r: gz, max: maxTarBytes})
	files := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("vulnid: archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".json") {
			continue
		}
		_, rest, ok := strings.Cut(h.Name, "/")
		if !ok || !strings.HasPrefix(rest, reviewedDir) || strings.Contains(rest, "..") {
			continue
		}
		if h.Size > maxFileBytes {
			continue
		}
		doc, err := io.ReadAll(io.LimitReader(tr, maxFileBytes))
		if err != nil {
			return fmt.Errorf("vulnid: archive: %w", err)
		}
		files++
		if err := b.Add(doc); err != nil {
			continue // one malformed file does not sink the map
		}
	}
	if files == 0 {
		return errors.New("vulnid: the archive holds no reviewed advisories")
	}
	return nil
}

type countReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, errors.New("vulnid: archive over the size cap")
	}
	return n, err
}
