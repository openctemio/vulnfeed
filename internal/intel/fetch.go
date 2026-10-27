package intel

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Sources. cisa.gov fronts its feed with a WAF that refuses some data-center
// addresses; the cisagov organisation publishes the same catalog on GitHub.
const (
	KEVURL       = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	KEVMirrorURL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
	EPSSURL      = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

	maxKEVBytes      = 64 << 20
	maxEPSSGzBytes   = 128 << 20
	maxEPSSPlainSize = 1 << 30
	maxAttempts      = 3
)

var allowedHosts = map[string]bool{
	"www.cisa.gov":               true,
	"raw.githubusercontent.com":  true,
	"epss.empiricalsecurity.com": true,
}

// Client fetches the two feeds.
type Client struct {
	HTTP      *http.Client
	KEVURLs   []string // tried in order
	EPSSURL   string
	Sleep     func(context.Context, time.Duration) error
	Log       func(format string, args ...any)
	extraHost string // admits a test server's host
}

// NewClient returns a client of the public sources.
func NewClient() *Client {
	c := &Client{KEVURLs: []string{KEVURL, KEVMirrorURL}, EPSSURL: EPSSURL, Sleep: sleep}
	c.HTTP = &http.Client{Timeout: 10 * time.Minute, CheckRedirect: c.checkRedirect}
	return c
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) ok(u *url.URL) bool {
	return u.Scheme == "https" && (allowedHosts[u.Hostname()] || (c.extraHost != "" && u.Host == c.extraHost))
}

func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("intel: too many redirects")
	}
	if !c.ok(req.URL) {
		return fmt.Errorf("intel: redirect to %s refused", req.URL.Redacted())
	}
	return nil
}

func (c *Client) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log(format, args...)
	}
}

// get runs fn on the body of a 200 answer, retrying transient failures.
func (c *Client) get(ctx context.Context, raw string, fn func(io.Reader) error) error {
	u, err := url.Parse(raw)
	if err != nil || !c.ok(u) {
		return fmt.Errorf("intel: refusing to fetch %q", raw)
	}
	var last error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		retry, err := c.once(ctx, u.String(), fn)
		if err == nil {
			return nil
		}
		last = err
		if !retry || attempt == maxAttempts {
			break
		}
		c.logf("intel: %v; retrying", err)
		if err := c.Sleep(ctx, 5*time.Second*time.Duration(attempt)); err != nil {
			return err
		}
	}
	return last
}

func (c *Client) once(ctx context.Context, raw string, fn func(io.Reader) error) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "openctemio-vulnfeed (https://github.com/openctemio/vulnfeed)")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return true, fmt.Errorf("intel fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500,
			fmt.Errorf("intel: status %d from %s", resp.StatusCode, resp.Request.URL.Host)
	}
	// A parse failure is a bad document, not a transient error: no retry.
	return false, fn(resp.Body)
}

// FetchKEV reads the KEV catalog from the first source that answers with a
// document that validates (the WAF-to-mirror fallback).
func (c *Client) FetchKEV(ctx context.Context) (*KEV, error) {
	var last error
	for _, u := range c.KEVURLs {
		var k *KEV
		err := c.get(ctx, u, func(r io.Reader) (err error) {
			k, err = ParseKEV(io.LimitReader(r, maxKEVBytes))
			return err
		})
		if err == nil {
			return k, nil
		}
		last = err
		c.logf("intel: kev from %s failed: %v", hostOf(u), err)
	}
	return nil, last
}

// FetchEPSS reads the current EPSS scores.
func (c *Client) FetchEPSS(ctx context.Context) (*EPSS, error) {
	var e *EPSS
	err := c.get(ctx, c.EPSSURL, func(r io.Reader) error {
		gz, err := gzip.NewReader(io.LimitReader(r, maxEPSSGzBytes))
		if err != nil {
			return fmt.Errorf("intel: epss gzip: %w", err)
		}
		defer gz.Close()
		e, err = ParseEPSS(io.LimitReader(gz, maxEPSSPlainSize))
		return err
	})
	return e, err
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return "?"
}
