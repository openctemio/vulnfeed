// Package collect builds the next snapshot: the previous one plus what the
// sources changed since.
package collect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/vulnfeed/internal/bundle"
	"github.com/openctemio/vulnfeed/internal/cve5"
	"github.com/openctemio/vulnfeed/internal/nvd"
)

// Source terms and attribution carried in every manifest.
var nvdSource = bundle.Source{
	Name:        "nvd",
	Terms:       "https://nvd.nist.gov/developers/terms-of-use",
	Attribution: "This product uses data from the NVD API but is not endorsed or certified by the NVD.",
}

var cve5Source = bundle.Source{
	Name:        "cve5",
	Terms:       "https://www.cve.org/Legal/TermsOfUse",
	Attribution: "CVE records from the CVE List of the CVE Program. CVE is a registered trademark of The MITRE Corporation.",
}

// Guard against a source that suddenly withdraws data.
const (
	maxRemovedShare = 0.02
	minRemovedLimit = 500
	cursorOverlap   = 10 * time.Minute
)

// Pager fetches NVD pages; *nvd.Client implements it.
type Pager interface {
	FetchPage(ctx context.Context, q nvd.Query) (*nvd.Page, error)
}

// CVEList reads the CVE List; *cve5.Client implements it.
type CVEList interface {
	Changed(ctx context.Context, from, to time.Time, fn func(cve5.Record)) error
	Baseline(ctx context.Context, fn func(cve5.Record)) (time.Time, error)
}

// Options of a build.
type Options struct {
	Now time.Time
	// AllowMassChange lets a build remove more than the guard allows (a
	// person decided the source change is real).
	AllowMassChange bool
	// Since limits a first build to CVEs modified after it (a trial run;
	// a published first build reads the whole corpus).
	Since time.Time
	// CVEList, when set, is read after NVD (see merge.go for the
	// precedence between the two).
	CVEList CVEList
	Log     func(format string, args ...any)
}

// Build returns the next snapshot. prev may be nil (first build).
func Build(ctx context.Context, prev *bundle.Snapshot, pager Pager, opt Options) (*bundle.Snapshot, error) {
	next := bundle.NewSnapshot()
	var since time.Time
	if prev != nil {
		next.Sequence = prev.Sequence + 1
		for k, v := range prev.Vulns {
			next.Vulns[k] = v
		}
		for k, v := range prev.Ranges {
			next.Ranges[k] = v
		}
		for k, v := range prev.Products {
			next.Products[k] = v
		}
		since = prev.SourceAsOf("nvd")
	} else {
		next.Sequence = 1
		since = opt.Since
	}
	started := opt.Now.UTC().Truncate(time.Second)
	apply := func(p *nvd.Page) {
		for _, rec := range p.Records {
			applyRecord(next, rec)
		}
	}
	if since.IsZero() {
		if err := pages(ctx, pager, nvd.Query{}, apply, opt.Log); err != nil {
			return nil, err
		}
	} else {
		from := since.Add(-cursorOverlap)
		for from.Before(started) {
			to := from.Add(nvd.MaxWindow)
			if to.After(started) {
				to = started
			}
			if err := pages(ctx, pager, nvd.Query{ModifiedGTE: from, ModifiedLT: to}, apply, opt.Log); err != nil {
				return nil, err
			}
			from = to
		}
	}
	src := nvdSource
	src.AsOf = started
	next.Sources = []bundle.Source{src}
	if opt.CVEList != nil {
		var cveSince time.Time
		if prev != nil {
			cveSince = prev.SourceAsOf("cve5")
		} else {
			cveSince = opt.Since
		}
		if err := readCVEList(ctx, next, opt.CVEList, cveSince, started, opt.Log); err != nil {
			return nil, err
		}
		cs := cve5Source
		cs.AsOf = started
		next.Sources = append(next.Sources, cs)
	} else if prev != nil {
		// A build without the CVE List keeps its cursor for the next one.
		for _, s := range prev.Sources {
			if s.Name == "cve5" {
				next.Sources = append(next.Sources, s)
			}
		}
	}
	if prev != nil && !opt.AllowMassChange {
		_, _, removed := bundle.Changed(prev, next)
		total := 0
		for _, rs := range prev.Ranges {
			total += len(rs)
		}
		limit := int(float64(total) * maxRemovedShare)
		if limit < minRemovedLimit {
			limit = minRemovedLimit
		}
		if removed > limit {
			return nil, fmt.Errorf("refusing to publish: %d ranges removed, over the limit of %d (rerun with --allow-mass-change after checking the source)", removed, limit)
		}
	}
	return next, next.Validate()
}

// readCVEList applies the CVE List records changed since the cursor; with
// no cursor (the source's first build), or more changes than an
// incremental read takes, it reads the daily baseline and the changes
// since it.
func readCVEList(ctx context.Context, s *bundle.Snapshot, src CVEList, since, until time.Time, log func(string, ...any)) error {
	apply := func(r cve5.Record) { applyCVE5(s, r) }
	if !since.IsZero() {
		err := src.Changed(ctx, since.Add(-cursorOverlap), until, apply)
		if !errors.Is(err, cve5.ErrTooManyChanges) {
			return err
		}
		if log != nil {
			log("cve5: %v; reading the baseline", err)
		}
	}
	asOf, err := src.Baseline(ctx, apply)
	if err != nil {
		return err
	}
	return src.Changed(ctx, asOf.Add(-cursorOverlap), until, apply)
}

func pages(ctx context.Context, pager Pager, q nvd.Query, apply func(*nvd.Page), log func(string, ...any)) error {
	for start := 0; ; {
		q.StartIndex = start
		p, err := pager.FetchPage(ctx, q)
		if err != nil {
			return err
		}
		apply(p)
		start += p.Count
		if log != nil {
			log("nvd: %d/%d", start, p.TotalResults)
		}
		if p.Count == 0 || start >= p.TotalResults {
			return nil
		}
	}
}
