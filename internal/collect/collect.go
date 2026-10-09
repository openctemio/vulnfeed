// Package collect builds the next snapshot: the previous one plus what the
// sources changed since.
package collect

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/vulnfeed/internal/bundle"
	"github.com/openctemio/vulnfeed/internal/nvd"
)

// Source terms and attribution carried in every manifest.
var nvdSource = bundle.Source{
	Name:        "nvd",
	Terms:       "https://nvd.nist.gov/developers/terms-of-use",
	Attribution: "This product uses data from the NVD API but is not endorsed or certified by the NVD.",
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

// Options of a build.
type Options struct {
	Now time.Time
	// AllowMassChange lets a build remove more than the guard allows (a
	// person decided the source change is real).
	AllowMassChange bool
	// Since limits a first build to CVEs modified after it (a trial run;
	// a published first build reads the whole corpus).
	Since time.Time
	Log   func(format string, args ...any)
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

// applyRecord folds one converted CVE into the snapshot: a CVE with ranges
// (or already in the snapshot) gets its record and complete range set; a
// rejected CVE keeps its record without ranges; a CVE with more statements
// than a bundle carries keeps its previous ranges.
func applyRecord(s *bundle.Snapshot, rec nvd.Record) {
	_, known := s.Vulns[rec.Vuln.ID]
	switch {
	case rec.Rejected:
		if known {
			s.SetVuln(rec.Vuln, nil, nil)
		}
	case rec.TooManyRanges:
		if known {
			s.SetVuln(rec.Vuln, s.Ranges[rec.Vuln.ID], nil)
		}
	case len(rec.Ranges) == 0 && !known:
	default:
		s.SetVuln(rec.Vuln, rec.Ranges, rec.Products)
	}
}
