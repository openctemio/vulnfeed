package collect

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/vulnfeed/internal/bundle"
	"github.com/openctemio/vulnfeed/internal/model"
	"github.com/openctemio/vulnfeed/internal/nvd"
)

var nginx = model.Product{Key: "cpe:a:f5:nginx", Part: "a", Vendor: "f5", Name: "nginx", CPEVendor: "f5", CPEProduct: "nginx"}

func rec(id, end string) nvd.Record {
	r := nvd.Record{Vuln: model.Vuln{ID: id, Status: "Analyzed", CWEs: []string{}}, Products: map[string]model.Product{nginx.Key: nginx}}
	if end != "" {
		r.Ranges = []model.Range{{Vuln: id, Product: nginx.Key, Scheme: "generic", Source: "nvd", End: end}}
	}
	return r
}

type fakePager struct {
	pages   [][]nvd.Record
	queries []nvd.Query
}

func (f *fakePager) FetchPage(_ context.Context, q nvd.Query) (*nvd.Page, error) {
	f.queries = append(f.queries, q)
	total := 0
	for _, p := range f.pages {
		total += len(p)
	}
	idx, seen := 0, 0
	for idx < len(f.pages) && seen < q.StartIndex {
		seen += len(f.pages[idx])
		idx++
	}
	if idx >= len(f.pages) {
		return &nvd.Page{TotalResults: total}, nil
	}
	return &nvd.Page{TotalResults: total, Count: len(f.pages[idx]), Records: f.pages[idx]}, nil
}

func TestBootstrapThenIncremental(t *testing.T) {
	now := time.Date(2026, 10, 9, 2, 0, 0, 0, time.UTC)
	p := &fakePager{pages: [][]nvd.Record{{rec("CVE-2021-0001", "2"), rec("CVE-2021-0002", "")}, {rec("CVE-2021-0003", "3")}}}
	first, err := Build(context.Background(), nil, p, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || len(first.Vulns) != 2 || len(p.queries) != 2 || !p.queries[0].ModifiedGTE.IsZero() {
		t.Fatalf("bootstrap: seq %d vulns %d queries %+v", first.Sequence, len(first.Vulns), p.queries)
	}
	if !first.SourceAsOf("nvd").Equal(now) {
		t.Fatal("source as-of")
	}
	// Next day: only modified CVEs; a rejected one keeps its record without
	// ranges; a CVE first seen without ranges is not added.
	rejected := rec("CVE-2021-0001", "")
	rejected.Rejected = true
	p2 := &fakePager{pages: [][]nvd.Record{{rejected, rec("CVE-2021-0004", ""), rec("CVE-2021-0003", "4")}}}
	second, err := Build(context.Background(), first, p2, Options{Now: now.Add(24 * time.Hour), AllowMassChange: true})
	if err != nil {
		t.Fatal(err)
	}
	q := p2.queries[0]
	if !q.ModifiedGTE.Equal(now.Add(-cursorOverlap)) || !q.ModifiedLT.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("window %+v", q)
	}
	if second.Sequence != 2 || len(second.Ranges["CVE-2021-0001"]) != 0 || second.Vulns["CVE-2021-0001"].ID == "" ||
		second.Ranges["CVE-2021-0003"][0].End != "4" {
		t.Fatalf("second %+v", second)
	}
	if _, ok := second.Vulns["CVE-2021-0004"]; ok {
		t.Fatal("CVE without ranges added")
	}
	ids, added, removed := bundle.Changed(first, second)
	if len(ids) != 2 || added != 1 || removed != 2 {
		t.Fatalf("changed %v +%d -%d", ids, added, removed)
	}
}

func TestLongGapUsesWindows(t *testing.T) {
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	prev := bundle.NewSnapshot()
	prev.Sources = []bundle.Source{{Name: "nvd", AsOf: now.AddDate(0, -9, 0)}}
	p := &fakePager{}
	if _, err := Build(context.Background(), prev, p, Options{Now: now}); err != nil {
		t.Fatal(err)
	}
	if len(p.queries) != 3 {
		t.Fatalf("windows %d", len(p.queries))
	}
	for _, q := range p.queries {
		if q.ModifiedLT.Sub(q.ModifiedGTE) > nvd.MaxWindow {
			t.Fatalf("window %+v", q)
		}
	}
}

func TestGuardRefusesMassRemoval(t *testing.T) {
	now := time.Now()
	prev := bundle.NewSnapshot()
	prev.Sources = []bundle.Source{{Name: "nvd", AsOf: now.Add(-time.Hour)}}
	var withdrawn []nvd.Record
	for i := 0; i < 600; i++ {
		id := fmt.Sprintf("CVE-2021-%05d", i)
		r := rec(id, "2")
		prev.SetVuln(r.Vuln, r.Ranges, r.Products)
		w := rec(id, "")
		w.Ranges = []model.Range{{Vuln: id, Product: nginx.Key, Scheme: "generic", Source: "nvd", End: "3"}}
		withdrawn = append(withdrawn, w)
	}
	// Every range replaced: 600 removed, over the 500 floor.
	p := &fakePager{pages: [][]nvd.Record{withdrawn}}
	if _, err := Build(context.Background(), prev, p, Options{Now: now}); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("guard: %v", err)
	}
	p = &fakePager{pages: [][]nvd.Record{withdrawn}}
	if _, err := Build(context.Background(), prev, p, Options{Now: now, AllowMassChange: true}); err != nil {
		t.Fatalf("override: %v", err)
	}
}
