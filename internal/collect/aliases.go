package collect

import (
	"strings"

	"github.com/openctemio/vulnfeed/internal/alias"
	"github.com/openctemio/vulnfeed/internal/bundle"
	"github.com/openctemio/vulnfeed/internal/cve5"
	"github.com/openctemio/vulnfeed/internal/model"
	"github.com/openctemio/vulnfeed/internal/nvd"
)

// observe records what a CVE List record says about product identity: its
// CNA and ADP affected items and the CVE's NVD products. A rejected record
// leaves the state (it is not published).
func observe(state map[string]alias.Obs, s *bundle.Snapshot, rec cve5.Record) {
	id := rec.Vuln.ID
	if rec.Rejected {
		delete(state, id)
		return
	}
	var adp []alias.Item
	for _, a := range rec.ADP {
		adp = append(adp, items(a.Affected)...)
	}
	var nvdKeys []string
	for _, r := range s.Ranges[id] {
		if r.Source == "nvd" {
			nvdKeys = append(nvdKeys, strings.TrimPrefix(r.Product, "cpe:"))
		}
	}
	state[id] = alias.Observe(id, items(rec.Affected), adp, nvdKeys)
}

func items(in []cve5.Affected) []alias.Item {
	out := make([]alias.Item, 0, len(in))
	for _, a := range in {
		it := alias.Item{Vendor: a.Vendor, Product: a.Product, PackageName: a.PackageName}
		for _, c := range a.CPEs {
			if p, err := nvd.ParseCPE(c); err == nil && !strings.Contains(p.Product, ":") {
				it.CPEs = append(it.CPEs, p.Part+":"+p.Vendor+":"+p.Product)
			}
		}
		out = append(out, it)
	}
	return out
}

// Aliases builds the dictionary from the state, rewrites the CVE List
// ranges whose product is a CNA name the dictionary maps to the canonical
// product, and returns the entries and the coverage. Ranges of a name the
// dictionary does not resolve keep their name-derived product (kept,
// matched once a later dictionary resolves it).
func Aliases(s *bundle.Snapshot, state map[string]alias.Obs) ([]alias.Entry, alias.Stats, error) {
	var vocab []string
	for _, rs := range s.Ranges {
		for _, r := range rs {
			if r.Source == "nvd" {
				vocab = append(vocab, strings.TrimPrefix(r.Product, "cpe:"))
			}
		}
	}
	d, err := alias.Build(state, vocab)
	if err != nil {
		return nil, alias.Stats{}, err
	}
	entries := d.Entries(state)
	Remap(s, d.Map(entries))
	return entries, d.Coverage(state, len(entries)), nil
}

// Remap points every CVE List range at the canonical product its name maps
// to. NVD ranges already name CPE products and are left alone.
func Remap(s *bundle.Snapshot, m map[string]string) {
	if len(m) == 0 {
		return
	}
	for id, rs := range s.Ranges {
		changed := false
		out := make([]model.Range, len(rs))
		products := map[string]model.Product{}
		for i, r := range rs {
			out[i] = r
			if r.Source != "cve5" {
				continue
			}
			if t, ok := m[strings.TrimPrefix(r.Product, "cpe:")]; ok {
				out[i].Product = "cpe:" + t
				products[out[i].Product] = productOf(s, t)
				changed = true
			}
		}
		if changed {
			s.SetVuln(s.Vulns[id], out, products)
		}
	}
}

// productOf returns the snapshot's product for a CPE key or one built from
// the key.
func productOf(s *bundle.Snapshot, key string) model.Product {
	if p, ok := s.Products["cpe:"+key]; ok {
		return p
	}
	parts := strings.SplitN(key, ":", 3)
	return nvd.ProductOf(nvd.CPE{Part: parts[0], Vendor: parts[1], Product: parts[2]})
}
