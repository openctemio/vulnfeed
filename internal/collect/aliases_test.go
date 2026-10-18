package collect

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/vulnfeed/internal/alias"
	"github.com/openctemio/vulnfeed/internal/cve5"
	"github.com/openctemio/vulnfeed/internal/model"
	"github.com/openctemio/vulnfeed/internal/nvd"
)

// cnaRecord is a CVE List record whose only product identity is the CNA's
// vendor and product strings.
func cnaRecord(cveID, vendor, product, end string) cve5.Record {
	key := alias.NameKey(vendor, product)
	pk := "cpe:" + key
	p := model.Product{Key: pk, Part: "a", Vendor: vendor, Name: product, CPEVendor: key[2 : len(key)-len(product)-1], CPEProduct: key[len(key)-len(alias.ProductKey(product)):]}
	return cve5.Record{
		Vuln:     model.Vuln{ID: cveID, Status: cve5.StatusPublished, CWEs: []string{}},
		Ranges:   []model.Range{{Vuln: cveID, Product: pk, Scheme: "generic", End: end, Source: "cve5"}},
		Products: map[string]model.Product{pk: p},
		Affected: []cve5.Affected{{Vendor: vendor, Product: product}},
	}
}

// A CNA name that consistently co-occurs with an NVD product is learned;
// CVEs that name the product only by that string are then published under
// the canonical product. A name nothing resolves stays as it is (kept,
// unmatched) and is listed as unresolved.
func TestAliasesLearnAndRemap(t *testing.T) {
	now := time.Date(2026, 10, 9, 2, 0, 0, 0, time.UTC)
	var nvdRecs []nvd.Record
	var list []cve5.Record
	for i := 0; i < 3; i++ {
		cveID := fmt.Sprintf("CVE-2026-2000%d", i)
		nvdRecs = append(nvdRecs, rec(cveID, "1.20.1")) // NVD names f5:nginx
		list = append(list, cnaRecord(cveID, "Nginx Inc Software", "nginx", "1.20.1"))
	}
	list = append(list, cnaRecord("CVE-2026-30001", "Nginx Inc Software", "nginx", "1.25.0"),
		cnaRecord("CVE-2026-30002", "Nobody Knows", "Mystery Box", "2.0"))
	state := map[string]alias.Obs{}
	s, err := Build(context.Background(), nil, &fakePager{pages: [][]nvd.Record{nvdRecs}},
		Options{Now: now, CVEList: &fakeList{baseline: list, asOf: now}, AliasState: state})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Ranges["CVE-2026-30001"][0].Product; got != "cpe:a:nginx_inc_software:nginx" {
		t.Fatalf("before the dictionary: %s", got)
	}
	entries, st, err := Aliases(s, state)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Ranges["CVE-2026-30001"][0].Product; got != "cpe:a:f5:nginx" {
		t.Errorf("CNA-only CVE not remapped: %s", got)
	}
	if got := s.Ranges["CVE-2026-30002"][0].Product; got != "cpe:a:nobody_knows:mystery_box" {
		t.Errorf("unresolved name changed: %s", got)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Value == "a:nginx_inc_software:nginx" && e.Target == "a:f5:nginx" && e.Basis == alias.BasisLearned && e.Support == 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("entries %+v", entries)
	}
	// 5 published: 3 with NVD CPEs, 1 resolved through the entry, 1 unresolved.
	if st.Published != 5 || st.Resolved != 4 || st.ResolvedByEntry != 1 || st.Unresolved != 1 ||
		len(st.TopUnresolved) != 1 || st.TopUnresolved[0].Name != "a:nobody_knows:mystery_box" {
		t.Errorf("stats %+v", st)
	}

	// A rejected record leaves the state.
	rej := cve5.Record{Vuln: model.Vuln{ID: "CVE-2026-30002", Status: cve5.StatusRejected}, Rejected: true}
	if _, err := Build(context.Background(), s, &fakePager{}, Options{Now: now.Add(time.Hour), CVEList: &fakeList{changes: []cve5.Record{rej}},
		AliasState: state, AllowMassChange: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := state["CVE-2026-30002"]; ok {
		t.Error("rejected CVE still in the state")
	}
}
