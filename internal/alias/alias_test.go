package alias

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestKeys(t *testing.T) {
	cases := []struct {
		fn       func(string) string
		in, want string
	}{
		{VendorKey, "Google Inc.", "google"},
		{VendorKey, "Microsoft Corporation", "microsoft"},
		{VendorKey, "Foo Co., Ltd.", "foo"},
		{VendorKey, "Siemens AG", "siemens"},
		{VendorKey, "Inc", "inc"},
		{VendorKey, "n/a", ""},
		{VendorKey, "N/A", ""},
		{VendorKey, "  ", ""},
		{VendorKey, "Evil‮Corp", "evilcorp"},
		{VendorKey, strings.Repeat("v", 200), ""},
		{ProductKey, "Windows Server 2019 (Server Core installation)", "windows_server_2019"},
		{ProductKey, "Exchange Server [CU 12]", "exchange_server"},
		{ProductKey, "(beta)", "beta"},
		{ProductKey, "Apache HTTP Server", "apache_http_server"},
		{ProductKey, "unspecified", ""},
	}
	for _, c := range cases {
		if got := c.fn(c.in); got != c.want {
			t.Errorf("%q: got %q want %q", c.in, got, c.want)
		}
	}
}

func TestObserve(t *testing.T) {
	o := Observe("CVE-2026-0001",
		[]Item{{Vendor: "Google Inc.", Product: "Chrome", CPEs: []string{"a:google:chrome"}},
			{Vendor: "Acme Corp", Product: "Widget"}},
		[]Item{{Vendor: "acme", Product: "widget", CPEs: []string{"a:acme_software:widget"}}},
		nil)
	if !reflect.DeepEqual(o.Names, []string{"a:acme:widget"}) {
		t.Errorf("names %v", o.Names)
	}
	want := [][2]string{{"a:acme:widget", "a:acme_software:widget"}}
	if !reflect.DeepEqual(o.Pairs, want) {
		t.Errorf("pairs %v", o.Pairs)
	}
	// The record's own CPE equals its name: no pair, no name.
	o = Observe("CVE-2026-0002", []Item{{Vendor: "Google", Product: "Chrome", CPEs: []string{"a:google:chrome"}}}, nil, nil)
	if len(o.Pairs) != 0 || len(o.Names) != 0 || len(o.CPEs) != 1 {
		t.Errorf("%+v", o)
	}
	// One unnamed product and one NVD product pair.
	o = Observe("CVE-2026-0003", []Item{{Vendor: "Linux", Product: "Linux"}}, nil, []string{"o:linux:linux_kernel"})
	if !reflect.DeepEqual(o.Pairs, [][2]string{{"a:linux:linux", "o:linux:linux_kernel"}}) {
		t.Errorf("pairs %v", o.Pairs)
	}
	// Two NVD products are ambiguous: no pair.
	o = Observe("CVE-2026-0004", []Item{{Vendor: "X", Product: "Y"}}, nil, []string{"a:x:y1", "a:x:y2"})
	if len(o.Pairs) != 0 {
		t.Errorf("pairs %v", o.Pairs)
	}
	// Explicitly unresolvable records.
	if o := Observe("CVE-2026-0005", []Item{{Vendor: "n/a", Product: "n/a"}}, nil, nil); o.Missing != MissingNoProduct {
		t.Errorf("missing %q", o.Missing)
	}
	if o := Observe("CVE-2026-0006", []Item{{PackageName: "lodash"}}, nil, nil); o.Missing != MissingPackage {
		t.Errorf("missing %q", o.Missing)
	}
	// Malformed CPE values are dropped, never kept.
	o = Observe("CVE-2026-0007", []Item{{Vendor: "a", Product: "b", CPEs: []string{"a:*:b", "a:X:b", "a:x", "a:x:b\x00"}}}, nil, nil)
	if len(o.CPEs) != 0 || len(o.Pairs) != 0 {
		t.Errorf("%+v", o)
	}
	// Caps.
	var many []Item
	for i := 0; i < 200; i++ {
		many = append(many, Item{Vendor: "v", Product: fmt.Sprintf("p%d", i)})
	}
	if o := Observe("CVE-2026-0008", many, nil, nil); len(o.Names) != MaxPerObs {
		t.Errorf("names %d", len(o.Names))
	}
}

func state(obs ...Obs) map[string]Obs {
	m := map[string]Obs{}
	for _, o := range obs {
		m[o.ID] = o
	}
	return m
}

func pair(id, name, cpe string) Obs {
	return Obs{ID: id, Names: []string{name}, Pairs: [][2]string{{name, cpe}}}
}

func TestBuildLearnsWithThresholds(t *testing.T) {
	s := state(
		// "google inc" names three CVEs whose CPE is google:chrome.
		pair("CVE-1", "a:goog:chrome", "a:google:chrome"),
		pair("CVE-2", "a:goog:chrome", "a:google:chrome"),
		pair("CVE-3", "a:goog:chrome", "a:google:chrome"),
		// Two pairs only: not enough evidence.
		pair("CVE-4", "a:rare:thing", "a:rare_inc:thing"),
		pair("CVE-5", "a:rare:thing", "a:rare_inc:thing"),
		// Disagreement below 90%: three of four.
		pair("CVE-6", "a:mixed:p", "a:one:p"),
		pair("CVE-7", "a:mixed:p", "a:one:p"),
		pair("CVE-8", "a:mixed:p", "a:one:p"),
		pair("CVE-9", "a:mixed:p", "a:two:p"),
		// Unresolvable and unresolved.
		Obs{ID: "CVE-10", Missing: MissingNoProduct},
		Obs{ID: "CVE-11", Names: []string{"a:nobody:nothing"}},
		// Has a CPE: always resolved.
		Obs{ID: "CVE-12", CPEs: []string{"a:google:chrome"}},
		// A CNA name that is already a known CPE product.
		Obs{ID: "CVE-13", Names: []string{"a:google:chrome"}},
		// The kernel: curated.
		Obs{ID: "CVE-14", Names: []string{"a:linux:linux"}},
		// The same vendor:product known as an operating system.
		Obs{ID: "CVE-15", Names: []string{"a:fortinet:fortios"}},
	)
	d, err := Build(s, []string{"o:fortinet:fortios"})
	if err != nil {
		t.Fatal(err)
	}
	check := func(name, want, basis string) {
		t.Helper()
		got, b, ok := d.Resolve(name)
		if want == "" {
			if ok {
				t.Errorf("%s resolved to %s", name, got)
			}
			return
		}
		if !ok || got != want || b != basis {
			t.Errorf("%s: got %s (%s, %v), want %s (%s)", name, got, b, ok, want, basis)
		}
	}
	check("a:goog:chrome", "a:google:chrome", BasisLearned)
	check("a:rare:thing", "", "")
	check("a:mixed:p", "", "")
	check("a:linux:linux", "o:linux:linux_kernel", BasisCurated)
	check("a:google:chrome", "a:google:chrome", "")
	check("a:fortinet:fortios", "o:fortinet:fortios", BasisPart)
	entries := d.Entries(s)
	got := map[string]string{}
	for _, e := range entries {
		got[e.Value] = e.Target + "/" + e.Basis
	}
	if got["a:goog:chrome"] != "a:google:chrome/learned" || got["a:fortinet:fortios"] != "o:fortinet:fortios/part" {
		t.Errorf("entries %v", got)
	}
	if _, ok := got["a:google:chrome"]; ok {
		t.Error("a name that is already canonical needs no entry")
	}
	st := d.Coverage(s, len(entries))
	// Resolved: 1-3 (learned), 12 (CPE), 13 (as is), 14 (curated), 15 (part)
	// = 7; unresolvable: 10; unresolved: 4, 5, 6-9, 11 = 7.
	if st.Published != 15 || st.Resolved != 7 || st.Unresolvable != 1 || st.Unresolved != 7 || st.ResolvedByName != 6 || st.ResolvedByEntry != 5 {
		t.Errorf("stats %+v", st)
	}
	if st.TopUnresolved[0].Name != "a:mixed:p" || st.TopUnresolved[0].CVEs != 4 {
		t.Errorf("top %v", st.TopUnresolved)
	}
}

func TestVendorMapping(t *testing.T) {
	var obs []Obs
	for i := 0; i < 5; i++ {
		obs = append(obs, pair(fmt.Sprintf("CVE-%d", i), fmt.Sprintf("a:msft:p%d", i), fmt.Sprintf("a:microsoft:p%d", i)))
	}
	obs = append(obs, Obs{ID: "CVE-x", Names: []string{"a:msft:edge"}}, Obs{ID: "CVE-y", Names: []string{"a:msft:unknown"}})
	d, err := Build(state(obs...), []string{"a:microsoft:edge"})
	if err != nil {
		t.Fatal(err)
	}
	if got, b, ok := d.Resolve("a:msft:edge"); !ok || got != "a:microsoft:edge" || b != BasisVendor {
		t.Errorf("edge: %s %s %v", got, b, ok)
	}
	// A vendor mapping never invents a product nobody knows.
	if got, _, ok := d.Resolve("a:msft:unknown"); ok {
		t.Errorf("unknown resolved to %s", got)
	}
}

func TestCuratedFileIsValid(t *testing.T) {
	entries, vendors, err := Curated()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || len(vendors) == 0 {
		t.Fatal("empty curated file")
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if seen[e.Value] {
			t.Errorf("duplicate %s", e.Value)
		}
		seen[e.Value] = true
	}
}

// A learned mapping never overrides a curated one (alias poisoning: many
// advisories cannot repoint a reviewed name).
func TestCuratedWinsOverLearned(t *testing.T) {
	var obs []Obs
	for i := 0; i < 50; i++ {
		obs = append(obs, pair(fmt.Sprintf("CVE-%d", i), "a:nginx:nginx", "a:evil:nginx"))
	}
	d, err := Build(state(obs...), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, b, _ := d.Resolve("a:nginx:nginx"); got != "a:f5:nginx" || b != BasisCurated {
		t.Errorf("got %s %s", got, b)
	}
}

// The product name repeats the vendor or ends in a generic word: the
// shorter name resolves only when it is a known CPE product.
func TestVariants(t *testing.T) {
	d, err := Build(state(Obs{ID: "CVE-1", Names: []string{"a:microsoft:microsoft_edge"}}), []string{"a:microsoft:edge", "o:cisco:nx-os"})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"a:microsoft:microsoft_edge": "a:microsoft:edge", "a:cisco:cisco_nx-os_software": "o:cisco:nx-os",
		"a:cisco:nx-os_software": "o:cisco:nx-os", "a:microsoft:microsoft_unknown": ""} {
		got, b, ok := d.Resolve(name)
		if want == "" {
			if ok {
				t.Errorf("%s resolved to %s", name, got)
			}
			continue
		}
		if got != want || b != BasisVariant {
			t.Errorf("%s: %s %s", name, got, b)
		}
	}
	// A vendor with no CPE product at all is reported as a new vendor.
	st := d.Coverage(state(Obs{ID: "CVE-2", Names: []string{"a:brandnew:thing"}}, Obs{ID: "CVE-3", Names: []string{"a:microsoft:nothing"}}), 0)
	if st.Unresolved != 2 || st.NewVendor != 1 {
		t.Errorf("%+v", st)
	}
}
