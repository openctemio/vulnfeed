package model

import (
	"strings"
	"testing"
)

func TestValidVersion(t *testing.T) {
	for _, v := range []string{"1", "1.18.0", "v2.0", "8.2p1", "1.1.1w", "2.4.58-rc1", "r24", "R30p1", "1_2_3", "2.0~rc1", strings.Repeat("1.", 15) + "1"} {
		if !ValidVersion(v) {
			t.Errorf("%q refused", v)
		}
	}
	for _, v := range []string{"", " 1", "latest", "rr24", "-1", "1.0 (Ubuntu)", "1:2.3", "1/2", strings.Repeat("1", 65),
		strings.Repeat("1.", 17) + "1", "1." + strings.Repeat("9", 19), "1\n"} {
		if ValidVersion(v) {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestValidProductKey(t *testing.T) {
	for k, want := range map[string]bool{
		"cpe:a:f5:nginx": true, "cpe:o:microsoft:windows": true, "cpe:a:joomla:joomla!": true,
		"cpe:a:f5": false, "cpe:x:f5:nginx": false, "cpe:a:*:nginx": false, "cpe:a:f5:-": false,
		"cpe:a:F5:nginx": false, "cpe:a:f5:ng:inx": false, "nginx": false, "cpe:a:f5:ngi\x01nx": false,
	} {
		if ValidProductKey(k) != want {
			t.Errorf("%q: %v", k, !want)
		}
	}
}

func okRange() Range {
	return Range{Vuln: "CVE-2021-23017", Product: "cpe:a:f5:nginx", Scheme: "generic", Source: "nvd", End: "1.20.1"}
}

func TestRangeValidate(t *testing.T) {
	if err := okRange().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Range){
		"bad vuln":         func(r *Range) { r.Vuln = "GHSA-1" },
		"wildcard product": func(r *Range) { r.Product = "cpe:a:*:*" },
		"unknown scheme":   func(r *Range) { r.Scheme = "semver" },
		"unknown source":   func(r *Range) { r.Source = "blog" },
		"bad bound":        func(r *Range) { r.End = "n/a" },
		"exact and bound":  func(r *Range) { r.Exact = "1.0" },
		"start_incl alone": func(r *Range) { r.StartIncl = true },
		"end_incl alone":   func(r *Range) { r.End, r.EndIncl = "", true },
		"upper edition":    func(r *Range) { r.Edition = "Community" },
		"long target":      func(r *Range) { r.Target = strings.Repeat("x", 65) },
		"bad condition":    func(r *Range) { r.Condition = "cpe:a:*:linux" },
	} {
		r := okRange()
		mut(&r)
		if r.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVulnAndProductValidate(t *testing.T) {
	v := Vuln{ID: "CVE-2021-23017", Severity: "high", CWEs: []string{"CWE-193"}, CVSS: &CVSS{Version: "3.1", Score: 7.7, Vector: "CVSS:3.1/AV:N"}}
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Vuln){
		"id":          func(v *Vuln) { v.ID = "CVE-21-1" },
		"severity":    func(v *Vuln) { v.Severity = "urgent" },
		"cwe":         func(v *Vuln) { v.CWEs = []string{"NVD-CWE-Other"} },
		"score":       func(v *Vuln) { v.CVSS = &CVSS{Score: 11} },
		"vector":      func(v *Vuln) { v.CVSS = &CVSS{Score: 1, Vector: "<script>"} },
		"description": func(v *Vuln) { v.Description = strings.Repeat("x", 4001) },
		"newline":     func(v *Vuln) { v.Description = "a\nb" },
	} {
		w := v
		mut(&w)
		if w.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := Product{Key: "cpe:a:f5:nginx", Part: "a", Vendor: "f5", Name: "nginx", CPEVendor: "f5", CPEProduct: "nginx"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.CPEVendor = "other"
	if p.Validate() == nil {
		t.Fatal("key/fields mismatch accepted")
	}
}

func FuzzValidVersion(f *testing.F) {
	for _, s := range []string{"1.2.3", "r24", "latest", "8.2p1", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidVersion(s) && (len(s) > MaxVersionLen || strings.ContainsAny(s, " /:\n\x00")) {
			t.Fatalf("accepted %q", s)
		}
	})
}
