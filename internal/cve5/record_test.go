package cve5

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/vulnfeed/internal/model"
)

func load(t *testing.T, name string) Record {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok, err := Decode(bytes.NewReader(b))
	if err != nil || !ok {
		t.Fatalf("%s: ok %v err %v", name, ok, err)
	}
	return rec
}

func TestPublishedRecord(t *testing.T) {
	rec := load(t, "published.json")
	v := rec.Vuln
	if v.ID != "CVE-2026-10001" || v.Status != StatusPublished || rec.Rejected {
		t.Fatalf("vuln %+v", v)
	}
	if v.Description != "A heap overflow in the request parser allows remote code execution." {
		t.Fatalf("description not sanitised: %q", v.Description)
	}
	if v.CVSS == nil || v.CVSS.Version != "4.0" || v.CVSS.Score != 9.3 || v.Severity != "critical" {
		t.Fatalf("cvss %+v %s", v.CVSS, v.Severity)
	}
	if len(v.CWEs) != 1 || v.CWEs[0] != "CWE-122" {
		t.Fatalf("cwes %v", v.CWEs)
	}
	if v.Published == nil || v.Modified == nil || v.Published.Format("2006-01-02") != "2026-10-01" {
		t.Fatalf("dates %v %v", v.Published, v.Modified)
	}
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		`cpe:a:example_corp:web_server start=2.0 incl end=2.4.7`: true,
		`cpe:a:example_corp:web_server start= end=1.9.9 incl`:    true,
		`cpe:a:example_corp:web_server exact=3.1.0`:              true,
		`cpe:a:example_corp:web_server start=5.0 incl end=`:      true,
		`cpe:a:example:agent start=1.0 incl end=1.2`:             true,
		`cpe:h:example:appliance exact=7.1`:                      true,
	}
	got := map[string]bool{}
	for _, r := range rec.Ranges {
		if r.Source != "cve5" || r.Scheme != "generic" {
			t.Fatalf("range %+v", r)
		}
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
		if _, ok := rec.Products[r.Product]; !ok {
			t.Fatalf("product %s missing", r.Product)
		}
		got[describe(r)] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing range %s", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("unexpected range %s (a statement that must be dropped was widened)", k)
		}
	}
	for _, p := range rec.Products {
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.References) != 1 || rec.References[0].URL != "https://example.com/advisory/1" || rec.References[0].Tags[0] != "vendor-advisory" {
		t.Fatalf("references %+v", rec.References)
	}
}

// The CNA's affected list and the ADP containers are kept in full, not
// only what becomes a range.
func TestAffectedAndADPKept(t *testing.T) {
	rec := load(t, "published.json")
	if len(rec.Affected) != 5 {
		t.Fatalf("affected %d", len(rec.Affected))
	}
	ws := rec.Affected[0]
	if ws.Vendor != "Example Corp" || ws.Product != "Web Server" || ws.DefaultStatus != "unaffected" || len(ws.Versions) != 10 {
		t.Fatalf("web server %+v", ws)
	}
	if v := ws.Versions[7]; len(v.Changes) != 1 || v.Changes[0].At != "4.1" || v.Changes[0].Status != "unaffected" {
		t.Fatalf("changes %+v", v)
	}
	if v := ws.Versions[5]; v.VersionType != "git" || v.LessThan != "1.5" {
		t.Fatalf("git statement %+v", v)
	}
	pkg := rec.Affected[4]
	if pkg.PackageName != "left-pad" || pkg.CollectionURL != "https://registry.npmjs.org" {
		t.Fatalf("package %+v", pkg)
	}
	if len(rec.Affected[1].CPEs) != 2 {
		t.Fatalf("cpes %+v", rec.Affected[1].CPEs)
	}
	if len(rec.ADP) != 1 {
		t.Fatalf("adp %+v", rec.ADP)
	}
	a := rec.ADP[0]
	if a.ShortName != "CISA-ADP" || a.CVSS == nil || a.CVSS.Score != 8.8 || a.Severity != "high" || a.CWEs[0] != "CWE-787" {
		t.Fatalf("adp %+v", a)
	}
	if a.SSVC == nil || a.SSVC.Exploitation != "poc" || a.SSVC.Automatable != "yes" || a.SSVC.TechnicalImpact != "total" {
		t.Fatalf("ssvc %+v", a.SSVC)
	}
	if len(a.Affected) != 1 || a.Affected[0].CPEs[0] != "cpe:2.3:a:example_corp:web_server:*:*:*:*:*:*:*:*" {
		t.Fatalf("adp affected %+v", a.Affected)
	}
	// ADP data does not change the CNA's fields.
	if rec.Vuln.CVSS.Score != 9.3 || rec.Vuln.CWEs[0] != "CWE-122" {
		t.Fatalf("CNA fields overwritten: %+v", rec.Vuln)
	}
}

func describe(r model.Range) string {
	if r.Exact != "" {
		return r.Product + " exact=" + r.Exact
	}
	s := r.Product + " start=" + r.Start
	if r.StartIncl {
		s += " incl"
	}
	s += " end=" + r.End
	if r.EndIncl {
		s += " incl"
	}
	return s
}

func TestRejectedRecord(t *testing.T) {
	rec := load(t, "rejected.json")
	if !rec.Rejected || rec.Vuln.Status != StatusRejected || len(rec.Ranges) != 0 {
		t.Fatalf("%+v", rec)
	}
	if !strings.Contains(rec.Vuln.Description, "withdrawn") || rec.Vuln.Modified == nil {
		t.Fatalf("%+v", rec.Vuln)
	}
}

func TestUpdatedRecord(t *testing.T) {
	rec := load(t, "updated.json")
	if !strings.HasSuffix(rec.Vuln.Description, "(updated).") || len(rec.Ranges) != 1 || rec.Ranges[0].End != "2.4.8" {
		t.Fatalf("%+v", rec)
	}
}

func TestDecodeRefuses(t *testing.T) {
	cases := map[string]string{
		"not json":     `{"dataType":`,
		"not a record": `{"dataType":"CVE_RECORD","dataVersion":"4.0","cveMetadata":{"cveId":"CVE-2026-1000","state":"PUBLISHED"}}`,
		"bad id":       `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-26-1","state":"PUBLISHED"}}`,
		"wrong type":   `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1000","state":"PUBLISHED"},"containers":{"cna":{"affected":"x"}}}`,
		"oversized":    `{"dataType":"CVE_RECORD","dataVersion":"5.1","pad":"` + strings.Repeat("a", MaxRecordBytes) + `"}`,
	}
	for name, in := range cases {
		if _, ok, err := Decode(strings.NewReader(in)); err == nil || ok {
			t.Errorf("%s: accepted", name)
		}
	}
	// A reserved id has no record to carry: skipped without an error.
	if _, ok, err := Decode(strings.NewReader(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1000","state":"RESERVED"}}`)); ok || err != nil {
		t.Errorf("reserved: ok %v err %v", ok, err)
	}
	// An out-of-range score is dropped, not carried.
	rec, ok, err := Decode(strings.NewReader(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1000","state":"PUBLISHED"},
		"containers":{"cna":{"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":99,"vectorString":"CVSS:3.1/AV:N"}}]}}}`))
	if err != nil || !ok || rec.Vuln.CVSS != nil {
		t.Errorf("score: %+v %v %v", rec.Vuln.CVSS, ok, err)
	}
}

func TestUntrustedTextIsBounded(t *testing.T) {
	long := strings.Repeat("x​<script>", 2000)
	in := `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1000","state":"PUBLISHED"},
		"containers":{"cna":{"descriptions":[{"lang":"en","value":"` + long + `\u0000\r\n"}],
		"affected":[{"vendor":"` + strings.Repeat("v", 600) + `","product":"p","versions":[{"version":"1.0","status":"affected"}]},
		            {"vendor":"Acme‮","product":"Tool\u0000","versions":[{"version":"1.0","status":"affected"}]}]}}}`
	rec, ok, err := Decode(strings.NewReader(in))
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	d := rec.Vuln.Description
	if len(d) > model.MaxDescriptionLen || strings.ContainsAny(d, "\x00\r\n​") {
		t.Fatalf("description %d bytes", len(d))
	}
	if err := rec.Vuln.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(rec.Ranges) != 1 || rec.Ranges[0].Product != "cpe:a:acme:tool" {
		t.Fatalf("ranges %+v", rec.Ranges)
	}
}

func TestTooManyRanges(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1000","state":"PUBLISHED"},"containers":{"cna":{"affected":[{"vendor":"a","product":"b","versions":[`)
	for i := 0; i < MaxVersionsPerItem; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"version":"1.1.` + strconv.Itoa(i) + `","status":"affected"}`)
	}
	b.WriteString(`]},{"vendor":"a","product":"c","versions":[{"version":"1.0","status":"affected"},{"version":"2.0","status":"affected"}]}]}}}`)
	rec, ok, err := Decode(strings.NewReader(b.String()))
	if err != nil || !ok || !rec.TooManyRanges || len(rec.Ranges) != 0 {
		t.Fatalf("ok %v err %v too many %v ranges %d", ok, err, rec.TooManyRanges, len(rec.Ranges))
	}
}

func FuzzDecode(f *testing.F) {
	for _, n := range []string{"published.json", "rejected.json", "updated.json"} {
		b, _ := os.ReadFile("testdata/" + n)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		rec, ok, err := Decode(bytes.NewReader(b))
		if err != nil || !ok {
			return
		}
		if err := rec.Vuln.Validate(); err != nil {
			t.Fatalf("invalid vuln: %v", err)
		}
		for _, r := range rec.Ranges {
			if err := r.Validate(); err != nil {
				t.Fatalf("invalid range: %v", err)
			}
			if r.Exact == "" && r.Start == "" && r.End == "" {
				t.Fatalf("range covers every version: %+v", r)
			}
		}
		for _, p := range rec.Products {
			if err := p.Validate(); err != nil {
				t.Fatalf("invalid product: %v", err)
			}
		}
	})
}

func TestStatementsNeverWidenToAllVersions(t *testing.T) {
	rec := func(versions string) Record {
		t.Helper()
		doc := `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1001","state":"PUBLISHED"},` +
			`"containers":{"cna":{"affected":[{"vendor":"acme","product":"tool","defaultStatus":"affected","versions":[` + versions + `]}]}}}`
		r, ok, err := Decode(strings.NewReader(doc))
		if err != nil || !ok {
			t.Fatalf("ok %v err %v", ok, err)
		}
		return r
	}
	for name, versions := range map[string]string{
		"zero to star":       `{"version":"0","lessThan":"*","status":"affected"}`,
		"star to star":       `{"version":"*","lessThanOrEqual":"*","status":"affected","versionType":"semver"}`,
		"empty to star":      `{"version":"","lessThan":"*","status":"affected"}`,
		"default status":     `{"version":"2.0","status":"unaffected"}`,
		"open with carveout": `{"version":"1.0","lessThan":"*","status":"affected"},{"version":"1.4.2","lessThanOrEqual":"1.4.9","status":"unaffected"}`,
	} {
		if r := rec(versions); len(r.Ranges) != 0 {
			t.Errorf("%s: ranges %+v", name, r.Ranges)
		}
	}
	// Bounded ranges stay, and an open-ended one without carve-outs is what
	// the CNA states.
	r := rec(`{"version":"0","lessThan":"1.2","status":"affected"},{"version":"1.2","status":"unaffected"}`)
	if len(r.Ranges) != 1 || r.Ranges[0].End != "1.2" || r.Ranges[0].Start != "" {
		t.Fatalf("bounded: %+v", r.Ranges)
	}
	r = rec(`{"version":"3.0","lessThan":"*","status":"affected"}`)
	if len(r.Ranges) != 1 || r.Ranges[0].Start != "3.0" || r.Ranges[0].End != "" {
		t.Fatalf("open-ended: %+v", r.Ranges)
	}
}

// The "other" metric's content is free-form: a numeric SSVC version (and
// non-string option values) must not make the whole record undecodable.
func TestOtherMetricVersionNumberOrString(t *testing.T) {
	for _, c := range []struct{ version, want string }{{`"2.0.3"`, "2.0.3"}, {`2`, "2"}, {`2.0`, "2.0"}, {`{"x":1}`, ""}, {`null`, ""}} {
		raw := `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0001","state":"PUBLISHED",
			"datePublished":"2026-01-02T00:00:00Z","dateUpdated":"2026-01-02T00:00:00Z"},
			"containers":{"cna":{"descriptions":[{"lang":"en","value":"x"}],"affected":[{"vendor":"Example","product":"Widget","versions":[{"version":"1.0","status":"affected"}]}]},
			"adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"other":{"type":"ssvc","content":{"version":` + c.version + `,
			"options":[{"Exploitation":"none"},{"Automatable":false},{"Technical Impact":"partial"}]}}}]}]}}`
		rec, ok, err := Decode(strings.NewReader(raw))
		if err != nil || !ok {
			t.Fatalf("version %s: ok %v err %v", c.version, ok, err)
		}
		if len(rec.ADP) != 1 || rec.ADP[0].SSVC == nil {
			t.Fatalf("version %s: adp %+v", c.version, rec.ADP)
		}
		s := rec.ADP[0].SSVC
		if s.Version != c.want || s.Exploitation != "none" || s.Automatable != "false" || s.TechnicalImpact != "partial" {
			t.Errorf("version %s: ssvc %+v", c.version, s)
		}
	}
}
