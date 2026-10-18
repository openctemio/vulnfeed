package collect

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/vulnfeed/internal/bundle"
	"github.com/openctemio/vulnfeed/internal/cve5"
	"github.com/openctemio/vulnfeed/internal/dsse"
	"github.com/openctemio/vulnfeed/internal/model"
	"github.com/openctemio/vulnfeed/internal/nvd"
)

func fixture(t *testing.T, name string) cve5.Record {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "cve5", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	r, ok, err := cve5.Decode(bytes.NewReader(b))
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	return r
}

// fakeList serves CVE List records: the baseline once, then the changes.
type fakeList struct {
	baseline  []cve5.Record
	changes   []cve5.Record
	asOf      time.Time
	tooMany   bool
	baselines int
	windows   [][2]time.Time
}

func (f *fakeList) Changed(_ context.Context, from, to time.Time, fn func(cve5.Record)) error {
	f.windows = append(f.windows, [2]time.Time{from, to})
	if f.tooMany {
		f.tooMany = false
		return cve5.ErrTooManyChanges
	}
	for _, r := range f.changes {
		fn(r)
	}
	return nil
}

func (f *fakeList) Baseline(_ context.Context, fn func(cve5.Record)) (time.Time, error) {
	f.baselines++
	for _, r := range f.baseline {
		fn(r)
	}
	return f.asOf, nil
}

func nvdRec(id string, score float64, end string) nvd.Record {
	r := rec(id, end)
	r.Vuln.Description = "NVD copy"
	if score > 0 {
		r.Vuln.CVSS, r.Vuln.Severity = &model.CVSS{Version: "3.1", Score: score, Vector: "CVSS:3.1/AV:N"}, "high"
		r.Vuln.CWEs = []string{"CWE-79"}
	}
	return r
}

const id = "CVE-2026-10001"

func TestPrecedenceNVDRangesAndScoreWin(t *testing.T) {
	now := time.Date(2026, 10, 9, 2, 0, 0, 0, time.UTC)
	list := &fakeList{baseline: []cve5.Record{fixture(t, "published.json")}, asOf: now.Truncate(24 * time.Hour)}
	p := &fakePager{pages: [][]nvd.Record{{nvdRec(id, 7.5, "2")}}}
	s, err := Build(context.Background(), nil, p, Options{Now: now, CVEList: list})
	if err != nil {
		t.Fatal(err)
	}
	v := s.Vulns[id]
	// NVD has CPE ranges and a score: they win; the CNA text and date win.
	if !rangesFrom(s.Ranges[id], "nvd") || len(s.Ranges[id]) != 1 {
		t.Fatalf("ranges %+v", s.Ranges[id])
	}
	if v.CVSS.Score != 7.5 || v.CWEs[0] != "CWE-79" {
		t.Fatalf("score %+v cwes %v", v.CVSS, v.CWEs)
	}
	if v.Description == "NVD copy" || v.Published == nil {
		t.Fatalf("description %q", v.Description)
	}
	if list.baselines != 1 || len(list.windows) != 1 || !list.windows[0][0].Equal(list.asOf.Add(-cursorOverlap)) {
		t.Fatalf("baseline %d windows %v", list.baselines, list.windows)
	}
	if !s.SourceAsOf("cve5").Equal(now) {
		t.Fatal("cve5 cursor")
	}
}

func TestPrecedenceCNAFillsWhereNVDHasNone(t *testing.T) {
	now := time.Date(2026, 10, 9, 2, 0, 0, 0, time.UTC)
	list := &fakeList{baseline: []cve5.Record{fixture(t, "published.json")}, asOf: now}
	// NVD knows the CVE but has neither ranges nor a score (not analysed).
	p := &fakePager{pages: [][]nvd.Record{{nvdRec(id, 0, "")}}}
	s, err := Build(context.Background(), nil, p, Options{Now: now, CVEList: list})
	if err != nil {
		t.Fatal(err)
	}
	if !rangesFrom(s.Ranges[id], "cve5") || len(s.Ranges[id]) != 6 {
		t.Fatalf("ranges %+v", s.Ranges[id])
	}
	if v := s.Vulns[id]; v.CVSS == nil || v.CVSS.Version != "4.0" || v.CWEs[0] != "CWE-122" {
		t.Fatalf("CNA score and CWE not used: %+v", v)
	}

	// Next build: NVD changes the record, still without ranges or score:
	// the CNA ranges and score stay. Then NVD adds CPE ranges: they
	// replace the CNA's.
	p2 := &fakePager{pages: [][]nvd.Record{{nvdRec(id, 0, "")}}}
	s2, err := Build(context.Background(), s, p2, Options{Now: now.Add(time.Hour), CVEList: &fakeList{}})
	if err != nil {
		t.Fatal(err)
	}
	if !rangesFrom(s2.Ranges[id], "cve5") || s2.Vulns[id].CVSS == nil {
		t.Fatalf("NVD without ranges dropped the CNA's: %+v", s2.Ranges[id])
	}
	p3 := &fakePager{pages: [][]nvd.Record{{nvdRec(id, 8.1, "3")}}}
	s3, err := Build(context.Background(), s2, p3, Options{Now: now.Add(2 * time.Hour), CVEList: &fakeList{changes: []cve5.Record{fixture(t, "updated.json")}}, AllowMassChange: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rangesFrom(s3.Ranges[id], "nvd") || len(s3.Ranges[id]) != 1 || s3.Vulns[id].CVSS.Score != 8.1 {
		t.Fatalf("NVD ranges did not win: %+v", s3.Ranges[id])
	}
	if d := s3.Vulns[id].Description; d == "NVD copy" {
		t.Fatal("CVE List description lost to NVD's copy in the same build")
	}
}

func TestCVEListUpdateAndRejection(t *testing.T) {
	now := time.Date(2026, 10, 9, 2, 0, 0, 0, time.UTC)
	s, err := Build(context.Background(), nil, &fakePager{}, Options{Now: now,
		CVEList: &fakeList{baseline: []cve5.Record{fixture(t, "published.json")}, asOf: now}})
	if err != nil {
		t.Fatal(err)
	}
	// An update replaces the CNA ranges.
	s2, err := Build(context.Background(), s, &fakePager{}, Options{Now: now.Add(time.Hour), AllowMassChange: true,
		CVEList: &fakeList{changes: []cve5.Record{fixture(t, "updated.json")}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Ranges[id]) != 1 || s2.Ranges[id][0].End != "2.4.8" || !s2.Vulns[id].Modified.After(*s.Vulns[id].Modified) {
		t.Fatalf("update %+v", s2.Ranges[id])
	}
	// A rejection keeps the record without ranges; NVD still being
	// behind (published, with ranges, in the same build) does not undo it.
	s3, err := Build(context.Background(), s2, &fakePager{pages: [][]nvd.Record{{nvdRec(id, 5, "9")}}}, Options{Now: now.Add(2 * time.Hour), AllowMassChange: true,
		CVEList: &fakeList{changes: []cve5.Record{fixture(t, "rejected.json")}}})
	if err != nil {
		t.Fatal(err)
	}
	if v := s3.Vulns[id]; v.Status != cve5.StatusRejected || len(s3.Ranges[id]) != 0 {
		t.Fatalf("rejection %+v %+v", v, s3.Ranges[id])
	}
	// A CVE first seen rejected is not added.
	if _, ok := s3.Vulns["CVE-2026-10003"]; ok {
		t.Fatal("unknown rejected CVE added")
	}
}

func TestTooManyChangesFallsBackToBaseline(t *testing.T) {
	now := time.Date(2026, 10, 9, 2, 0, 0, 0, time.UTC)
	prev := bundle.NewSnapshot()
	prev.Sources = []bundle.Source{{Name: "nvd", AsOf: now.Add(-time.Hour)}, {Name: "cve5", AsOf: now.Add(-time.Hour)}}
	list := &fakeList{tooMany: true, baseline: []cve5.Record{fixture(t, "published.json")}, asOf: now.Truncate(24 * time.Hour)}
	s, err := Build(context.Background(), prev, &fakePager{}, Options{Now: now, CVEList: list})
	if err != nil {
		t.Fatal(err)
	}
	if list.baselines != 1 || len(list.windows) != 2 || len(s.Ranges[id]) != 6 {
		t.Fatalf("baselines %d windows %d ranges %d", list.baselines, len(list.windows), len(s.Ranges[id]))
	}
}

func TestBuildWithoutCVEListKeepsItsCursor(t *testing.T) {
	now := time.Date(2026, 10, 9, 2, 0, 0, 0, time.UTC)
	prev := bundle.NewSnapshot()
	prev.Sources = []bundle.Source{{Name: "nvd", AsOf: now.Add(-time.Hour)}, {Name: "cve5", AsOf: now.Add(-time.Hour)}}
	s, err := Build(context.Background(), prev, &fakePager{}, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if !s.SourceAsOf("cve5").Equal(now.Add(-time.Hour)) {
		t.Fatal("cursor lost")
	}
}

// Re-reading the same changes (the cursor overlaps the previous window)
// changes nothing: the delta is empty and the files are byte-identical.
func TestDeltaIdempotent(t *testing.T) {
	now := time.Date(2026, 10, 9, 2, 0, 0, 0, time.UTC)
	changes := []cve5.Record{fixture(t, "published.json"), fixture(t, "updated.json")}
	first, err := Build(context.Background(), nil, &fakePager{pages: [][]nvd.Record{{rec("CVE-2021-0001", "2")}}},
		Options{Now: now, CVEList: &fakeList{baseline: changes, asOf: now}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(context.Background(), first, &fakePager{pages: [][]nvd.Record{{rec("CVE-2021-0001", "2")}}},
		Options{Now: now, CVEList: &fakeList{changes: changes}})
	if err != nil {
		t.Fatal(err)
	}
	if ids, added, removed := bundle.Changed(first, second); len(ids) != 0 || added != 0 || removed != 0 {
		t.Fatalf("replayed changes produced a delta: %v +%d -%d", ids, added, removed)
	}
	d1, d2 := t.TempDir(), t.TempDir()
	if _, _, _, err := bundle.Write(d1, nil, first, bundle.WriteOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	second.Sequence = first.Sequence
	if _, _, _, err := bundle.Write(d2, nil, second, bundle.WriteOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	for _, rf := range []string{"products", "vulns", "ranges"} {
		a, _ := os.ReadFile(filepath.Join(d1, bundle.FileName(bundle.KindSnapshot, rf)))
		b, _ := os.ReadFile(filepath.Join(d2, bundle.FileName(bundle.KindSnapshot, rf)))
		if !bytes.Equal(a, b) {
			t.Fatalf("%s differs", rf)
		}
	}
}

// A bundle carrying CVE List records signs and verifies as the platform
// verifies it, including the per-record re-validation; a tampered record
// file is refused.
func TestSignedBundleWithCVEListVerifies(t *testing.T) {
	now := time.Now().UTC()
	rootPub, root, _ := ed25519.GenerateKey(nil)
	pub, priv, _ := ed25519.GenerateKey(nil)
	ks, err := dsse.SignKeySet(root, 1, now.Add(-time.Hour), 90*24*time.Hour, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	first, err := Build(context.Background(), nil, &fakePager{pages: [][]nvd.Record{{rec("CVE-2021-0001", "2")}}},
		Options{Now: now, CVEList: &fakeList{baseline: []cve5.Record{fixture(t, "published.json")}, asOf: now}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(context.Background(), first, &fakePager{}, Options{Now: now.Add(time.Hour), AllowMassChange: true,
		CVEList: &fakeList{changes: []cve5.Record{fixture(t, "updated.json")}}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_, delta, _, err := bundle.Write(dir, first, second, bundle.WriteOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if delta == nil || delta.Stats.Vulns != 1 {
		t.Fatalf("delta %+v", delta)
	}
	if err := bundle.Sign(dir, priv, ks, dsse.KeyID(rootPub), now); err != nil {
		t.Fatal(err)
	}
	v, err := bundle.VerifyDir(dir, bundle.VerifyOptions{PinnedRoot: dsse.KeyID(rootPub), AppliedSeq: first.Sequence, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyV2(dir, v.KeySet, now); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, s := range v.Snapshot.Sources {
		names[s.Name] = s.Terms != "" && s.Attribution != ""
	}
	if !names["nvd"] || !names["cve5"] {
		t.Fatalf("sources %+v", v.Snapshot.Sources)
	}
	// Signed by a key outside the key set: refused.
	_, other, _ := ed25519.GenerateKey(nil)
	dir2 := t.TempDir()
	if _, _, _, err := bundle.Write(dir2, first, second, bundle.WriteOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Sign(dir2, other, ks, dsse.KeyID(rootPub), now); err == nil {
		t.Fatal("signed with a key outside the key set")
	}
	// A record file changed after signing: refused.
	f := filepath.Join(dir, bundle.FileName(bundle.KindDelta, "ranges"))
	b, _ := os.ReadFile(f)
	b[len(b)/2] ^= 0xff
	_ = os.WriteFile(f, b, 0o644)
	if _, err := bundle.VerifyDir(dir, bundle.VerifyOptions{PinnedRoot: dsse.KeyID(rootPub), AppliedSeq: first.Sequence, Now: now}); err == nil {
		t.Fatal("tampered delta accepted")
	}
}
