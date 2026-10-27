package bundle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/vulnfeed/internal/intel"
)

func testKEV(n int, asOf time.Time) *intel.KEV {
	k := &intel.KEV{AsOf: asOf, Version: "2026.10.24"}
	for i := 0; i < n; i++ {
		k.Entries = append(k.Entries, intel.KEVEntry{CVE: fmt.Sprintf("CVE-2021-%05d", 10000+i), Vendor: "V", Product: "P",
			Name: "N", Description: "D", DateAdded: "2022-03-03", Ransomware: "Unknown", CWEs: []string{"CWE-79"}})
	}
	return k
}

func testEPSS(n int, asOf time.Time) *intel.EPSS {
	e := &intel.EPSS{AsOf: asOf, Version: "v2025.03.14"}
	for i := 0; i < n; i++ {
		e.Entries = append(e.Entries, intel.EPSSEntry{CVE: fmt.Sprintf("CVE-2020-%05d", i), Score: 0.25, Percentile: 0.5})
	}
	return e
}

func buildWithIntel(t *testing.T, k keys, seq uint64, in IntelInput, prevDir string, prev *IntelManifest) (string, *IntelManifest, []string) {
	t.Helper()
	dir := t.TempDir()
	if _, _, _, err := Write(dir, nil, snapshot(seq, "1.20.1"), WriteOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	m, notes, err := WriteIntel(dir, seq, time.Now(), in, prevDir, prev)
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(dir, k.priv, k.keyset, k.rootID, time.Now()); err != nil {
		t.Fatal(err)
	}
	return dir, m, notes
}

var (
	day1 = time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	day2 = day1.Add(24 * time.Hour)
)

func TestIntelRoundTrip(t *testing.T) {
	k := newKeys(t)
	dir, m, _ := buildWithIntel(t, k, 7, IntelInput{KEV: testKEV(600, day1), EPSS: testEPSS(1000, day1)}, "", nil)
	got, err := VerifyIntel(dir, verifiedKeySet(t, k), 7)
	if err != nil || got == nil {
		t.Fatal(got, err)
	}
	if f := got.Stream("kev").FetchedAt; f.IsZero() || f.After(time.Now().Add(time.Minute)) {
		t.Fatalf("fetched_at %v", f)
	}
	if len(got.Streams) != 2 || got.Streams[0].Name != "epss" || got.Streams[1].Name != "kev" || got.Sequence != 7 {
		t.Fatalf("%+v", got)
	}
	kev := got.Stream("kev")
	if kev.File.Records != 600 || !kev.AsOf.Equal(day1) || kev.Attribution == "" || m.Stream("kev").File.SHA256 != kev.File.SHA256 {
		t.Fatalf("%+v", kev)
	}
	ents, err := ReadKEV(dir, kev)
	if err != nil || len(ents) != 600 || ents[0].CVE != "CVE-2021-10000" {
		t.Fatal(len(ents), err)
	}
	sc, err := ReadEPSS(dir, got.Stream("epss"))
	if err != nil || len(sc) != 1000 || sc[1].Score != 0.25 {
		t.Fatal(len(sc), err)
	}
}

func TestIntelVerifyRefusals(t *testing.T) {
	k := newKeys(t)
	dir, _, _ := buildWithIntel(t, k, 7, IntelInput{KEV: testKEV(600, day1)}, "", nil)
	ks := verifiedKeySet(t, k)
	if _, err := VerifyIntel(dir, ks, 8); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Errorf("another release's sequence must be refused: %v", err)
	}
	// A tampered entries file fails its hash.
	f := filepath.Join(dir, IntelFileName("kev"))
	b, _ := os.ReadFile(f)
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(f, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIntel(dir, ks, 7); err == nil {
		t.Error("a tampered file must fail")
	}
	// Another key set does not verify the signature.
	other := newKeys(t)
	if _, err := VerifyIntel(dir, verifiedKeySet(t, other), 7); err == nil {
		t.Error("a signature of another key set must fail")
	}
	// A directory without the manifest is fine (old releases).
	if m, err := VerifyIntel(t.TempDir(), ks, 7); m != nil || err != nil {
		t.Errorf("no manifest: %v %v", m, err)
	}
}

func TestIntelCarriesForwardWhenFetchFailed(t *testing.T) {
	k := newKeys(t)
	d1, m1, _ := buildWithIntel(t, k, 7, IntelInput{KEV: testKEV(600, day1), EPSS: testEPSS(1000, day1)}, "", nil)
	// The next build could not read EPSS at all and read a newer KEV.
	d2, m2, notes := buildWithIntel(t, k, 8, IntelInput{KEV: testKEV(601, day2)}, d1, m1)
	got, err := VerifyIntel(d2, verifiedKeySet(t, k), 8)
	if err != nil {
		t.Fatal(err, notes)
	}
	if !got.Stream("kev").AsOf.Equal(day2) || got.Stream("kev").File.Records != 601 {
		t.Errorf("fresh KEV published: %+v", got.Stream("kev"))
	}
	e := got.Stream("epss")
	if e == nil || !e.AsOf.Equal(day1) || e.File.SHA256 != m1.Stream("epss").File.SHA256 || m2.Stream("epss") == nil {
		t.Fatalf("EPSS carried with its older data date: %+v", e)
	}
	if !e.FetchedAt.Equal(m1.Stream("epss").FetchedAt) || !got.Stream("kev").FetchedAt.After(e.FetchedAt.Add(-time.Second)) {
		t.Errorf("a carried stream keeps its fetch time: %v vs %v", e.FetchedAt, m1.Stream("epss").FetchedAt)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "epss: carried forward") {
		t.Errorf("notes %v", notes)
	}
}

func TestIntelNeverRollsBackOrShrinks(t *testing.T) {
	k := newKeys(t)
	d1, m1, _ := buildWithIntel(t, k, 7, IntelInput{KEV: testKEV(600, day2), EPSS: testEPSS(1000, day2)}, "", nil)
	// An older KEV copy and a truncated EPSS copy are both refused.
	d2, _, notes := buildWithIntel(t, k, 8, IntelInput{KEV: testKEV(600, day1), EPSS: testEPSS(500, day2.Add(time.Hour))}, d1, m1)
	got, err := VerifyIntel(d2, verifiedKeySet(t, k), 8)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Stream("kev").AsOf.Equal(day2) {
		t.Errorf("an older data date must not replace the newer: %+v", got.Stream("kev"))
	}
	if got.Stream("epss").File.Records != 1000 || !got.Stream("epss").AsOf.Equal(day2) {
		t.Errorf("a truncated snapshot must not replace the previous: %+v", got.Stream("epss"))
	}
	j := strings.Join(notes, "\n")
	if !strings.Contains(j, "older than") || !strings.Contains(j, "truncated") {
		t.Errorf("notes %v", notes)
	}
}

func TestIntelNothingToPublish(t *testing.T) {
	dir := t.TempDir()
	m, _, err := WriteIntel(dir, 1, time.Now(), IntelInput{}, "", nil)
	if m != nil || err != nil {
		t.Fatal(m, err)
	}
	if _, err := os.Stat(filepath.Join(dir, unsignedIntelManifest)); err == nil {
		t.Error("no manifest may be written without streams")
	}
}
