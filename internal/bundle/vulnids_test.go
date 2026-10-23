package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/vulnfeed/internal/vulnid"
)

var testVulnIDs = []vulnid.Entry{
	{ID: "GHSA-8gq3-9chp-cf2j", CVE: "CVE-2024-1234", Source: "ghsa"},
	{ID: "PYSEC-2024-12", CVE: "CVE-2024-0008", Source: "osv"},
}

func buildWithVulnIDs(t *testing.T, k keys, prev *VulnIDManifest, seq uint64, entries []vulnid.Entry) (string, *VulnIDManifest) {
	t.Helper()
	dir := t.TempDir()
	s := snapshot(seq, "1.20.1")
	if _, _, _, err := Write(dir, nil, s, WriteOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	m, err := WriteVulnIDs(dir, seq, prev, entries, vulnid.Stats{Advisories: 5, Published: len(entries), OverBroad: 1, NoCVE: 2}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(dir, k.priv, k.keyset, k.rootID, time.Now()); err != nil {
		t.Fatal(err)
	}
	return dir, m
}

func TestVulnIDsRoundTripAndVersion(t *testing.T) {
	k := newKeys(t)
	dir, m := buildWithVulnIDs(t, k, nil, 7, testVulnIDs)
	if m.Version != 7 || m.Sequence != 7 || m.Schema != VulnIDsSchema {
		t.Fatalf("manifest %+v", m)
	}
	got, err := VerifyVulnIDs(dir, verifiedKeySet(t, k), 7)
	if err != nil || got == nil {
		t.Fatal(got, err)
	}
	if got.ExpiresAt.Sub(got.CreatedAt) != Validity || len(got.Files) != 1 || got.Files[0].Records != 2 || got.Stats.OverBroad != 1 {
		t.Fatalf("verified %+v", got)
	}
	st, err := os.Stat(filepath.Join(dir, VulnIDsEntriesFile))
	if err != nil || st.Size() != got.Files[0].Size {
		t.Fatal("size does not match the manifest", err)
	}
	entries, err := ReadVulnIDEntries(dir, got)
	if err != nil || len(entries) != 2 || entries[0] != testVulnIDs[0] {
		t.Fatal(entries, err)
	}
	// Unchanged entries keep the version, changed ones bump it.
	if _, m2 := buildWithVulnIDs(t, k, got, 8, testVulnIDs); m2.Version != 7 || m2.Sequence != 8 {
		t.Fatalf("unchanged entries: version %d sequence %d, want 7 and 8", m2.Version, m2.Sequence)
	}
	changed := append(append([]vulnid.Entry{}, testVulnIDs...), vulnid.Entry{ID: "RUSTSEC-2024-1", CVE: "CVE-2024-5555", Source: "osv"})
	if _, m3 := buildWithVulnIDs(t, k, got, 9, changed); m3.Version != 9 {
		t.Fatalf("changed entries: version %d, want 9", m3.Version)
	}
	// A restart with the same sequence still grows.
	if _, m4 := buildWithVulnIDs(t, k, got, 7, changed); m4.Version != 8 {
		t.Fatalf("version %d, want 8", m4.Version)
	}
}

func TestVulnIDsDeterministic(t *testing.T) {
	k := newKeys(t)
	_, a := buildWithVulnIDs(t, k, nil, 7, testVulnIDs)
	_, b := buildWithVulnIDs(t, k, nil, 7, testVulnIDs)
	if a.Files[0].SHA256 != b.Files[0].SHA256 || a.Files[0].Size != b.Files[0].Size {
		t.Fatal("same entries, different bytes")
	}
}

func TestVulnIDsRefused(t *testing.T) {
	k := newKeys(t)
	ks := verifiedKeySet(t, k)
	if m, err := VerifyVulnIDs(t.TempDir(), ks, 7); m != nil || err != nil {
		t.Fatal("a release without the map is fine", m, err)
	}
	dir, _ := buildWithVulnIDs(t, k, nil, 7, testVulnIDs)
	if _, err := VerifyVulnIDs(dir, ks, 8); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("a map built for another sequence must be refused: %v", err)
	}
	dir, _ = buildWithVulnIDs(t, k, nil, 7, testVulnIDs)
	if err := os.WriteFile(filepath.Join(dir, VulnIDsEntriesFile), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVulnIDs(dir, ks, 7); err == nil {
		t.Fatal("a tampered entries file must be refused")
	}
	dir, _ = buildWithVulnIDs(t, k, nil, 7, testVulnIDs)
	other := newKeys(t)
	resignJSON(t, dir, VulnIDsManifestFile, VulnIDsManifestPayloadType, other.priv, func(map[string]any) {})
	if _, err := VerifyVulnIDs(dir, ks, 7); err == nil {
		t.Fatal("a manifest signed by an unlisted key must be refused")
	}
	dir, _ = buildWithVulnIDs(t, k, nil, 7, testVulnIDs)
	resignJSON(t, dir, VulnIDsManifestFile, "application/vnd.openctem.vulnfeed.aliases+json", k.priv, func(map[string]any) {})
	if _, err := VerifyVulnIDs(dir, ks, 7); err == nil {
		t.Fatal("a wrong payload type must be refused")
	}
	dir, _ = buildWithVulnIDs(t, k, nil, 7, testVulnIDs)
	resignJSON(t, dir, VulnIDsManifestFile, VulnIDsManifestPayloadType, k.priv, func(m map[string]any) { m["extra"] = 1 })
	if _, err := VerifyVulnIDs(dir, ks, 7); err == nil {
		t.Fatal("an unknown manifest field must be refused")
	}
}

func TestWriteVulnIDsRefusesBadEntries(t *testing.T) {
	bad := [][]vulnid.Entry{
		{{ID: "GHSA-8gq3-9chp-cf2j", CVE: "cve-2024-1", Source: "ghsa"}},
		{{ID: "GHSA-8GQ3-9CHP-CF2J", CVE: "CVE-2024-1234", Source: "ghsa"}},
		{{ID: "MAL-2024-1", CVE: "CVE-2024-1234", Source: "osv"}},
		{{ID: "RHSA-2024:1", CVE: "CVE-2024-1234", Source: "osv"}},
		{{ID: "PYSEC-2024-12", CVE: "CVE-2024-1234", Source: "ghsa"}},
		{testVulnIDs[1], testVulnIDs[0]},
		{testVulnIDs[0], testVulnIDs[0]},
	}
	for i, e := range bad {
		if _, err := WriteVulnIDs(t.TempDir(), 7, nil, e, vulnid.Stats{}, time.Now()); err == nil {
			t.Errorf("case %d: expected a refusal", i)
		}
	}
}
