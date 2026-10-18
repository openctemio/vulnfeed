package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/vulnfeed/internal/alias"
	"github.com/openctemio/vulnfeed/internal/dsse"
)

var testEntries = []alias.Entry{{Kind: "cpe", Value: "a:google_inc:chrome", Target: "a:google:chrome", Basis: alias.BasisLearned, Support: 4}}

var testState = map[string]alias.Obs{
	"CVE-2026-0001": {ID: "CVE-2026-0001", Names: []string{"a:google_inc:chrome"}, Pairs: [][2]string{{"a:google_inc:chrome", "a:google:chrome"}}},
	"CVE-2026-0002": {ID: "CVE-2026-0002", Missing: alias.MissingNoProduct},
}

func buildWithAliases(t *testing.T, k keys, prev *AliasManifest, entries []alias.Entry) (string, *AliasManifest) {
	t.Helper()
	dir := t.TempDir()
	s := snapshot(7, "1.20.1")
	if _, _, _, err := Write(dir, nil, s, WriteOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	m, err := WriteAliases(dir, s.Sequence, prev, entries, testState, alias.Stats{Published: 2, Resolved: 1, Unresolvable: 1, Coverage: 1}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(dir, k.priv, k.keyset, k.rootID, time.Now()); err != nil {
		t.Fatal(err)
	}
	return dir, m
}

func verifiedKeySet(t *testing.T, k keys) *dsse.KeySet {
	t.Helper()
	ks, err := dsse.VerifyKeySet(k.keyset, k.rootID, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestAliasesRoundTripAndVersion(t *testing.T) {
	k := newKeys(t)
	dir, m := buildWithAliases(t, k, nil, testEntries)
	if m.Version != 7 {
		t.Fatalf("version %d, want the release sequence", m.Version)
	}
	got, err := VerifyAliases(dir, verifiedKeySet(t, k), 7)
	if err != nil || got == nil {
		t.Fatalf("verify: %v", err)
	}
	entries, err := ReadAliasEntries(dir, got)
	if err != nil || len(entries) != 1 || entries[0] != testEntries[0] {
		t.Fatalf("entries %v %v", entries, err)
	}
	state, err := ReadAliasState(dir, got)
	if err != nil || len(state) != 2 || state["CVE-2026-0002"].Missing != alias.MissingNoProduct {
		t.Fatalf("state %v %v", state, err)
	}
	// Same entries: same version; changed entries: a higher version.
	if _, m2 := buildWithAliases(t, k, got, testEntries); m2.Version != 7 {
		t.Errorf("unchanged entries got version %d", m2.Version)
	}
	changed := append([]alias.Entry{{Kind: "cpe", Value: "a:acme:x", Target: "a:acme_software:x", Basis: alias.BasisLearned}}, testEntries...)
	if _, m3 := buildWithAliases(t, k, got, changed); m3.Version != 8 {
		t.Errorf("changed entries got version %d", m3.Version)
	}
	// Without a readable previous dictionary the version still does not
	// go back (the release sequence, not 1).
	if _, m4 := buildWithAliases(t, k, nil, changed); m4.Version != 7 {
		t.Errorf("no previous dictionary got version %d", m4.Version)
	}
}

func TestAliasesRefused(t *testing.T) {
	k := newKeys(t)
	ks := verifiedKeySet(t, k)
	// No manifest: nothing to verify.
	if m, err := VerifyAliases(t.TempDir(), ks, 7); m != nil || err != nil {
		t.Fatalf("empty dir: %v %v", m, err)
	}
	// Built for another release (a replayed dictionary).
	dir, _ := buildWithAliases(t, k, nil, testEntries)
	if _, err := VerifyAliases(dir, ks, 8); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Errorf("wrong sequence: %v", err)
	}
	// A tampered entries file.
	dir, _ = buildWithAliases(t, k, nil, testEntries)
	if err := os.WriteFile(filepath.Join(dir, AliasesEntriesFile), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAliases(dir, ks, 7); err == nil {
		t.Error("tampered entries accepted")
	}
	// Signed by a key outside the key set.
	dir, _ = buildWithAliases(t, k, nil, testEntries)
	other := newKeys(t)
	resignJSON(t, dir, AliasesManifestFile, AliasesManifestPayloadType, other.priv, func(map[string]any) {})
	if _, err := VerifyAliases(dir, ks, 7); err == nil {
		t.Error("foreign signature accepted")
	}
	// An unknown field in the signed manifest (strict decoding).
	dir, _ = buildWithAliases(t, k, nil, testEntries)
	resignJSON(t, dir, AliasesManifestFile, AliasesManifestPayloadType, k.priv, func(m map[string]any) { m["extra"] = 1 })
	if _, err := VerifyAliases(dir, ks, 7); err == nil {
		t.Error("unknown field accepted")
	}
	// The writer refuses an invalid entry.
	if _, err := WriteAliases(t.TempDir(), 1, nil, []alias.Entry{{Kind: "cpe", Value: "a:X:y", Target: "a:x:y"}}, nil, alias.Stats{}, time.Now()); err == nil {
		t.Error("invalid entry written")
	}
	if _, err := WriteAliases(t.TempDir(), 1, nil, []alias.Entry{{Kind: "cpe", Value: "a:x:y", Target: "a:x:y"}}, nil, alias.Stats{}, time.Now()); err == nil {
		t.Error("self entry written")
	}
}
