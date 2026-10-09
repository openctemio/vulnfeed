package bundle

import (
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/vulnfeed/internal/dsse"
	"github.com/openctemio/vulnfeed/internal/model"
)

type keys struct {
	rootID string
	priv   ed25519.PrivateKey
	keyset []byte
}

func newKeys(t *testing.T) keys {
	t.Helper()
	rootPub, root, _ := ed25519.GenerateKey(nil)
	pub, priv, _ := ed25519.GenerateKey(nil)
	ks, err := dsse.SignKeySet(root, 1, time.Now().Add(-time.Hour), 90*24*time.Hour, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	return keys{rootID: dsse.KeyID(rootPub), priv: priv, keyset: ks}
}

var nginx = model.Product{Key: "cpe:a:f5:nginx", Part: "a", Vendor: "f5", Name: "nginx", CPEVendor: "f5", CPEProduct: "nginx"}

func snapshot(seq uint64, end string) *Snapshot {
	s := NewSnapshot()
	s.Sequence = seq
	s.Sources = []Source{{Name: "nvd", AsOf: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)}}
	s.SetVuln(model.Vuln{ID: "CVE-2021-23017", Status: "Analyzed", Severity: "high", CWEs: []string{}},
		[]model.Range{{Vuln: "CVE-2021-23017", Product: nginx.Key, Scheme: "generic", Source: "nvd", End: end}},
		map[string]model.Product{nginx.Key: nginx})
	s.SetVuln(model.Vuln{ID: "CVE-2020-0001", Status: "Analyzed", CWEs: []string{}},
		[]model.Range{{Vuln: "CVE-2020-0001", Product: nginx.Key, Scheme: "generic", Source: "nvd", Exact: "1.0"}}, nil)
	return s
}

func build(t *testing.T, k keys, prev, next *Snapshot) string {
	t.Helper()
	dir := t.TempDir()
	if _, _, _, err := Write(dir, prev, next, WriteOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(dir, k.priv, k.keyset, k.rootID, time.Now()); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRoundTrip(t *testing.T) {
	k := newKeys(t)
	prev, next := snapshot(1, "1.20.1"), snapshot(2, "1.20.2")
	dir := build(t, k, prev, next)
	v, err := VerifyDir(dir, VerifyOptions{PinnedRoot: k.rootID, AppliedSeq: 1, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if v.Latest.Sequence != 2 || v.Latest.Tag != "v1-2" || v.Delta == nil || v.Delta.BaseSequence != 1 {
		t.Fatalf("%+v", v.Latest)
	}
	if v.Delta.Stats.Vulns != 1 || v.Delta.Stats.RangesAdded != 1 || v.Delta.Stats.RangesRemoved != 1 {
		t.Fatalf("delta stats %+v", v.Delta.Stats)
	}
	got, err := ReadRecords(dir, v.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Vulns) != 2 || got.Ranges["CVE-2021-23017"][0].End != "1.20.2" || len(got.Products) != 1 {
		t.Fatalf("snapshot %+v", got)
	}
	d, err := ReadRecords(dir, *v.Delta)
	if err != nil || len(d.Vulns) != 1 {
		t.Fatalf("delta %v %+v", err, d)
	}
	// Two builds of the same data are byte-identical files.
	dir2 := build(t, k, prev, next)
	for _, f := range v.Snapshot.Files {
		a, _ := os.ReadFile(filepath.Join(dir, f.Name))
		b, _ := os.ReadFile(filepath.Join(dir2, f.Name))
		if string(a) != string(b) {
			t.Errorf("%s differs between builds", f.Name)
		}
	}
}

func TestVerifyRefuses(t *testing.T) {
	k := newKeys(t)
	other := newKeys(t)
	now := time.Now()
	cases := map[string]struct {
		mut func(t *testing.T, dir string)
		opt VerifyOptions
	}{
		"rollback":            {nil, VerifyOptions{PinnedRoot: k.rootID, AppliedSeq: 5, Now: now}},
		"replay same":         {nil, VerifyOptions{PinnedRoot: k.rootID, AppliedSeq: 3, Now: now}},
		"expired":             {nil, VerifyOptions{PinnedRoot: k.rootID, Now: now.Add(8 * 24 * time.Hour)}},
		"other root":          {nil, VerifyOptions{PinnedRoot: other.rootID, Now: now}},
		"key set rolled back": {nil, VerifyOptions{PinnedRoot: k.rootID, MinKeySetVer: 2, Now: now}},
		"tampered file": {func(t *testing.T, dir string) {
			p := filepath.Join(dir, FileName(KindSnapshot, "ranges"))
			b, _ := os.ReadFile(p)
			b[len(b)/2] ^= 0xff
			_ = os.WriteFile(p, b, 0o644)
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
		"swapped key set": {func(t *testing.T, dir string) {
			_ = os.WriteFile(filepath.Join(dir, KeySetFile), other.keyset, 0o644)
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
		"pointer signed by a stranger": {func(t *testing.T, dir string) {
			resignJSON(t, dir, LatestFile, LatestPayloadType, other.priv, func(m map[string]any) {})
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
		"pointer names another sequence": {func(t *testing.T, dir string) {
			resignJSON(t, dir, LatestFile, LatestPayloadType, k.priv, func(m map[string]any) { m["sequence"] = 9; m["tag"] = "v1-9" })
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
		"manifest valid for a year": {func(t *testing.T, dir string) {
			resignJSON(t, dir, "snapshot.manifest.dsse.json", ManifestPayloadType, k.priv, func(m map[string]any) {
				m["expires_at"] = now.Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339)
			})
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
		"unknown field": {func(t *testing.T, dir string) {
			resignJSON(t, dir, LatestFile, LatestPayloadType, k.priv, func(m map[string]any) { m["extra"] = 1 })
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
	}
	for name, c := range cases {
		dir := build(t, k, snapshot(2, "1.20.1"), snapshot(3, "1.20.2"))
		if c.mut != nil {
			c.mut(t, dir)
		}
		if _, err := VerifyDir(dir, c.opt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Poisoned records under a valid signature and correct hashes are refused:
// the importer re-validates every record.
func TestPoisonedRecordsRefused(t *testing.T) {
	k := newKeys(t)
	cases := map[string]string{
		"wildcard product":   `{"vuln":"CVE-2021-23017","product":"cpe:a:*:*","scheme":"generic","start_incl":false,"end":"2","end_incl":false,"edition":"","target":"","source":"nvd"}`,
		"unparseable bound":  `{"vuln":"CVE-2021-23017","product":"cpe:a:f5:nginx","scheme":"generic","start_incl":false,"end":"latest","end_incl":false,"edition":"","target":"","source":"nvd"}`,
		"unknown vuln":       `{"vuln":"CVE-2099-0001","product":"cpe:a:f5:nginx","scheme":"generic","start_incl":false,"end":"2","end_incl":false,"edition":"","target":"","source":"nvd"}`,
		"product not listed": `{"vuln":"CVE-2021-23017","product":"cpe:a:evil:thing","scheme":"generic","start_incl":false,"end":"2","end_incl":false,"edition":"","target":"","source":"nvd"}`,
		"extra field":        `{"vuln":"CVE-2021-23017","product":"cpe:a:f5:nginx","scheme":"generic","start_incl":false,"end":"2","end_incl":false,"edition":"","target":"","source":"nvd","sql":"x"}`,
	}
	for name, line := range cases {
		dir := build(t, k, nil, snapshot(1, "1.20.1"))
		replaceFile(t, dir, k, FileName(KindSnapshot, "ranges"), line+"\n", 1)
		if _, err := VerifyDir(dir, VerifyOptions{PinnedRoot: k.rootID, Now: time.Now()}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A wrong record count is refused too.
	dir := build(t, k, nil, snapshot(1, "1.20.1"))
	replaceFile(t, dir, k, FileName(KindSnapshot, "ranges"),
		`{"vuln":"CVE-2021-23017","product":"cpe:a:f5:nginx","scheme":"generic","start_incl":false,"end":"2","end_incl":false,"edition":"","target":"","source":"nvd"}`+"\n", 5)
	if _, err := VerifyDir(dir, VerifyOptions{PinnedRoot: k.rootID, Now: time.Now()}); err == nil || !strings.Contains(err.Error(), "records") {
		t.Errorf("record count: %v", err)
	}
}

func TestWriteRefusesInvalidSnapshot(t *testing.T) {
	s := snapshot(1, "1.20.1")
	s.Ranges["CVE-2021-23017"][0].End = "n/a"
	if _, _, _, err := Write(t.TempDir(), nil, s, WriteOptions{Now: time.Now()}); err == nil {
		t.Fatal("invalid snapshot written")
	}
}

func TestSignRefusesKeyOutsideKeySet(t *testing.T) {
	k := newKeys(t)
	_, stranger, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	if _, _, _, err := Write(dir, nil, snapshot(1, "1"), WriteOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(dir, stranger, k.keyset, k.rootID, time.Now()); err == nil {
		t.Fatal("signed with a key outside the key set")
	}
}

// replaceFile rewrites one record file, fixes its hash/size/count in the
// manifest and re-signs the manifest: only record validation can catch it.
func replaceFile(t *testing.T, dir string, k keys, name, content string, records int) {
	t.Helper()
	p := filepath.Join(dir, name)
	f, _ := os.Create(p)
	gz := gzip.NewWriter(f)
	_, _ = gz.Write([]byte(content))
	_ = gz.Close()
	_ = f.Close()
	b, _ := os.ReadFile(p)
	sum := sha256.Sum256(b)
	resignJSON(t, dir, "snapshot.manifest.dsse.json", ManifestPayloadType, k.priv, func(m map[string]any) {
		for _, fi := range m["files"].([]any) {
			fm := fi.(map[string]any)
			if fm["name"] == name {
				fm["sha256"], fm["size"], fm["records"] = hex.EncodeToString(sum[:]), len(b), records
			}
		}
	})
}

func resignJSON(t *testing.T, dir, file, payloadType string, priv ed25519.PrivateKey, mut func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatal(err)
	}
	var env dsse.Envelope
	_ = json.Unmarshal(raw, &env)
	var m map[string]any
	_ = json.Unmarshal(env.Payload, &m)
	mut(m)
	payload, _ := json.Marshal(m)
	out, _ := dsse.Sign(priv, payloadType, payload)
	_ = os.WriteFile(filepath.Join(dir, file), out, 0o644)
}
