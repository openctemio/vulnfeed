package bundle

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/transfer"
	sdkbundle "github.com/openctemio/sdk-go/pkg/transfer/bundle"

	"github.com/openctemio/vulnfeed/internal/model"
)

var t0 = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)

// big returns a snapshot of n vulnerabilities with one range each; the
// vulnerability with index changed gets a different range end (-1: none).
func big(seq uint64, n, changed int) *Snapshot {
	s := NewSnapshot()
	s.Sequence = seq
	s.Sources = []Source{{Name: "nvd", AsOf: t0}}
	for i := range n {
		id := fmt.Sprintf("CVE-2024-%05d", i)
		end := "2.0"
		if i == changed {
			end = "3.0"
		}
		s.SetVuln(model.Vuln{ID: id, Status: "Analyzed", Description: "d " + id, CWEs: []string{}},
			[]model.Range{{Vuln: id, Product: nginx.Key, Scheme: "generic", Source: "nvd", End: end}},
			map[string]model.Product{nginx.Key: nginx})
	}
	return s
}

func writeAt(t *testing.T, prev, next *Snapshot) string {
	t.Helper()
	dir := t.TempDir()
	if _, _, _, err := Write(dir, prev, next, WriteOptions{Now: t0}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func manifestV2(t *testing.T, dir, name string) sdkbundle.Manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var m sdkbundle.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func chunkHashes(m sdkbundle.Manifest, stream string) []string {
	var out []string
	for _, s := range m.Streams {
		if s.Name == stream {
			for _, c := range s.Chunks {
				out = append(out, c.SHA256)
			}
		}
	}
	return out
}

func TestV2UnchangedInputGivesIdenticalChunks(t *testing.T) {
	a := writeAt(t, nil, big(1, 6000, -1))
	b := writeAt(t, nil, big(1, 6000, -1))
	c := writeAt(t, nil, big(2, 6000, -1)) // a later release of the same data
	for _, stream := range []string{"vulns", "ranges", "products"} {
		ha := chunkHashes(manifestV2(t, a, unsignedSnapshotV2), stream)
		hb := chunkHashes(manifestV2(t, b, unsignedSnapshotV2), stream)
		hc := chunkHashes(manifestV2(t, c, unsignedSnapshotV2), stream)
		if stream != "products" && len(ha) < 2 {
			t.Fatalf("%s: %d chunks, did not split", stream, len(ha))
		}
		if strings.Join(ha, ",") != strings.Join(hb, ",") || strings.Join(ha, ",") != strings.Join(hc, ",") {
			t.Fatalf("%s: same input, different chunks", stream)
		}
	}
}

func TestV2OneChangedVulnChangesOneVulnChunkAndOneRangeChunk(t *testing.T) {
	a := writeAt(t, nil, big(1, 6000, -1))
	b := writeAt(t, nil, big(2, 6000, 3100))
	ma, mb := manifestV2(t, a, unsignedSnapshotV2), manifestV2(t, b, unsignedSnapshotV2)
	if h := chunkHashes(ma, "vulns"); strings.Join(h, ",") != strings.Join(chunkHashes(mb, "vulns"), ",") {
		t.Fatal("vuln records did not change, their chunks must not")
	}
	ha, hb := chunkHashes(ma, "ranges"), chunkHashes(mb, "ranges")
	if len(ha) != len(hb) {
		t.Fatalf("chunk count moved: %d -> %d", len(ha), len(hb))
	}
	diff := 0
	for i := range ha {
		if ha[i] != hb[i] {
			diff++
		}
	}
	// The changed range gets a new id, so it may move to a neighbouring
	// chunk: at most the chunk it left and the chunk it joined change.
	if diff < 1 || diff > 2 {
		t.Fatalf("%d range chunks changed, want 1 (2 if the range id crossed a boundary)", diff)
	}
}

func TestV1OutputUnchangedByV2(t *testing.T) {
	k := newKeys(t)
	dir := build(t, k, snapshot(1, "2.0"), snapshot(2, "3.0"))
	for _, n := range []string{"latest.dsse.json", "snapshot.manifest.dsse.json", "delta.manifest.dsse.json", "keyset.dsse.json",
		"snapshot-products.jsonl.gz", "snapshot-vulns.jsonl.gz", "snapshot-ranges.jsonl.gz", "delta-vulns.jsonl.gz"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("v1 file %s missing: %v", n, err)
		}
	}
	if _, err := VerifyDir(dir, VerifyOptions{PinnedRoot: k.rootID, AppliedSeq: 1, Now: time.Now()}); err != nil {
		t.Fatalf("v1 verify: %v", err)
	}
	for _, n := range []string{unsignedSnapshotV2, unsignedDeltaV2, "snapshot.manifest.json", "latest.json"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			t.Fatalf("unsigned %s left in a signed release", n)
		}
	}
}

type collect struct {
	vulns, ranges, products map[string]bool
	completes               int
}

func (c *collect) ApplyChunk(_ context.Context, ch *sdkbundle.Chunk, _ sdkbundle.State) error {
	return ch.Records(func(line []byte) error {
		var r struct {
			ID      string `json:"id"`
			Key     string `json:"key"`
			Vuln    string `json:"vuln"`
			Product string `json:"product"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		switch {
		case r.Key != "":
			c.products[r.Key] = true
		case r.ID != "":
			c.vulns[r.ID] = true
		default:
			c.ranges[r.Vuln] = true
		}
		return nil
	})
}

func (c *collect) Complete(context.Context, *sdkbundle.Manifest, sdkbundle.State) error {
	c.completes++
	return nil
}

func TestV2RoundTripWithSDKConsumer(t *testing.T) {
	k := newKeys(t)
	dir := t.TempDir()
	if _, _, _, err := Write(dir, big(1, 3000, -1), big(2, 3000, 5), WriteOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(dir, k.priv, k.keyset, k.rootID, time.Now()); err != nil {
		t.Fatal(err)
	}
	v, err := VerifyDir(dir, VerifyOptions{PinnedRoot: k.rootID, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyV2(dir, v.KeySet, time.Now()); err != nil {
		t.Fatalf("VerifyV2: %v", err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	f, err := transfer.New(transfer.Config{Origins: []transfer.Origin{{URL: srv.URL}}, CacheDir: t.TempDir(), Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	col := &collect{vulns: map[string]bool{}, ranges: map[string]bool{}, products: map[string]bool{}}
	pub, _ := k.priv.Public().(ed25519.PublicKey)
	c, err := sdkbundle.NewConsumer(sdkbundle.Config{Feed: FeedV2, Fetcher: f, Verifier: sdkbundle.NewEd25519Verifier(pub),
		Checkpoint: sdkbundle.FileCheckpoint{Path: filepath.Join(t.TempDir(), "cp.json")}, Applier: col})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != sdkbundle.KindSnapshot || len(col.vulns) != 3000 || len(col.ranges) != 3000 || !col.products[nginx.Key] || col.completes != 1 {
		t.Fatalf("res %+v vulns %d ranges %d products %v", res, len(col.vulns), len(col.ranges), col.products)
	}
}
