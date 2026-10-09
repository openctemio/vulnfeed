// Package bundle builds, signs, reads and verifies vulnerability bundles
// (OpenCTEM RFC-066 §5.5): JSON Lines files per record type, a signed
// manifest per snapshot and delta, and a signed latest pointer.
package bundle

import (
	"bufio"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/openctemio/vulnfeed/internal/dsse"
	"github.com/openctemio/vulnfeed/internal/model"
)

// Schemas, payload types and file names.
const (
	ManifestSchema      = "openctem.vulnfeed/v1"
	LatestSchema        = "openctem.vulnfeed.latest/v1"
	ManifestPayloadType = "application/vnd.openctem.vulnfeed.manifest+json"
	LatestPayloadType   = "application/vnd.openctem.vulnfeed.latest+json"

	KindSnapshot = "snapshot"
	KindDelta    = "delta"

	LatestFile   = "latest.dsse.json"
	KeySetFile   = "keyset.dsse.json"
	ManifestFile = "%s.manifest.dsse.json" // snapshot | delta

	Validity = 7 * 24 * time.Hour
)

// Caps (the importer applies the same).
const (
	MaxManifestBytes     = 1 << 20
	MaxFileBytes         = 512 << 20
	MaxDecompressedBytes = 2 << 30
	MaxRecordBytes       = 1 << 20
)

// Record files of a bundle, in import order.
var recordFiles = []string{"products", "vulns", "ranges"}

// FileName is the name of a record file of a kind.
func FileName(kind, records string) string { return kind + "-" + records + ".jsonl.gz" }

// Source names one upstream source and its terms.
type Source struct {
	Name        string    `json:"name"`
	AsOf        time.Time `json:"as_of"`
	Terms       string    `json:"terms"`
	Attribution string    `json:"attribution"`
}

// File is one record file of a manifest.
type File struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Records int    `json:"records"`
}

// Stats summarises a bundle.
type Stats struct {
	Vulns         int `json:"vulns"`
	Ranges        int `json:"ranges"`
	Products      int `json:"products"`
	RangesAdded   int `json:"ranges_added"`
	RangesRemoved int `json:"ranges_removed"`
}

// Collector identifies the build.
type Collector struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Manifest is the signed description of a snapshot or a delta.
type Manifest struct {
	Schema       string    `json:"schema"`
	Sequence     uint64    `json:"sequence"`
	Kind         string    `json:"kind"`
	BaseSequence uint64    `json:"base_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Sources      []Source  `json:"sources"`
	Files        []File    `json:"files"`
	Stats        Stats     `json:"stats"`
	Collector    Collector `json:"collector"`
}

// Latest is the signed pointer to the newest bundle.
type Latest struct {
	Schema       string    `json:"schema"`
	Sequence     uint64    `json:"sequence"`
	Tag          string    `json:"tag"`
	Snapshot     string    `json:"snapshot"`
	Delta        string    `json:"delta,omitempty"`
	BaseSequence uint64    `json:"base_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Tag is the release tag of a sequence.
func Tag(sequence uint64) string { return fmt.Sprintf("v1-%d", sequence) }

// Snapshot is the complete corpus.
type Snapshot struct {
	Sequence uint64
	Sources  []Source
	Vulns    map[string]model.Vuln
	Ranges   map[string][]model.Range
	Products map[string]model.Product
}

// NewSnapshot returns an empty snapshot.
func NewSnapshot() *Snapshot {
	return &Snapshot{Vulns: map[string]model.Vuln{}, Ranges: map[string][]model.Range{}, Products: map[string]model.Product{}}
}

// SourceAsOf returns a source's as-of time, or zero.
func (s *Snapshot) SourceAsOf(name string) time.Time {
	for _, src := range s.Sources {
		if src.Name == name {
			return src.AsOf
		}
	}
	return time.Time{}
}

// SetVuln stores a record and its complete range set. Ranges are kept in a
// canonical order so two builds of the same data are byte-identical.
func (s *Snapshot) SetVuln(v model.Vuln, ranges []model.Range, products map[string]model.Product) {
	s.Vulns[v.ID] = v
	rs := append([]model.Range(nil), ranges...)
	sort.Slice(rs, func(i, j int) bool { return rangeKey(rs[i]) < rangeKey(rs[j]) })
	rs = dedupRanges(rs)
	s.Ranges[v.ID] = rs
	for k, p := range products {
		s.Products[k] = p
	}
}

func rangeKey(r model.Range) string {
	b, _ := json.Marshal(r)
	return string(b)
}

func dedupRanges(rs []model.Range) []model.Range {
	out := rs[:0]
	for i, r := range rs {
		if i > 0 && rangeKey(r) == rangeKey(rs[i-1]) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// usedProducts returns the products the given vulns' ranges name.
func (s *Snapshot) usedProducts(ids []string) []model.Product {
	keys := map[string]bool{}
	for _, id := range ids {
		for _, r := range s.Ranges[id] {
			keys[r.Product] = true
			if r.Condition != "" {
				keys[r.Condition] = true
			}
		}
	}
	out := make([]model.Product, 0, len(keys))
	for k := range keys {
		if p, ok := s.Products[k]; ok {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (s *Snapshot) sortedIDs() []string {
	ids := make([]string, 0, len(s.Vulns))
	for id := range s.Vulns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *Snapshot) rangeCount(ids []string) int {
	n := 0
	for _, id := range ids {
		n += len(s.Ranges[id])
	}
	return n
}

// Changed returns the ids whose record or ranges differ from prev, and the
// numbers of ranges added and removed.
func Changed(prev, next *Snapshot) (ids []string, added, removed int) {
	for _, id := range next.sortedIDs() {
		pv, ok := prev.Vulns[id]
		if ok && rangeKeyOf(pv) == rangeKeyOf(next.Vulns[id]) && sameRanges(prev.Ranges[id], next.Ranges[id]) {
			continue
		}
		ids = append(ids, id)
		before := map[string]bool{}
		for _, r := range prev.Ranges[id] {
			before[rangeKey(r)] = true
		}
		after := map[string]bool{}
		for _, r := range next.Ranges[id] {
			k := rangeKey(r)
			after[k] = true
			if !before[k] {
				added++
			}
		}
		for k := range before {
			if !after[k] {
				removed++
			}
		}
	}
	return ids, added, removed
}

func rangeKeyOf(v model.Vuln) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func sameRanges(a, b []model.Range) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if rangeKey(a[i]) != rangeKey(b[i]) {
			return false
		}
	}
	return true
}

// Validate checks every record of the snapshot.
func (s *Snapshot) Validate() error {
	for _, id := range s.sortedIDs() {
		v := s.Vulns[id]
		if err := v.Validate(); err != nil {
			return err
		}
		for _, r := range s.Ranges[id] {
			if r.Vuln != id {
				return fmt.Errorf("range of %s filed under %s", r.Vuln, id)
			}
			if err := r.Validate(); err != nil {
				return err
			}
			for _, k := range []string{r.Product, r.Condition} {
				if k == "" {
					continue
				}
				p, ok := s.Products[k]
				if !ok {
					return fmt.Errorf("range %s: product %s is not in the bundle", id, k)
				}
				if err := p.Validate(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// WriteOptions describe a build.
type WriteOptions struct {
	Now       time.Time
	Collector Collector
}

// Write writes the snapshot of next and, when prev is not nil, the delta
// from prev, with unsigned manifests (payloads) and the latest pointer
// payload, into dir. It returns the manifests.
func Write(dir string, prev, next *Snapshot, opt WriteOptions) (snap, delta *Manifest, latest *Latest, err error) {
	if err := next.Validate(); err != nil {
		return nil, nil, nil, fmt.Errorf("refusing to publish an invalid bundle: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, nil, err
	}
	now := opt.Now.UTC().Truncate(time.Second)
	all := next.sortedIDs()
	snap = &Manifest{Schema: ManifestSchema, Sequence: next.Sequence, Kind: KindSnapshot, CreatedAt: now,
		ExpiresAt: now.Add(Validity), Sources: next.Sources, Collector: opt.Collector,
		Stats: Stats{Vulns: len(all), Ranges: next.rangeCount(all)}}
	if snap.Files, snap.Stats.Products, err = writeFiles(dir, KindSnapshot, next, all); err != nil {
		return nil, nil, nil, err
	}
	latest = &Latest{Schema: LatestSchema, Sequence: next.Sequence, Tag: Tag(next.Sequence),
		Snapshot: fmt.Sprintf(ManifestFile, KindSnapshot), CreatedAt: now, ExpiresAt: now.Add(Validity)}
	if prev != nil {
		ids, added, removed := Changed(prev, next)
		delta = &Manifest{Schema: ManifestSchema, Sequence: next.Sequence, Kind: KindDelta, BaseSequence: prev.Sequence,
			CreatedAt: now, ExpiresAt: now.Add(Validity), Sources: next.Sources, Collector: opt.Collector,
			Stats: Stats{Vulns: len(ids), Ranges: next.rangeCount(ids), RangesAdded: added, RangesRemoved: removed}}
		if delta.Files, delta.Stats.Products, err = writeFiles(dir, KindDelta, next, ids); err != nil {
			return nil, nil, nil, err
		}
		latest.Delta, latest.BaseSequence = fmt.Sprintf(ManifestFile, KindDelta), prev.Sequence
	}
	for name, v := range map[string]any{"snapshot.manifest.json": snap, "delta.manifest.json": delta, "latest.json": latest} {
		if v == nil || (name == "delta.manifest.json" && delta == nil) {
			continue
		}
		if err := writeJSON(filepath.Join(dir, name), v); err != nil {
			return nil, nil, nil, err
		}
	}
	return snap, delta, latest, nil
}

func writeFiles(dir, kind string, s *Snapshot, ids []string) ([]File, int, error) {
	products := s.usedProducts(ids)
	var files []File
	for _, rf := range recordFiles {
		name := FileName(kind, rf)
		var n int
		f, err := writeGz(filepath.Join(dir, name), func(enc *json.Encoder) error {
			switch rf {
			case "products":
				for _, p := range products {
					if err := enc.Encode(p); err != nil {
						return err
					}
					n++
				}
			case "vulns":
				for _, id := range ids {
					if err := enc.Encode(s.Vulns[id]); err != nil {
						return err
					}
					n++
				}
			case "ranges":
				for _, id := range ids {
					for _, r := range s.Ranges[id] {
						if err := enc.Encode(r); err != nil {
							return err
						}
						n++
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
		f.Name, f.Records = name, n
		files = append(files, f)
	}
	return files, len(products), nil
}

func writeGz(path string, fill func(*json.Encoder) error) (File, error) {
	out, err := os.Create(path)
	if err != nil {
		return File{}, err
	}
	h := sha256.New()
	counter := &countWriter{}
	gz, _ := gzip.NewWriterLevel(io.MultiWriter(out, h, counter), gzip.BestCompression)
	gz.ModTime = time.Unix(0, 0)
	bw := bufio.NewWriterSize(gz, 1<<20)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	if err := fill(enc); err != nil {
		out.Close()
		return File{}, err
	}
	if err := bw.Flush(); err != nil {
		out.Close()
		return File{}, err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		return File{}, err
	}
	if err := out.Close(); err != nil {
		return File{}, err
	}
	if counter.n > MaxFileBytes {
		return File{}, fmt.Errorf("%s is %d bytes, over the %d cap", filepath.Base(path), counter.n, MaxFileBytes)
	}
	return File{SHA256: hex.EncodeToString(h.Sum(nil)), Size: counter.n}, nil
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Sign wraps the unsigned manifests and latest pointer in dir in DSSE
// envelopes signed by priv, and copies the key set next to them. The
// signing key must be listed in the key set.
func Sign(dir string, priv ed25519.PrivateKey, keyset []byte, pinnedRoot string, now time.Time) error {
	ks, err := dsse.VerifyKeySet(keyset, pinnedRoot, 0, now)
	if err != nil {
		return err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	listed := false
	for _, k := range ks.Keys {
		if k.KeyID == dsse.KeyID(pub) {
			listed = true
		}
	}
	if !listed {
		return fmt.Errorf("the signing key %s is not in the key set", dsse.KeyID(pub))
	}
	pairs := []struct{ in, out, typ string }{
		{"snapshot.manifest.json", fmt.Sprintf(ManifestFile, KindSnapshot), ManifestPayloadType},
		{"delta.manifest.json", fmt.Sprintf(ManifestFile, KindDelta), ManifestPayloadType},
		{"latest.json", LatestFile, LatestPayloadType},
	}
	for _, p := range pairs {
		payload, err := os.ReadFile(filepath.Join(dir, p.in))
		if errors.Is(err, os.ErrNotExist) && p.in == "delta.manifest.json" {
			continue
		}
		if err != nil {
			return err
		}
		env, err := dsse.Sign(priv, p.typ, payload)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, p.out), env, 0o644); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(dir, p.in)); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, KeySetFile), keyset, 0o644)
}
