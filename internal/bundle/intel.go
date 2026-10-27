package bundle

// The exploitation signals (CISA KEV and FIRST EPSS) travel next to the
// bundle as a signed side manifest, intel.manifest.dsse.json, in the same
// way as the alias dictionary and the vulnerability id map: it names one
// entries file per stream (SHA-256, size, records) and carries the bundle
// sequence it was built with. The corpus format stays v1, so a platform that
// does not know the manifest ignores it.
//
// Each stream states its own data date (`as_of`: KEV's dateReleased, EPSS's
// score_date). A platform applies a stream only when that date is newer than
// the one it holds, so a replayed or carried-forward older copy never rolls a
// newer one back. A platform skips a stream name it does not know (it is
// signed, so skipping is safe): later signals add streams without a lockstep
// release.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/openctemio/vulnfeed/internal/dsse"
	"github.com/openctemio/vulnfeed/internal/intel"
)

// Intel side manifest files.
const (
	IntelSchema              = "openctem.vulnfeed.intel/v1"
	IntelManifestPayloadType = "application/vnd.openctem.vulnfeed.intel+json"
	IntelManifestFile        = "intel.manifest.dsse.json"
	unsignedIntelManifest    = "intel.manifest.json"
)

var intelStreamRe = regexp.MustCompile(`^[a-z0-9]{1,24}$`)

// IntelFileName is the entries file of a stream.
func IntelFileName(stream string) string { return "intel-" + stream + ".jsonl.gz" }

// IntelStream describes one signed stream.
type IntelStream struct {
	Name string    `json:"name"`
	AsOf time.Time `json:"as_of"`
	// FetchedAt is when the collector last read the source successfully:
	// the build time of a fresh stream, the earlier value of a carried one.
	// A platform judges how current a stream is by it (AsOf is the
	// publisher's own date and may be days old while the data is current).
	FetchedAt   time.Time `json:"fetched_at"`
	Version     string    `json:"version"`
	Attribution string    `json:"attribution"`
	File        File      `json:"file"`
}

// IntelManifest is the signed description of the side files.
type IntelManifest struct {
	Schema    string        `json:"schema"`
	Sequence  uint64        `json:"sequence"`
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	Streams   []IntelStream `json:"streams"`
}

// Stream returns the named stream.
func (m *IntelManifest) Stream(name string) *IntelStream {
	if m == nil {
		return nil
	}
	for i := range m.Streams {
		if m.Streams[i].Name == name {
			return &m.Streams[i]
		}
	}
	return nil
}

// IntelInput is what a build collected. A nil source (its fetch failed) is
// carried forward from the previous release when there is one.
type IntelInput struct {
	KEV  *intel.KEV
	EPSS *intel.EPSS
}

// WriteIntel writes the entries files and the unsigned manifest into dir.
// Per stream: the fresh copy is published when it passes the guards (data
// date not older than the previous release's, record count not under
// intel.ShrinkFloor of it); otherwise the previous release's verified copy
// is carried forward with its older data date. The returned notes say what
// was refused or carried. No stream at all writes no manifest.
func WriteIntel(dir string, sequence uint64, now time.Time, in IntelInput, prevDir string, prev *IntelManifest) (*IntelManifest, []string, error) {
	now = now.UTC().Truncate(time.Second)
	m := &IntelManifest{Schema: IntelSchema, Sequence: sequence, CreatedAt: now, ExpiresAt: now.Add(Validity)}
	var notes []string

	type fresh struct {
		name    string
		asOf    time.Time
		version string
		n       int
		fill    func(*json.Encoder) error
		err     error
	}
	var cands []fresh
	if in.KEV != nil {
		k := in.KEV
		cands = append(cands, fresh{name: intel.StreamKEV, asOf: k.AsOf, version: k.Version, n: len(k.Entries), fill: func(enc *json.Encoder) error {
			for _, e := range k.Entries {
				if err := enc.Encode(e); err != nil {
					return err
				}
			}
			return nil
		}})
	}
	if in.EPSS != nil {
		e := in.EPSS
		cands = append(cands, fresh{name: intel.StreamEPSS, asOf: e.AsOf, version: e.Version, n: len(e.Entries), fill: func(enc *json.Encoder) error {
			for _, r := range e.Entries {
				if err := enc.Encode(r); err != nil {
					return err
				}
			}
			return nil
		}})
	}
	done := map[string]bool{}
	for _, c := range cands {
		old := prev.Stream(c.name)
		switch {
		case old != nil && c.asOf.Before(old.AsOf):
			notes = append(notes, fmt.Sprintf("%s: the source's data date %s is older than the previous release's %s; carried forward",
				c.name, c.asOf.Format(time.RFC3339), old.AsOf.Format(time.RFC3339)))
			continue
		case old != nil:
			if err := intel.CheckShrink(c.name, c.n, old.File.Records); err != nil {
				notes = append(notes, err.Error()+"; carried forward")
				continue
			}
		}
		f, err := writeGz(filepath.Join(dir, IntelFileName(c.name)), c.fill)
		if err != nil {
			return nil, notes, err
		}
		f.Name, f.Records = IntelFileName(c.name), c.n
		m.Streams = append(m.Streams, IntelStream{Name: c.name, AsOf: c.asOf.UTC(), FetchedAt: now, Version: c.version,
			Attribution: intel.Attribution(c.name), File: f})
		done[c.name] = true
	}
	// Carry forward every stream of the previous release that was not
	// replaced (a failed fetch, a refused copy, or a stream this build did
	// not try).
	if prev != nil {
		for _, s := range prev.Streams {
			if done[s.Name] {
				continue
			}
			if err := copyVerified(filepath.Join(prevDir, s.File.Name), filepath.Join(dir, s.File.Name), s.File); err != nil {
				notes = append(notes, fmt.Sprintf("%s: the previous copy could not be carried: %v", s.Name, err))
				continue
			}
			m.Streams = append(m.Streams, s)
			notes = append(notes, fmt.Sprintf("%s: carried forward (data date %s)", s.Name, s.AsOf.Format(time.RFC3339)))
		}
	}
	if len(m.Streams) == 0 {
		return nil, notes, nil
	}
	sort.Slice(m.Streams, func(i, j int) bool { return m.Streams[i].Name < m.Streams[j].Name })
	return m, notes, writeJSON(filepath.Join(dir, unsignedIntelManifest), m)
}

func copyVerified(from, to string, f File) error {
	if err := checkFile(from, f); err != nil {
		return err
	}
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// VerifyIntel verifies the side manifest in dir against the key set: its
// signature, schema, the bundle sequence it must carry, validity, and every
// stream's file (size, SHA-256). A directory without the manifest gives
// (nil, nil).
func VerifyIntel(dir string, ks *dsse.KeySet, sequence uint64) (*IntelManifest, error) {
	path := filepath.Join(dir, IntelManifestFile)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	var m IntelManifest
	if err := verifyJSON(ks, path, IntelManifestPayloadType, &m); err != nil {
		return nil, err
	}
	switch {
	case m.Schema != IntelSchema:
		return nil, fmt.Errorf("intel: schema %q", m.Schema)
	case m.Sequence != sequence:
		return nil, fmt.Errorf("intel: built for sequence %d, the release is %d", m.Sequence, sequence)
	case m.ExpiresAt.Sub(m.CreatedAt) > Validity:
		return nil, fmt.Errorf("intel: valid for more than %s", Validity)
	case len(m.Streams) == 0 || len(m.Streams) > 16:
		return nil, errors.New("intel: no streams or too many")
	}
	seen := map[string]bool{}
	for _, s := range m.Streams {
		if !intelStreamRe.MatchString(s.Name) || seen[s.Name] || s.File.Name != IntelFileName(s.Name) || s.AsOf.IsZero() || s.FetchedAt.IsZero() || s.FetchedAt.After(m.CreatedAt.Add(time.Hour)) {
			return nil, fmt.Errorf("intel: stream %q is malformed or repeated", s.Name)
		}
		seen[s.Name] = true
		if err := checkFile(filepath.Join(dir, s.File.Name), s.File); err != nil {
			return nil, err
		}
	}
	return &m, nil
}

// ReadKEV reads and validates the KEV stream of a verified manifest.
func ReadKEV(dir string, s *IntelStream) ([]intel.KEVEntry, error) {
	var out []intel.KEVEntry
	err := eachLine(filepath.Join(dir, s.File.Name), func(line []byte) error {
		var e intel.KEVEntry
		if err := strictLine(line, &e); err != nil {
			return err
		}
		if !intel.ValidCVE(e.CVE) || (len(out) > 0 && out[len(out)-1].CVE >= e.CVE) {
			return fmt.Errorf("intel: kev entry %q", e.CVE)
		}
		if len(out) >= intel.MaxKEVRecords {
			return errors.New("intel: too many kev entries")
		}
		out = append(out, e)
		return nil
	})
	if err == nil && len(out) != s.File.Records {
		err = fmt.Errorf("intel: %d kev entries, the manifest says %d", len(out), s.File.Records)
	}
	return out, err
}

// ReadEPSS reads and validates the EPSS stream of a verified manifest.
func ReadEPSS(dir string, s *IntelStream) ([]intel.EPSSEntry, error) {
	var out []intel.EPSSEntry
	err := eachLine(filepath.Join(dir, s.File.Name), func(line []byte) error {
		var e intel.EPSSEntry
		if err := strictLine(line, &e); err != nil {
			return err
		}
		if !intel.ValidCVE(e.CVE) || e.Score < 0 || e.Score > 1 || e.Percentile < 0 || e.Percentile > 1 ||
			(len(out) > 0 && out[len(out)-1].CVE >= e.CVE) {
			return fmt.Errorf("intel: epss entry %q", e.CVE)
		}
		if len(out) >= intel.MaxEPSSRecords {
			return errors.New("intel: too many epss entries")
		}
		out = append(out, e)
		return nil
	})
	if err == nil && len(out) != s.File.Records {
		err = fmt.Errorf("intel: %d epss entries, the manifest says %d", len(out), s.File.Records)
	}
	return out, err
}
