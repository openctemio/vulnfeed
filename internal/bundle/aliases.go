package bundle

// The alias dictionary (OpenCTEM RFC-066 §5.6) travels next to the bundle
// as its own signed manifest: aliases.manifest.dsse.json names the
// dictionary entries and the learner's state, with SHA-256 and sizes,
// carries the bundle sequence it was built with (a platform accepts it only
// for the release its verified pointer names) and a dictionary version that
// grows whenever the entries change.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/openctemio/vulnfeed/internal/alias"
	"github.com/openctemio/vulnfeed/internal/dsse"
)

// Alias dictionary files.
const (
	AliasesSchema              = "openctem.vulnfeed.aliases/v1"
	AliasesManifestPayloadType = "application/vnd.openctem.vulnfeed.aliases+json"
	AliasesManifestFile        = "aliases.manifest.dsse.json"
	AliasesEntriesFile         = "aliases.jsonl.gz"
	AliasesStateFile           = "aliases-state.jsonl.gz"
	unsignedAliasesManifest    = "aliases.manifest.json"
)

// AliasManifest is the signed description of an alias dictionary.
type AliasManifest struct {
	Schema    string      `json:"schema"`
	Sequence  uint64      `json:"sequence"`
	Version   uint64      `json:"version"`
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	Files     []File      `json:"files"`
	Stats     alias.Stats `json:"stats"`
}

// WriteAliases writes the dictionary entries, the learner state and the
// unsigned manifest into dir. The version is prev's when the entries file
// is byte-identical to prev's, else prev's plus one (1 without prev).
func WriteAliases(dir string, sequence uint64, prev *AliasManifest, entries []alias.Entry, state map[string]alias.Obs,
	stats alias.Stats, now time.Time) (*AliasManifest, error) {
	if len(entries) > alias.MaxEntries || len(state) > alias.MaxStateObs {
		return nil, fmt.Errorf("refusing to publish %d alias entries and %d observations (over the caps)", len(entries), len(state))
	}
	for _, e := range entries {
		if e.Kind != "cpe" || !alias.ValidCPEKey(e.Value) || !alias.ValidCPEKey(e.Target) || e.Value == e.Target {
			return nil, fmt.Errorf("refusing to publish an invalid alias entry %q → %q", e.Value, e.Target)
		}
	}
	ef, err := writeGz(filepath.Join(dir, AliasesEntriesFile), func(enc *json.Encoder) error {
		for _, e := range entries {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	ef.Name, ef.Records = AliasesEntriesFile, len(entries)
	ids := make([]string, 0, len(state))
	for id := range state {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	sf, err := writeGz(filepath.Join(dir, AliasesStateFile), func(enc *json.Encoder) error {
		for _, id := range ids {
			if err := enc.Encode(state[id]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sf.Name, sf.Records = AliasesStateFile, len(ids)
	now = now.UTC().Truncate(time.Second)
	m := &AliasManifest{Schema: AliasesSchema, Sequence: sequence, Version: 1, CreatedAt: now, ExpiresAt: now.Add(Validity),
		Files: []File{ef, sf}, Stats: stats}
	if prev != nil {
		m.Version = prev.Version + 1
		if len(prev.Files) > 0 && prev.Files[0].SHA256 == ef.SHA256 {
			m.Version = prev.Version
		}
	}
	return m, writeJSON(filepath.Join(dir, unsignedAliasesManifest), m)
}

// VerifyAliases verifies the alias manifest in dir against the key set: its
// signature, schema, the bundle sequence it must carry, and its files. A
// directory without the manifest gives (nil, nil).
func VerifyAliases(dir string, ks *dsse.KeySet, sequence uint64) (*AliasManifest, error) {
	path := filepath.Join(dir, AliasesManifestFile)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	var m AliasManifest
	if err := verifyJSON(ks, path, AliasesManifestPayloadType, &m); err != nil {
		return nil, err
	}
	switch {
	case m.Schema != AliasesSchema:
		return nil, fmt.Errorf("aliases: schema %q", m.Schema)
	case m.Sequence != sequence:
		return nil, fmt.Errorf("aliases: built for sequence %d, the release is %d", m.Sequence, sequence)
	case m.Version == 0:
		return nil, errors.New("aliases: version 0")
	case len(m.Files) != 2 || m.Files[0].Name != AliasesEntriesFile || m.Files[1].Name != AliasesStateFile:
		return nil, errors.New("aliases: unexpected files")
	}
	for _, f := range m.Files {
		if err := checkFile(filepath.Join(dir, f.Name), f); err != nil {
			return nil, err
		}
	}
	return &m, nil
}

// ReadAliasEntries reads and validates the entries of a verified manifest.
func ReadAliasEntries(dir string, m *AliasManifest) ([]alias.Entry, error) {
	var out []alias.Entry
	err := eachLine(filepath.Join(dir, AliasesEntriesFile), func(line []byte) error {
		var e alias.Entry
		if err := strictLine(line, &e); err != nil {
			return err
		}
		if e.Kind != "cpe" || !alias.ValidCPEKey(e.Value) || !alias.ValidCPEKey(e.Target) || e.Value == e.Target {
			return fmt.Errorf("aliases: entry %q", e.Value)
		}
		if len(out) >= alias.MaxEntries {
			return errors.New("aliases: too many entries")
		}
		out = append(out, e)
		return nil
	})
	if err == nil && len(out) != m.Files[0].Records {
		err = fmt.Errorf("aliases: %d entries, the manifest says %d", len(out), m.Files[0].Records)
	}
	return out, err
}

// ReadAliasState reads the learner state of a verified manifest.
func ReadAliasState(dir string, m *AliasManifest) (map[string]alias.Obs, error) {
	out := map[string]alias.Obs{}
	err := eachLine(filepath.Join(dir, AliasesStateFile), func(line []byte) error {
		var o alias.Obs
		if err := strictLine(line, &o); err != nil {
			return err
		}
		if len(out) >= alias.MaxStateObs || len(o.Names) > alias.MaxPerObs || len(o.Pairs) > alias.MaxPerObs || len(o.CPEs) > alias.MaxPerObs {
			return errors.New("aliases: state over the caps")
		}
		for _, p := range o.Pairs {
			if !alias.ValidCPEKey(p[0]) || !alias.ValidCPEKey(p[1]) {
				return fmt.Errorf("aliases: state of %s", o.ID)
			}
		}
		for _, k := range append(append([]string{}, o.Names...), o.CPEs...) {
			if !alias.ValidCPEKey(k) {
				return fmt.Errorf("aliases: state of %s", o.ID)
			}
		}
		out[o.ID] = o
		return nil
	})
	if err == nil && len(out) != m.Files[1].Records {
		err = fmt.Errorf("aliases: %d observations, the manifest says %d", len(out), m.Files[1].Records)
	}
	return out, err
}
