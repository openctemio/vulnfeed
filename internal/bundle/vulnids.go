package bundle

// The vulnerability id alias map travels next to the bundle as its own
// optional signed manifest, like the alias dictionary: vulnids.manifest.dsse.json
// names the entries file (SHA-256, size, records), carries the bundle
// sequence it was built with (a platform accepts it only for the release its
// verified pointer names) and a version that grows only when the entries
// change.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openctemio/vulnfeed/internal/dsse"
	"github.com/openctemio/vulnfeed/internal/vulnid"
)

// Vulnerability id map files.
const (
	VulnIDsSchema              = "openctem.vulnfeed.vulnids/v1"
	VulnIDsManifestPayloadType = "application/vnd.openctem.vulnfeed.vulnids+json"
	VulnIDsManifestFile        = "vulnids.manifest.dsse.json"
	VulnIDsEntriesFile         = "vulnids.jsonl.gz"
	unsignedVulnIDsManifest    = "vulnids.manifest.json"
)

// VulnIDManifest is the signed description of a vulnerability id map.
type VulnIDManifest struct {
	Schema    string       `json:"schema"`
	Sequence  uint64       `json:"sequence"`
	Version   uint64       `json:"version"`
	CreatedAt time.Time    `json:"created_at"`
	ExpiresAt time.Time    `json:"expires_at"`
	Files     []File       `json:"files"`
	Stats     vulnid.Stats `json:"stats"`
}

func validEntry(e vulnid.Entry) bool {
	src := vulnid.SourceOSV
	if len(e.ID) > 5 && e.ID[:5] == "GHSA-" {
		src = vulnid.SourceGHSA
	}
	return vulnid.ValidID(e.ID) && vulnid.ValidCVE(e.CVE) && e.Source == src
}

// WriteVulnIDs writes the entries (sorted by id, no duplicate) and the
// unsigned manifest into dir. The version is prev's when the entries file is
// byte-identical to prev's, else the release sequence (above prev's).
func WriteVulnIDs(dir string, sequence uint64, prev *VulnIDManifest, entries []vulnid.Entry, stats vulnid.Stats,
	now time.Time) (*VulnIDManifest, error) {
	if len(entries) > vulnid.MaxEntries {
		return nil, fmt.Errorf("refusing to publish %d vulnerability id entries (over the cap)", len(entries))
	}
	for i, e := range entries {
		if !validEntry(e) || (i > 0 && entries[i-1].ID >= e.ID) {
			return nil, fmt.Errorf("refusing to publish an invalid or unordered vulnerability id entry %q", e.ID)
		}
	}
	ef, err := writeGz(filepath.Join(dir, VulnIDsEntriesFile), func(enc *json.Encoder) error {
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
	if ef.Size > vulnid.MaxFileBytes {
		return nil, fmt.Errorf("refusing to publish %d compressed bytes of vulnerability ids (over the cap)", ef.Size)
	}
	ef.Name, ef.Records = VulnIDsEntriesFile, len(entries)
	now = now.UTC().Truncate(time.Second)
	m := &VulnIDManifest{Schema: VulnIDsSchema, Sequence: sequence, Version: sequence, CreatedAt: now, ExpiresAt: now.Add(Validity),
		Files: []File{ef}, Stats: stats}
	if prev != nil {
		switch {
		case len(prev.Files) > 0 && prev.Files[0].SHA256 == ef.SHA256:
			m.Version = prev.Version
		case m.Version <= prev.Version:
			m.Version = prev.Version + 1
		}
	}
	return m, writeJSON(filepath.Join(dir, unsignedVulnIDsManifest), m)
}

// VerifyVulnIDs verifies the manifest in dir against the key set: its
// signature, schema, the bundle sequence it must carry, validity and its
// file. A directory without the manifest gives (nil, nil).
func VerifyVulnIDs(dir string, ks *dsse.KeySet, sequence uint64) (*VulnIDManifest, error) {
	path := filepath.Join(dir, VulnIDsManifestFile)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	var m VulnIDManifest
	if err := verifyJSON(ks, path, VulnIDsManifestPayloadType, &m); err != nil {
		return nil, err
	}
	switch {
	case m.Schema != VulnIDsSchema:
		return nil, fmt.Errorf("vulnids: schema %q", m.Schema)
	case m.Sequence != sequence:
		return nil, fmt.Errorf("vulnids: built for sequence %d, the release is %d", m.Sequence, sequence)
	case m.Version == 0:
		return nil, errors.New("vulnids: version 0")
	case m.ExpiresAt.Sub(m.CreatedAt) > Validity:
		return nil, fmt.Errorf("vulnids: valid for more than %s", Validity)
	case len(m.Files) != 1 || m.Files[0].Name != VulnIDsEntriesFile:
		return nil, errors.New("vulnids: unexpected files")
	}
	if m.Files[0].Size > vulnid.MaxFileBytes {
		return nil, errors.New("vulnids: entries file over the cap")
	}
	if err := checkFile(filepath.Join(dir, m.Files[0].Name), m.Files[0]); err != nil {
		return nil, err
	}
	return &m, nil
}

// ReadVulnIDEntries reads and validates the entries of a verified manifest.
func ReadVulnIDEntries(dir string, m *VulnIDManifest) ([]vulnid.Entry, error) {
	var out []vulnid.Entry
	err := eachLine(filepath.Join(dir, VulnIDsEntriesFile), func(line []byte) error {
		var e vulnid.Entry
		if err := strictLine(line, &e); err != nil {
			return err
		}
		if !validEntry(e) || (len(out) > 0 && out[len(out)-1].ID >= e.ID) {
			return fmt.Errorf("vulnids: entry %q", e.ID)
		}
		if len(out) >= vulnid.MaxEntries {
			return errors.New("vulnids: too many entries")
		}
		out = append(out, e)
		return nil
	})
	if err == nil && len(out) != m.Files[0].Records {
		err = fmt.Errorf("vulnids: %d entries, the manifest says %d", len(out), m.Files[0].Records)
	}
	return out, err
}
