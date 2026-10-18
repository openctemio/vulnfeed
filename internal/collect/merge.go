package collect

// Precedence between the two sources of a CVE.
//
// The CVE List carries what the CNA (the CVE's assigner) publishes; NVD
// carries the same CNA text plus its own analysis (CPE configurations, its
// score). A build reads NVD first and the CVE List second, and each record
// is folded into the snapshot field by field:
//
//	field                   winner
//	state (rejected)        either source saying rejected; a CVE List record
//	                        that is published again restores it
//	description, published  the CVE List when its record is read; NVD's copy
//	                        of the CNA text otherwise
//	modified                the later of the two
//	score, severity, CWEs   NVD when it has them; the CNA's (CVE List) only
//	                        fill a CVE NVD has none for
//	affected ranges         NVD's CPE configurations whenever NVD has any for
//	                        the CVE (source "nvd"); the CNA's affected data
//	                        (source "cve5") only for a CVE without them
//
// A CVE's range set comes from one source, never a mix, so a range's
// source tells which rule produced it. A CVE enters the bundle once one
// source gives it ranges (as before); after that both sources keep it
// current.

import (
	"strings"
	"time"

	"github.com/openctemio/vulnfeed/internal/bundle"
	"github.com/openctemio/vulnfeed/internal/cve5"
	"github.com/openctemio/vulnfeed/internal/model"
	"github.com/openctemio/vulnfeed/internal/nvd"
)

// rangesFrom reports whether a CVE's ranges came from source.
func rangesFrom(rs []model.Range, source string) bool {
	return len(rs) > 0 && rs[0].Source == source
}

func later(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil || !b.After(*a):
		return a
	}
	return b
}

// applyRecord folds one converted NVD CVE into the snapshot: a CVE with
// ranges (or already in the snapshot) gets its record and NVD's range set;
// a rejected CVE keeps its record without ranges; a CVE with more
// statements than a bundle carries keeps its previous ranges. NVD having
// no ranges leaves CNA ranges in place, and a score or CWE NVD lacks is
// kept from the CNA.
func applyRecord(s *bundle.Snapshot, rec nvd.Record) {
	prev, known := s.Vulns[rec.Vuln.ID]
	v := rec.Vuln
	if known && !rec.Rejected {
		if v.CVSS == nil {
			v.CVSS, v.Severity = prev.CVSS, prev.Severity
		}
		if len(v.CWEs) == 0 {
			v.CWEs = prev.CWEs
		}
		if v.Description == "" {
			v.Description = prev.Description
		}
	}
	switch {
	case rec.Rejected:
		if known {
			s.SetVuln(v, nil, nil)
		}
	case rec.TooManyRanges:
		if known {
			s.SetVuln(v, s.Ranges[v.ID], nil)
		}
	case len(rec.Ranges) == 0 && !known:
	case len(rec.Ranges) == 0 && rangesFrom(s.Ranges[v.ID], "cve5"):
		s.SetVuln(v, s.Ranges[v.ID], nil)
	default:
		s.SetVuln(v, rec.Ranges, rec.Products)
	}
}

// applyCVE5 folds one CVE List record into the snapshot by the table
// above.
func applyCVE5(s *bundle.Snapshot, rec cve5.Record) {
	id := rec.Vuln.ID
	prev, known := s.Vulns[id]
	if rec.Rejected {
		if known {
			v := prev
			v.Status = cve5.StatusRejected
			if rec.Vuln.Description != "" {
				v.Description = rec.Vuln.Description
			}
			v.Modified = later(prev.Modified, rec.Vuln.Modified)
			s.SetVuln(v, nil, nil)
		}
		return
	}
	var ranges []model.Range
	products := rec.Products
	switch {
	case known && rangesFrom(s.Ranges[id], "nvd"):
		ranges, products = s.Ranges[id], nil
	case rec.TooManyRanges:
		if !known {
			return
		}
		ranges, products = s.Ranges[id], nil
	default:
		ranges = rec.Ranges
	}
	if !known && len(ranges) == 0 {
		return
	}
	v := rec.Vuln
	if known {
		v = prev
		if rec.Vuln.Description != "" {
			v.Description = rec.Vuln.Description
		}
		if rec.Vuln.Published != nil {
			v.Published = rec.Vuln.Published
		}
		v.Modified = later(prev.Modified, rec.Vuln.Modified)
		if strings.EqualFold(prev.Status, cve5.StatusRejected) {
			v.Status = cve5.StatusPublished
		}
		if v.CVSS == nil {
			v.CVSS, v.Severity = rec.Vuln.CVSS, rec.Vuln.Severity
		}
		if len(v.CWEs) == 0 {
			v.CWEs = rec.Vuln.CWEs
		}
	}
	if v.CWEs == nil {
		v.CWEs = []string{}
	}
	s.SetVuln(v, ranges, products)
}
