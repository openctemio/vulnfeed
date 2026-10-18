package alias

import (
	"bufio"
	_ "embed"
	"fmt"
	"sort"
	"strings"
)

// Learning thresholds: a CNA name maps to a CPE product when at least
// minSupport CVEs pair them and at least minAgreement of the CVEs that
// pair the name agree; a CNA vendor maps to a CPE vendor with stronger
// evidence (minVendorSupport), and only where the resulting product is a
// known CPE product.
const (
	minSupport       = 3
	minVendorSupport = 5
	minAgreement     = 0.9
)

// Caps on one observation and on the state.
const (
	MaxPerObs   = 64
	MaxStateObs = 2_000_000
	MaxEntries  = 200_000
	// TopUnresolved is how many unresolved names the stats list.
	TopUnresolved = 100
)

// Reasons a CVE names no product that a dictionary could resolve.
const (
	MissingNoProduct = "no_product" // no vendor/product, or placeholders ("n/a")
	MissingPackage   = "package"    // a package name only (a package identity, not a CPE product)
)

// Item is one affected item of a CVE record as the CNA (or an ADP) states
// it: names as written and the CPE names it lists.
type Item struct {
	Vendor, Product, PackageName string
	CPEs                         []string // "part:vendor:product"
}

// Obs is what one CVE says about product identity; the state of the
// learner is one Obs per CVE, replaced whenever the CVE is read again.
type Obs struct {
	ID string `json:"id"`
	// Names: "a:vendor:product" name keys of CNA items that list no CPE.
	Names []string `json:"names,omitempty"`
	// Pairs: a name key and the one CPE product the same record states
	// for it (evidence for learning).
	Pairs [][2]string `json:"pairs,omitempty"`
	// CPEs: CPE products the record names (CNA, ADP or NVD).
	CPEs []string `json:"cpes,omitempty"`
	// Missing: set when no item names a product (MissingNoProduct,
	// MissingPackage).
	Missing string `json:"missing,omitempty"`
}

// NameKey is the dictionary key of a CNA vendor and product: the
// application part and both names in the CPE naming convention.
func NameKey(vendor, product string) string {
	vk, pk := VendorKey(vendor), ProductKey(product)
	if vk == "" || pk == "" {
		return ""
	}
	return "a:" + vk + ":" + pk
}

// Observe reduces one CVE to its Obs. cna are the CNA's items, adp the
// ADP containers' items, nvd the CPE products of the CVE's NVD
// configurations.
func Observe(id string, cna, adp []Item, nvd []string) Obs {
	o := Obs{ID: id}
	cpes := map[string]bool{}
	adpByName := map[string]map[string]bool{}
	for _, it := range adp {
		k := NameKey(it.Vendor, it.Product)
		for _, c := range validCPEs(it.CPEs) {
			cpes[c] = true
			if k != "" {
				if adpByName[k] == nil {
					adpByName[k] = map[string]bool{}
				}
				adpByName[k][c] = true
			}
		}
	}
	for _, c := range validCPEs(nvd) {
		cpes[c] = true
	}
	names := map[string]bool{}
	pairs := map[[2]string]bool{}
	packages := false
	for _, it := range cna {
		k := NameKey(it.Vendor, it.Product)
		own := validCPEs(it.CPEs)
		for _, c := range own {
			cpes[c] = true
		}
		if k == "" {
			if strings.TrimSpace(it.PackageName) != "" {
				packages = true
			}
			continue
		}
		evidence := distinct(own)
		if len(evidence) == 0 {
			evidence = keys(adpByName[k])
		}
		if len(evidence) == 1 {
			pairs[[2]string{k, evidence[0]}] = true
		}
		if len(own) == 0 {
			names[k] = true
		}
	}
	// One unnamed CNA product and one NVD product: the same product.
	if nv := distinct(validCPEs(nvd)); len(names) == 1 && len(nv) == 1 {
		for k := range names {
			pairs[[2]string{k, nv[0]}] = true
		}
	}
	for k := range names {
		if !cpes[k] {
			o.Names = append(o.Names, k)
		}
	}
	for p := range pairs {
		if p[0] != p[1] {
			o.Pairs = append(o.Pairs, p)
		}
	}
	o.CPEs = keys(cpes)
	sort.Strings(o.Names)
	sort.Slice(o.Pairs, func(i, j int) bool { return o.Pairs[i][0]+o.Pairs[i][1] < o.Pairs[j][0]+o.Pairs[j][1] })
	o.Names, o.Pairs, o.CPEs = capped(o.Names), cappedPairs(o.Pairs), capped(o.CPEs)
	if len(o.Names) == 0 && len(o.CPEs) == 0 {
		o.Missing = MissingNoProduct
		if packages {
			o.Missing = MissingPackage
		}
	}
	return o
}

// validCPEs keeps the well-formed "part:vendor:product" values.
func validCPEs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		if ValidCPEKey(c) {
			out = append(out, c)
		}
	}
	return out
}

// ValidCPEKey reports whether s is "part:vendor:product" with a concrete,
// lower-case vendor and product of at most 128 characters each.
func ValidCPEKey(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 3 || (parts[0] != "a" && parts[0] != "o" && parts[0] != "h") {
		return false
	}
	for _, p := range parts[1:] {
		if p == "" || len(p) > 128 || p == "*" || p == "-" || strings.ContainsAny(p, "*? \t") || strings.ToLower(p) != p {
			return false
		}
		for _, r := range p {
			if r < 0x20 || r == 0x7f {
				return false
			}
		}
	}
	return true
}

func distinct(in []string) []string {
	m := map[string]bool{}
	for _, s := range in {
		m[s] = true
	}
	return keys(m)
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func capped(s []string) []string {
	if len(s) > MaxPerObs {
		return s[:MaxPerObs]
	}
	return s
}

func cappedPairs(s [][2]string) [][2]string {
	if len(s) > MaxPerObs {
		return s[:MaxPerObs]
	}
	return s
}

// Entry is one dictionary entry: the product known as Value is the
// product Target. Basis says why (curated, learned, vendor, part).
type Entry struct {
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Target  string `json:"target"`
	Basis   string `json:"basis"`
	Support int    `json:"support"`
}

// Bases of an entry.
const (
	BasisCurated = "curated"
	BasisLearned = "learned"
	BasisVendor  = "vendor"
	BasisPart    = "part"
	BasisVariant = "variant"
)

// Dictionary maps name keys to CPE products.
type Dictionary struct {
	products map[string]Entry
	vendors  map[string]string // CNA vendor key → CPE vendor
	vocab    map[string]bool   // known CPE products
	cpeVend  map[string]bool   // vendors of known CPE products
	byVP     map[string]string // "vendor:product" → a known "part:vendor:product"
}

// Stats is the coverage of a dictionary over the published CVEs of the
// state.
type Stats struct {
	Published    int `json:"published"`
	Resolved     int `json:"resolved"`
	Unresolvable int `json:"unresolvable"`
	Unresolved   int `json:"unresolved"`
	// NewVendor: of the unresolved, the CVEs whose every CNA name has a
	// vendor no CPE product uses (directly or through a vendor mapping):
	// there is no CPE identity to resolve to, so the CNA name is the
	// product's identity. Reported apart, not counted in Coverage.
	NewVendor int `json:"new_vendor"`
	// Coverage is (Resolved + Unresolvable) / Published.
	Coverage float64 `json:"coverage"`
	// ResolvedByName counts the resolved CVEs that name their product only
	// by CNA strings (they match only through the dictionary).
	ResolvedByName int `json:"resolved_by_name"`
	// ResolvedByEntry: of those, the CVEs that need a dictionary entry
	// (their CNA name is not itself a known CPE product).
	ResolvedByEntry int `json:"resolved_by_entry"`
	Entries         int `json:"entries"`
	// TopUnresolved lists the most frequent unresolved name keys (public
	// advisory strings) for curation.
	TopUnresolved []NameCount `json:"top_unresolved,omitempty"`
}

// NameCount is a name key and the number of CVEs that use it.
type NameCount struct {
	Name string `json:"name"`
	CVEs int    `json:"cves"`
}

//go:embed curated.tsv
var curatedTSV string

// Curated returns the reviewed override entries and vendor mappings of
// curated.tsv.
func Curated() ([]Entry, map[string]string, error) {
	var entries []Entry
	vendors := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(curatedTSV))
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) != 3 {
			return nil, nil, fmt.Errorf("curated.tsv:%d: want 3 fields", line)
		}
		switch f[0] {
		case "cpe":
			if !ValidCPEKey(f[1]) || !ValidCPEKey(f[2]) || f[1] == f[2] {
				return nil, nil, fmt.Errorf("curated.tsv:%d: bad cpe entry", line)
			}
			entries = append(entries, Entry{Kind: "cpe", Value: f[1], Target: f[2], Basis: BasisCurated})
		case "vendor":
			if Key(f[1]) != f[1] || Key(f[2]) != f[2] || f[1] == "" || f[2] == "" {
				return nil, nil, fmt.Errorf("curated.tsv:%d: bad vendor entry", line)
			}
			vendors[f[1]] = f[2]
		default:
			return nil, nil, fmt.Errorf("curated.tsv:%d: unknown kind %q", line, f[0])
		}
	}
	return entries, vendors, sc.Err()
}

// Build learns the dictionary from the state. extraVocab adds known CPE
// products (the NVD products of the snapshot).
func Build(state map[string]Obs, extraVocab []string) (*Dictionary, error) {
	cur, curVendors, err := Curated()
	if err != nil {
		return nil, err
	}
	d := &Dictionary{products: map[string]Entry{}, vendors: map[string]string{}, vocab: map[string]bool{}, byVP: map[string]string{},
		cpeVend: map[string]bool{}}
	addVocab := func(c string) {
		if !ValidCPEKey(c) {
			return
		}
		d.vocab[c] = true
		d.cpeVend[strings.Split(c, ":")[1]] = true
		vp := c[2:]
		if cur, ok := d.byVP[vp]; !ok || c < cur {
			d.byVP[vp] = c
		}
	}
	for _, c := range extraVocab {
		addVocab(c)
	}
	pairCount := map[string]map[string]int{}
	vendorCount := map[string]map[string]int{}
	for _, o := range state {
		for _, c := range o.CPEs {
			addVocab(c)
		}
		seenVendor := map[[2]string]bool{}
		for _, p := range o.Pairs {
			if pairCount[p[0]] == nil {
				pairCount[p[0]] = map[string]int{}
			}
			pairCount[p[0]][p[1]]++
			vk, cv := strings.Split(p[0], ":")[1], strings.Split(p[1], ":")[1]
			if !seenVendor[[2]string{vk, cv}] {
				seenVendor[[2]string{vk, cv}] = true
				if vendorCount[vk] == nil {
					vendorCount[vk] = map[string]int{}
				}
				vendorCount[vk][cv]++
			}
		}
	}
	for name, targets := range pairCount {
		if t, n, ok := winner(targets, minSupport); ok && t != name {
			d.products[name] = Entry{Kind: "cpe", Value: name, Target: t, Basis: BasisLearned, Support: n}
		}
	}
	for vk, targets := range vendorCount {
		if t, _, ok := winner(targets, minVendorSupport); ok && t != vk {
			d.vendors[vk] = t
		}
	}
	for vk, cv := range curVendors {
		d.vendors[vk] = cv
	}
	for _, e := range cur {
		d.products[e.Value] = e
	}
	return d, nil
}

// winner returns the target with the most support when it has at least
// min CVEs and the agreement threshold.
func winner(counts map[string]int, min int) (string, int, bool) {
	best, bestN, total := "", 0, 0
	for t, n := range counts {
		total += n
		if n > bestN || (n == bestN && t < best) {
			best, bestN = t, n
		}
	}
	if bestN < min || float64(bestN) < minAgreement*float64(total) {
		return "", 0, false
	}
	return best, bestN, true
}

// Resolve returns the CPE product a name key stands for and the basis;
// ok is false when nothing resolves it. A name key that is itself a known
// CPE product resolves to itself (basis "").
func (d *Dictionary) Resolve(name string) (string, string, bool) {
	if e, ok := d.products[name]; ok {
		return e.Target, e.Basis, true
	}
	if d.vocab[name] {
		return name, "", true
	}
	parts := strings.SplitN(name, ":", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	// The same vendor:product known under another part (o, h).
	if c, ok := d.byVP[parts[1]+":"+parts[2]]; ok {
		return c, BasisPart, true
	}
	if cv, ok := d.vendors[parts[1]]; ok {
		if c, ok := d.byVP[cv+":"+parts[2]]; ok {
			return c, BasisVendor, true
		}
	}
	// The product name repeats the vendor ("Microsoft Edge") or ends in a
	// generic word ("NX-OS Software"): the shorter name, when it is a known
	// CPE product of the same (or the mapped) vendor.
	vendors := []string{parts[1]}
	if cv, ok := d.vendors[parts[1]]; ok {
		vendors = append(vendors, cv)
	}
	for _, p := range productVariants(parts[1], parts[2]) {
		for _, v := range vendors {
			if c, ok := d.byVP[v+":"+p]; ok {
				return c, BasisVariant, true
			}
		}
	}
	return "", "", false
}

// Generic trailing words of a product name.
var genericSuffixes = []string{"_software", "_firmware", "_application", "_app", "_plugin", "_server_software"}

// productVariants returns shorter forms of a product name: without the
// vendor's name in front, without a generic trailing word, and both.
func productVariants(vendor, product string) []string {
	var out []string
	base := []string{product}
	if p := strings.TrimPrefix(product, vendor+"_"); p != product && p != "" {
		out = append(out, p)
		base = append(base, p)
	}
	for _, b := range base {
		for _, sfx := range genericSuffixes {
			if p := strings.TrimSuffix(b, sfx); p != b && p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// Entries returns the dictionary entries for every name key the state
// uses (plus every curated entry), sorted by value, at most MaxEntries.
func (d *Dictionary) Entries(state map[string]Obs) []Entry {
	support := map[string]int{}
	for _, o := range state {
		for _, n := range o.Names {
			support[n]++
		}
		for _, p := range o.Pairs {
			if _, ok := support[p[0]]; !ok {
				support[p[0]] = 0
			}
		}
	}
	out := map[string]Entry{}
	for name, n := range support {
		t, basis, ok := d.Resolve(name)
		if !ok || t == name {
			continue
		}
		e := Entry{Kind: "cpe", Value: name, Target: t, Basis: basis, Support: n}
		if le, ok := d.products[name]; ok && le.Support > 0 {
			e.Support = le.Support
		}
		out[name] = e
	}
	for name, e := range d.products {
		if e.Basis == BasisCurated {
			out[name] = e
		}
	}
	list := make([]Entry, 0, len(out))
	for _, e := range out {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Value < list[j].Value })
	if len(list) > MaxEntries {
		list = list[:MaxEntries]
	}
	return list
}

// Coverage classifies the state's CVEs (published ones; the caller passes
// only those): resolved when the record names a CPE product or one of its
// CNA names resolves, unresolvable when it names no product (Missing),
// unresolved otherwise.
func (d *Dictionary) Coverage(state map[string]Obs, entries int) Stats {
	st := Stats{Entries: entries}
	unresolved := map[string]int{}
	for _, o := range state {
		st.Published++
		switch {
		case len(o.CPEs) > 0:
			st.Resolved++
			continue
		case len(o.Names) == 0:
			st.Unresolvable++
			continue
		}
		resolved, byEntry := false, false
		for _, n := range o.Names {
			if _, basis, ok := d.Resolve(n); ok {
				resolved = true
				byEntry = byEntry || basis != ""
			}
		}
		if resolved {
			st.Resolved++
			st.ResolvedByName++
			if byEntry {
				st.ResolvedByEntry++
			}
			continue
		}
		st.Unresolved++
		if d.allNewVendors(o.Names) {
			st.NewVendor++
		}
		for _, n := range o.Names {
			unresolved[n]++
		}
	}
	if st.Published > 0 {
		st.Coverage = float64(st.Resolved+st.Unresolvable) / float64(st.Published)
	}
	top := make([]NameCount, 0, len(unresolved))
	for n, c := range unresolved {
		top = append(top, NameCount{Name: n, CVEs: c})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].CVEs != top[j].CVEs {
			return top[i].CVEs > top[j].CVEs
		}
		return top[i].Name < top[j].Name
	})
	if len(top) > TopUnresolved {
		top = top[:TopUnresolved]
	}
	st.TopUnresolved = top
	return st
}

// Map returns name key → target for remapping ranges.
func (d *Dictionary) Map(entries []Entry) map[string]string {
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		m[e.Value] = e.Target
	}
	return m
}

// allNewVendors reports whether no name's vendor (or mapped vendor) is the
// vendor of a known CPE product.
func (d *Dictionary) allNewVendors(names []string) bool {
	for _, n := range names {
		v := strings.Split(n, ":")[1]
		if d.cpeVend[v] || d.cpeVend[d.vendors[v]] {
			return false
		}
	}
	return true
}
