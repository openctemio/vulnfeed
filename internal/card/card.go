// Package card reads and validates advisory cards: hand-written, reviewed,
// product-level statements about a vulnerability that may exist before a CVE
// record or a CPE does. A card names the affected products by catalog key,
// the affected and fixed versions per branch (or says they are not published
// yet), the configuration a vulnerability needs (from a closed list), the
// exploitation status, links to public proof-of-concept write-ups (metadata
// only: no code is ever fetched or stored), workarounds, detection ideas and
// the CVE ids it groups. Every fact cites at least one public source.
//
// Cards live as JSON files in a reviewed directory (cards/ in this
// repository). The builder publishes only reviewed and withdrawn cards, as
// the "cards" stream of the signed intel side manifest; a platform that does
// not know the stream skips it.
//
// Review is a role: a card records its author and its reviewer. With two
// different people the review mode is two_person; a card published by its
// own author must say single_review, so the gap stays visible.
package card

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Format and stream.
const (
	Schema     = "openctem.advisory-card/v1"
	StreamName = "cards"
	// Attribution travels with the stream in the signed manifest.
	Attribution = "OpenCTEM advisory cards: reviewed statements, each fact cites its public source"
)

// Caps (the platform enforces the same).
const (
	MaxCards     = 2000
	MaxCardBytes = 64 << 10
	maxTitle     = 160
	maxSummary   = 600
	maxNote      = 300
	maxName      = 80
	maxURL       = 512
	maxVulns     = 64
	maxProducts  = 16
	maxAffected  = 128
	maxRanges    = 16
	maxConds     = 8
	maxLinks     = 16
	maxSources   = 32
	maxNicknames = 8
	maxHistory   = 100
)

// Review states.
const (
	StateInReview  = "in_review"
	StateReviewed  = "reviewed"
	StateWithdrawn = "withdrawn"
)

// Review modes.
const (
	ModeTwoPerson    = "two_person"
	ModeSingleReview = "single_review"
)

// Exploitation statuses, weakest first.
const (
	ExploitNone            = "none"
	ExploitPoCPublic       = "poc_public"
	ExploitWeaponised      = "weaponised"
	ExploitInTheWild       = "exploited_itw"
	ExploitVendorConfirmed = "vendor_confirmed_exploited"
)

// Exploitations lists the statuses, weakest first.
func Exploitations() []string {
	return []string{ExploitNone, ExploitPoCPublic, ExploitWeaponised, ExploitInTheWild, ExploitVendorConfirmed}
}

// Predicates is the closed list of configuration conditions a platform can
// evaluate. A new predicate is a reviewed code change, never free text;
// anything else is "other" with a note, which a platform cannot use to
// narrow.
func Predicates() []string {
	return []string{"http2_enabled", "http3_enabled", "mail_proxy_auth_http", "resolver_runtime_dns", "kernel_sctp_reachable", "other"}
}

var (
	idRe       = regexp.MustCompile(`^OCA-[0-9]{4}-[0-9]{4,6}$`)
	cveRe      = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	ghsaRe     = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
	keyRe      = regexp.MustCompile(`^[aoh]:[a-z0-9][a-z0-9._\-]{0,63}:[a-z0-9][a-z0-9._\-+]{0,95}$`)
	versionRe  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~:_\-]{0,63}$`)
	sourceIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{0,47}$`)
	handleRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-]{0,39}$`)
)

// Source is one public document a card cites.
type Source struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	Publisher   string    `json:"publisher"`
	Tier        string    `json:"tier"` // vendor | cna | cert | researcher | press
	Title       string    `json:"title"`
	RetrievedAt time.Time `json:"retrieved_at"`
}

// Vuln is one vulnerability id the card groups.
type Vuln struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Sources []string `json:"sources"`
}

// Product is one affected product by catalog key (part:vendor:product).
type Product struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// Range is one affected range of upstream versions: introduced (inclusive,
// empty = from the first release) up to fixed (exclusive) or last_affected
// (inclusive); neither = no fix published yet.
type Range struct {
	Branch       string `json:"branch,omitempty"`
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Condition is a configuration a vulnerability needs.
type Condition struct {
	Predicate string `json:"predicate"`
	Note      string `json:"note,omitempty"`
}

// Affected says which versions of a product a set of the card's
// vulnerabilities affect, and under which conditions.
type Affected struct {
	Product    string      `json:"product"`
	Vulns      []string    `json:"vulns"`
	Versions   string      `json:"versions"` // published | not_published
	Ranges     []Range     `json:"ranges,omitempty"`
	Conditions []Condition `json:"conditions,omitempty"`
	Sources    []string    `json:"sources"`
}

// Fact is a short cited statement.
type Fact struct {
	Status  string   `json:"status,omitempty"`
	Level   string   `json:"level,omitempty"`
	Note    string   `json:"note,omitempty"`
	Sources []string `json:"sources"`
}

// Link is metadata of a public proof-of-concept or write-up. The content is
// never fetched, stored or redistributed.
type Link struct {
	URL       string   `json:"url"`
	Kind      string   `json:"kind"` // write_up | exploit_code | scanner_template
	Title     string   `json:"title"`
	FirstSeen string   `json:"first_seen,omitempty"` // YYYY-MM-DD
	Sources   []string `json:"sources"`
}

// Workaround is a mitigation and what it blocks.
type Workaround struct {
	Text    string   `json:"text"`
	Blocks  []string `json:"blocks"`
	Caveat  string   `json:"caveat,omitempty"`
	Sources []string `json:"sources"`
}

// Detection is an idea for finding affected or attacked systems.
type Detection struct {
	Kind    string   `json:"kind"` // safe_check | version_check | config_check | log_hint | host_hint
	Text    string   `json:"text"`
	Sources []string `json:"sources"`
}

// Review is the card's review record.
type Review struct {
	State      string     `json:"state"`
	Author     string     `json:"author"`
	ReviewedBy string     `json:"reviewed_by,omitempty"`
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`
	Mode       string     `json:"mode,omitempty"`
	// WithdrawnReason says why a withdrawn card no longer stands.
	WithdrawnReason string `json:"withdrawn_reason,omitempty"`
}

// Change is one revision of the card (the corrections log).
type Change struct {
	Revision int       `json:"revision"`
	At       time.Time `json:"at"`
	Note     string    `json:"note"`
}

// Card is one advisory card.
type Card struct {
	Schema       string       `json:"schema"`
	ID           string       `json:"id"`
	Revision     int          `json:"revision"`
	Title        string       `json:"title"`
	Nicknames    []string     `json:"nicknames,omitempty"`
	Summary      string       `json:"summary"`
	PublishedAt  time.Time    `json:"published_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	Severity     Fact         `json:"severity"`
	Vulns        []Vuln       `json:"vulns"`
	Products     []Product    `json:"products"`
	Affected     []Affected   `json:"affected"`
	Exploitation Fact         `json:"exploitation"`
	PoC          []Link       `json:"poc,omitempty"`
	Workarounds  []Workaround `json:"workarounds,omitempty"`
	Detection    []Detection  `json:"detection,omitempty"`
	Sources      []Source     `json:"sources"`
	Review       Review       `json:"review"`
	History      []Change     `json:"history"`
}

// Published reports whether the builder publishes the card.
func (c *Card) Published() bool {
	return c.Review.State == StateReviewed || c.Review.State == StateWithdrawn
}

// Decode reads one card strictly: unknown fields, trailing data and
// oversized input are refused.
func Decode(raw []byte) (*Card, error) {
	if len(raw) > MaxCardBytes {
		return nil, fmt.Errorf("card: %d bytes, over %d", len(raw), MaxCardBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Card
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("card: %w", err)
	}
	if dec.More() {
		return nil, errors.New("card: trailing data")
	}
	return &c, c.Validate()
}

// Validate checks every rule a card must meet before it can be published.
//
//nolint:gocyclo // one check per rule, kept in one place on purpose
func (c *Card) Validate() error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("card %s: %s", c.ID, fmt.Sprintf(format, a...))
	}
	switch {
	case c.Schema != Schema:
		return fail("schema %q, want %q", c.Schema, Schema)
	case !idRe.MatchString(c.ID):
		return fail("id must look like OCA-2026-0001")
	case c.Revision < 1:
		return fail("revision must be 1 or more")
	case c.PublishedAt.IsZero() || c.UpdatedAt.IsZero() || c.UpdatedAt.Before(c.PublishedAt):
		return fail("published_at and updated_at are required, updated_at not before published_at")
	}
	if err := text("title", c.Title, maxTitle, true); err != nil {
		return fail("%v", err)
	}
	if err := text("summary", c.Summary, maxSummary, true); err != nil {
		return fail("%v", err)
	}
	if len(c.Nicknames) > maxNicknames {
		return fail("more than %d nicknames", maxNicknames)
	}
	for _, n := range c.Nicknames {
		if err := text("nickname", n, 40, true); err != nil {
			return fail("%v", err)
		}
	}

	// Sources first: every fact must cite one of them.
	if len(c.Sources) == 0 || len(c.Sources) > maxSources {
		return fail("needs 1 to %d sources", maxSources)
	}
	src := map[string]Source{}
	for _, s := range c.Sources {
		switch {
		case !sourceIDRe.MatchString(s.ID) || src[s.ID].ID != "":
			return fail("source id %q is malformed or repeated", s.ID)
		case !slices.Contains([]string{"vendor", "cna", "cert", "researcher", "press"}, s.Tier):
			return fail("source %s: tier must be vendor, cna, cert, researcher or press", s.ID)
		case s.RetrievedAt.IsZero():
			return fail("source %s: retrieved_at is required", s.ID)
		}
		if err := httpsURL(s.URL); err != nil {
			return fail("source %s: %v", s.ID, err)
		}
		if err := text("publisher", s.Publisher, maxName, true); err != nil {
			return fail("source %s: %v", s.ID, err)
		}
		if err := text("title", s.Title, maxTitle, true); err != nil {
			return fail("source %s: %v", s.ID, err)
		}
		src[s.ID] = s
	}
	cite := func(what string, ids []string) error {
		if len(ids) == 0 {
			return fail("%s cites no source", what)
		}
		for _, id := range ids {
			if src[id].ID == "" {
				return fail("%s cites unknown source %q", what, id)
			}
		}
		return nil
	}
	// authoritative: a vendor, CNA or CERT source, or two publishers.
	authoritative := func(ids []string) bool {
		pubs := map[string]bool{}
		for _, id := range ids {
			s := src[id]
			if s.Tier == "vendor" || s.Tier == "cna" || s.Tier == "cert" {
				return true
			}
			pubs[strings.ToLower(s.Publisher)] = true
		}
		return len(pubs) >= 2
	}

	if !slices.Contains([]string{"critical", "high", "medium", "low"}, c.Severity.Level) {
		return fail("severity.level must be critical, high, medium or low")
	}
	if err := text("severity.note", c.Severity.Note, maxNote, false); err != nil {
		return fail("%v", err)
	}
	if err := cite("severity", c.Severity.Sources); err != nil {
		return err
	}

	if len(c.Vulns) == 0 || len(c.Vulns) > maxVulns {
		return fail("needs 1 to %d vulnerabilities", maxVulns)
	}
	vulns := map[string]bool{}
	for _, v := range c.Vulns {
		if !(cveRe.MatchString(v.ID) || ghsaRe.MatchString(v.ID)) || len(v.ID) > 32 || vulns[v.ID] {
			return fail("vulnerability id %q is malformed or repeated", v.ID)
		}
		vulns[v.ID] = true
		if err := text("vulnerability title", v.Title, maxTitle, true); err != nil {
			return fail("%s: %v", v.ID, err)
		}
		if err := cite(v.ID, v.Sources); err != nil {
			return err
		}
	}
	knownVulns := func(what string, ids []string) error {
		if len(ids) == 0 {
			return fail("%s names no vulnerability", what)
		}
		for _, id := range ids {
			if !vulns[id] {
				return fail("%s names %q, which the card does not list", what, id)
			}
		}
		return nil
	}

	if len(c.Products) == 0 || len(c.Products) > maxProducts {
		return fail("needs 1 to %d products", maxProducts)
	}
	products := map[string]bool{}
	for _, p := range c.Products {
		if !keyRe.MatchString(p.Key) || products[p.Key] {
			return fail("product key %q is malformed (part:vendor:product) or repeated", p.Key)
		}
		products[p.Key] = true
		if err := text("product name", p.Name, maxName, true); err != nil {
			return fail("%v", err)
		}
	}
	if len(c.Affected) == 0 || len(c.Affected) > maxAffected {
		return fail("needs 1 to %d affected statements", maxAffected)
	}
	covered := map[string]bool{}
	for i, a := range c.Affected {
		what := fmt.Sprintf("affected[%d]", i)
		if !products[a.Product] {
			return fail("%s names product %q, which the card does not list", what, a.Product)
		}
		if err := knownVulns(what, a.Vulns); err != nil {
			return err
		}
		for _, v := range a.Vulns {
			covered[v] = true
		}
		switch a.Versions {
		case "published":
			if len(a.Ranges) == 0 || len(a.Ranges) > maxRanges {
				return fail("%s: published versions need 1 to %d ranges", what, maxRanges)
			}
		case "not_published":
			if len(a.Ranges) != 0 {
				return fail("%s: not_published versions take no ranges", what)
			}
		default:
			return fail("%s: versions must be published or not_published", what)
		}
		for _, r := range a.Ranges {
			if err := r.validate(); err != nil {
				return fail("%s: %v", what, err)
			}
		}
		if len(a.Conditions) > maxConds {
			return fail("%s: more than %d conditions", what, maxConds)
		}
		for _, cd := range a.Conditions {
			if !slices.Contains(Predicates(), cd.Predicate) {
				return fail("%s: condition %q is not in the closed list", what, cd.Predicate)
			}
			if err := text("condition note", cd.Note, maxNote, cd.Predicate == "other"); err != nil {
				return fail("%s: %v", what, err)
			}
		}
		if err := cite(what, a.Sources); err != nil {
			return err
		}
		if !authoritative(a.Sources) {
			return fail("%s: affected products and ranges need a vendor, CNA or CERT source, or two publishers", what)
		}
	}
	for v := range vulns {
		if !covered[v] {
			return fail("%s has no affected statement", v)
		}
	}

	if !slices.Contains(Exploitations(), c.Exploitation.Status) {
		return fail("exploitation.status must be one of %s", strings.Join(Exploitations(), ", "))
	}
	if err := text("exploitation.note", c.Exploitation.Note, maxNote, false); err != nil {
		return fail("%v", err)
	}
	if err := cite("exploitation", c.Exploitation.Sources); err != nil {
		return err
	}
	switch c.Exploitation.Status {
	case ExploitPoCPublic, ExploitWeaponised:
		if len(c.PoC) == 0 {
			return fail("exploitation %s needs at least one proof-of-concept or write-up link", c.Exploitation.Status)
		}
	case ExploitInTheWild, ExploitVendorConfirmed:
		if !authoritative(c.Exploitation.Sources) {
			return fail("exploitation %s needs a vendor, CNA or CERT source, or two publishers", c.Exploitation.Status)
		}
	}
	if len(c.PoC) > maxLinks || len(c.Workarounds) > maxLinks || len(c.Detection) > maxLinks {
		return fail("more than %d links, workarounds or detection ideas", maxLinks)
	}
	for i, l := range c.PoC {
		what := fmt.Sprintf("poc[%d]", i)
		if err := httpsURL(l.URL); err != nil {
			return fail("%s: %v", what, err)
		}
		if !slices.Contains([]string{"write_up", "exploit_code", "scanner_template"}, l.Kind) {
			return fail("%s: kind must be write_up, exploit_code or scanner_template", what)
		}
		if err := text("title", l.Title, maxTitle, true); err != nil {
			return fail("%s: %v", what, err)
		}
		if l.FirstSeen != "" {
			if _, err := time.Parse("2006-01-02", l.FirstSeen); err != nil {
				return fail("%s: first_seen must be YYYY-MM-DD", what)
			}
		}
		if err := cite(what, l.Sources); err != nil {
			return err
		}
	}
	for i, w := range c.Workarounds {
		what := fmt.Sprintf("workarounds[%d]", i)
		if err := text("text", w.Text, maxNote, true); err != nil {
			return fail("%s: %v", what, err)
		}
		if err := text("caveat", w.Caveat, maxNote, false); err != nil {
			return fail("%s: %v", what, err)
		}
		if err := knownVulns(what, w.Blocks); err != nil {
			return err
		}
		if err := cite(what, w.Sources); err != nil {
			return err
		}
	}
	for i, d := range c.Detection {
		what := fmt.Sprintf("detection[%d]", i)
		if !slices.Contains([]string{"safe_check", "version_check", "config_check", "log_hint", "host_hint"}, d.Kind) {
			return fail("%s: kind must be safe_check, version_check, config_check, log_hint or host_hint", what)
		}
		if err := text("text", d.Text, maxNote, true); err != nil {
			return fail("%s: %v", what, err)
		}
		if err := cite(what, d.Sources); err != nil {
			return err
		}
	}
	if err := c.validateReview(); err != nil {
		return fail("%v", err)
	}
	return nil
}

func (c *Card) validateReview() error {
	r := c.Review
	if !handleRe.MatchString(r.Author) {
		return errors.New("review.author must be a handle")
	}
	if len(c.History) != c.Revision || len(c.History) > maxHistory {
		return errors.New("history must hold one entry per revision")
	}
	for i, h := range c.History {
		if h.Revision != i+1 || h.At.IsZero() || (i > 0 && h.At.Before(c.History[i-1].At)) {
			return fmt.Errorf("history[%d]: revisions must run 1..n in time order", i)
		}
		if err := text("history note", h.Note, maxNote, true); err != nil {
			return fmt.Errorf("history[%d]: %w", i, err)
		}
	}
	switch r.State {
	case StateInReview:
		if r.ReviewedBy != "" || r.ReviewedAt != nil || r.Mode != "" {
			return errors.New("a card in review has no reviewer yet")
		}
		return nil
	case StateReviewed, StateWithdrawn:
	default:
		return errors.New("review.state must be in_review, reviewed or withdrawn")
	}
	switch {
	case !handleRe.MatchString(r.ReviewedBy) || r.ReviewedAt == nil || r.ReviewedAt.Before(c.UpdatedAt):
		return errors.New("a reviewed card needs reviewed_by and a reviewed_at not before updated_at")
	case r.Mode == ModeTwoPerson && strings.EqualFold(r.Author, r.ReviewedBy):
		return errors.New("two_person review: the reviewer must not be the author")
	case r.Mode == ModeSingleReview && !strings.EqualFold(r.Author, r.ReviewedBy):
		return errors.New("single_review is only for a card its author published; use two_person")
	case r.Mode != ModeTwoPerson && r.Mode != ModeSingleReview:
		return errors.New("review.mode must be two_person or single_review")
	}
	if r.State == StateWithdrawn {
		return text("withdrawn_reason", r.WithdrawnReason, maxNote, true)
	}
	if r.WithdrawnReason != "" {
		return errors.New("withdrawn_reason is only for a withdrawn card")
	}
	return nil
}

func (r Range) validate() error {
	for _, v := range []string{r.Introduced, r.Fixed, r.LastAffected} {
		if v != "" && !versionRe.MatchString(v) {
			return fmt.Errorf("version %q is malformed", v)
		}
	}
	if r.Fixed != "" && r.LastAffected != "" {
		return errors.New("a range has fixed or last_affected, not both")
	}
	if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
		return errors.New("an empty range")
	}
	return text("branch", r.Branch, 40, false)
}

// text checks a display string: valid UTF-8, within its cap, no control,
// bidirectional-override or zero-width characters, no markup brackets. Card
// text is shown to people; it must not be able to restyle or hide anything.
func text(field, s string, maxLen int, required bool) error {
	if s == "" {
		if required {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
	if !utf8.ValidString(s) || len(s) > maxLen*4 || utf8.RuneCountInString(s) > maxLen {
		return fmt.Errorf("%s is over %d characters or not UTF-8", field, maxLen)
	}
	if strings.TrimSpace(s) != s {
		return fmt.Errorf("%s has leading or trailing space", field)
	}
	for _, r := range s {
		switch {
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			return fmt.Errorf("%s holds a control or format character (U+%04X)", field, r)
		case r == '<' || r == '>':
			return fmt.Errorf("%s holds a markup bracket", field)
		}
	}
	return nil
}

func httpsURL(raw string) error {
	if len(raw) > maxURL {
		return errors.New("url too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("url %q must be an absolute https URL without credentials", raw)
	}
	return text("url", raw, maxURL, true)
}

// ExploitationRank orders statuses (none = 0).
func ExploitationRank(s string) int { return slices.Index(Exploitations(), s) }

// LoadDir reads every *.json card of dir, sorted by id. Every card is
// validated; a file whose name is not its id is refused.
func LoadDir(dir string) ([]*Card, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(names) > MaxCards {
		return nil, fmt.Errorf("cards: %d files, over %d", len(names), MaxCards)
	}
	out := make([]*Card, 0, len(names))
	seen := map[string]bool{}
	for _, n := range names {
		fi, err := os.Lstat(n)
		if err != nil {
			return nil, err
		}
		if !fi.Mode().IsRegular() || fi.Size() > MaxCardBytes {
			return nil, fmt.Errorf("%s: not a regular file or over %d bytes", filepath.Base(n), MaxCardBytes)
		}
		raw, err := os.ReadFile(n)
		if err != nil {
			return nil, err
		}
		c, err := Decode(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(n), err)
		}
		if filepath.Base(n) != c.ID+".json" || seen[c.ID] {
			return nil, fmt.Errorf("%s: the file must be named after the card id %s", filepath.Base(n), c.ID)
		}
		seen[c.ID] = true
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// CheckSuccessor refuses a set of published cards that would hide what the
// previous release said: a card may be withdrawn (it stays, with its
// reason) but never dropped, and its revision never goes back.
func CheckSuccessor(prev, next []*Card) error {
	byID := map[string]*Card{}
	for _, c := range next {
		byID[c.ID] = c
	}
	for _, p := range prev {
		n := byID[p.ID]
		switch {
		case n == nil:
			return fmt.Errorf("cards: %s was published before and is missing; withdraw it instead of deleting it", p.ID)
		case n.Revision < p.Revision:
			return fmt.Errorf("cards: %s revision %d is older than the published %d", p.ID, n.Revision, p.Revision)
		case n.Revision == p.Revision && (!n.UpdatedAt.Equal(p.UpdatedAt) || n.Review.State != p.Review.State):
			return fmt.Errorf("cards: %s changed (or was withdrawn) without a new revision", p.ID)
		}
	}
	return nil
}
