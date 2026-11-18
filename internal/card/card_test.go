package card

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testNow is the clock the tests validate against: a day after the
// repository card's dates.
var testNow = time.Date(2026, 11, 19, 18, 0, 0, 0, time.UTC)

// first is the repository's first card; every test mutates a copy of it.
func first(t *testing.T) *Card {
	t.Helper()
	raw, err := os.ReadFile("../../cards/OCA-2026-0001.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Decode(raw, testNow)
	if err != nil {
		t.Fatalf("the repository's card must be valid: %v", err)
	}
	return c
}

func reviewed(c *Card, mode, by string) *Card {
	at := c.UpdatedAt.Add(time.Hour)
	c.Review.State, c.Review.Mode, c.Review.ReviewedBy, c.Review.ReviewedAt = StateReviewed, mode, by, &at
	return c
}

func TestRepositoryCardsAreValid(t *testing.T) {
	cs, err := LoadDir("../../cards", time.Now())
	if err != nil || len(cs) == 0 {
		t.Fatal(len(cs), err)
	}
	c := first(t)
	if c.Review.State != StateReported || !c.Published() {
		t.Fatal("the first card ships in the fast lane: reported, published")
	}
	if len(c.Vulns) != 5 || c.Exploitation.Status != ExploitPoCPublic {
		t.Fatalf("%+v", c.Vulns)
	}
}

func TestValidateRefusals(t *testing.T) {
	cases := map[string]func(c *Card){
		"bad schema":              func(c *Card) { c.Schema = "openctem.advisory-card/v9" },
		"bad id":                  func(c *Card) { c.ID = "CARD-1" },
		"uncited fact":            func(c *Card) { c.Workarounds[0].Sources = nil },
		"unknown source":          func(c *Card) { c.Detection[0].Sources = []string{"nowhere"} },
		"http source":             func(c *Card) { c.Sources[0].URL = "http://nginx.org/" },
		"javascript url":          func(c *Card) { c.PoC[0].URL = "javascript:alert(1)" },
		"credentials in url":      func(c *Card) { c.PoC[0].URL = "https://u:p@example.com/" },
		"markup in text":          func(c *Card) { c.Title = "nginx <script>alert(1)</script>" },
		"bidi override":           func(c *Card) { c.Summary = "safe \u202e txt.exe" },
		"zero width":              func(c *Card) { c.Nicknames = []string{"NGINX\u200b2Root"} },
		"newline":                 func(c *Card) { c.Workarounds[0].Text = "a\nb" },
		"line separator":          func(c *Card) { c.Title = "nginx\u2028Patch now" },
		"paragraph separator":     func(c *Card) { c.Summary = "nginx\u2029Patch now" },
		"link in title":           func(c *Card) { c.Title = "Patch now at https://evil.example" },
		"www host in summary":     func(c *Card) { c.Summary = "Patch now at WWW.evil.example" },
		"link in a note":          func(c *Card) { c.Exploitation.Note = "see ftp://evil.example" },
		"long title":              func(c *Card) { c.Title = strings.Repeat("x", maxTitle+1) },
		"unknown predicate":       func(c *Card) { c.Affected[0].Conditions = []Condition{{Predicate: "anything_goes"}} },
		"other without note":      func(c *Card) { c.Affected[0].Conditions = []Condition{{Predicate: "other"}} },
		"bad version":             func(c *Card) { c.Affected[0].Ranges[0].Fixed = "1.30.7; rm -rf" },
		"fixed and last":          func(c *Card) { c.Affected[0].Ranges[0].LastAffected = "1.30.6" },
		"ranges when unpublished": func(c *Card) { c.Affected[0].Versions = "not_published" },
		"no ranges when published": func(c *Card) {
			c.Affected[0].Ranges = nil
		},
		"unknown product": func(c *Card) { c.Affected[0].Product = "a:example:other" },
		"unknown vuln":    func(c *Card) { c.Workarounds[0].Blocks = []string{"CVE-2020-0001"} },
		"uncovered vuln": func(c *Card) {
			c.Vulns = append(c.Vulns, Vuln{ID: "CVE-2026-0001", Title: "x", Sources: []string{"circl-tr105"}})
		},
		"bad vuln id":       func(c *Card) { c.Vulns[0].ID = "CVE-26-1" },
		"bad exploitation":  func(c *Card) { c.Exploitation.Status = "guessed" },
		"poc without links": func(c *Card) { c.PoC = nil },
		"itw on a blog only": func(c *Card) {
			c.Exploitation.Status = ExploitInTheWild
			c.Sources = append(c.Sources, Source{ID: "blog", URL: "https://example.com/b", Publisher: "Blog", Tier: "researcher", Title: "b", RetrievedAt: c.UpdatedAt})
			c.Exploitation.Sources = []string{"blog"}
		},
		"ranges from one blog": func(c *Card) {
			c.Sources = append(c.Sources, Source{ID: "blog", URL: "https://example.com/b", Publisher: "Blog", Tier: "researcher", Title: "b", RetrievedAt: c.UpdatedAt})
			c.Affected[0].Sources = []string{"blog"}
		},
		"history gap":          func(c *Card) { c.Revision = 2 },
		"reviewer in review":   func(c *Card) { c.Review.ReviewedBy = "someone" },
		"reviewed no reviewer": func(c *Card) { c.Review.State = StateReviewed },
		"two person by author": func(c *Card) { reviewed(c, ModeTwoPerson, c.Review.Author) },
		"single by other":      func(c *Card) { reviewed(c, ModeSingleReview, "someone-else") },
		"withdrawn, no reason": func(c *Card) { reviewed(c, ModeTwoPerson, "reviewer").Review.State = StateWithdrawn },
		"reviewed before edit": func(c *Card) {
			reviewed(c, ModeTwoPerson, "reviewer")
			at := c.UpdatedAt.Add(-time.Minute)
			c.Review.ReviewedAt = &at
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := first(t)
			mut(c)
			if err := c.Validate(testNow); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestReviewModes(t *testing.T) {
	c := reviewed(first(t), ModeTwoPerson, "reviewer")
	if err := c.Validate(testNow); err != nil || !c.Published() {
		t.Fatal(err)
	}
	c = reviewed(first(t), ModeSingleReview, first(t).Review.Author)
	if err := c.Validate(testNow); err != nil {
		t.Fatal(err)
	}
	c = reviewed(first(t), ModeTwoPerson, "reviewer")
	c.Review.State, c.Review.WithdrawnReason = StateWithdrawn, "The vendor retracted the advisory."
	if err := c.Validate(testNow); err != nil || !c.Published() {
		t.Fatal(err)
	}
}

func TestDecodeStrict(t *testing.T) {
	raw, _ := json.Marshal(first(t))
	if _, err := Decode(append(raw[:len(raw)-1], []byte(`,"extra":1}`)...), testNow); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := Decode(append(raw, []byte(` {}`)...), testNow); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := Decode(make([]byte, MaxCardBytes+1), testNow); err == nil {
		t.Fatal("oversized card accepted")
	}
}

func TestLoadDirNameMustBeID(t *testing.T) {
	dir := t.TempDir()
	raw, _ := os.ReadFile("../../cards/OCA-2026-0001.json")
	if err := os.WriteFile(filepath.Join(dir, "OCA-2026-0002.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir, testNow); err == nil {
		t.Fatal("file named after another id accepted")
	}
}

func TestCheckSuccessor(t *testing.T) {
	prev := []*Card{reviewed(first(t), ModeTwoPerson, "reviewer")}
	if err := CheckSuccessor(prev, nil); err == nil {
		t.Fatal("dropped card accepted")
	}
	same := reviewed(first(t), ModeTwoPerson, "reviewer")
	if err := CheckSuccessor(prev, []*Card{same}); err != nil {
		t.Fatal(err)
	}
	edited := reviewed(first(t), ModeTwoPerson, "reviewer")
	edited.UpdatedAt = edited.UpdatedAt.Add(time.Minute)
	if err := CheckSuccessor(prev, []*Card{edited}); err == nil {
		t.Fatal("change without a new revision accepted")
	}
	withdrawn := reviewed(first(t), ModeTwoPerson, "reviewer")
	withdrawn.Review.State = StateWithdrawn
	if err := CheckSuccessor(prev, []*Card{withdrawn}); err == nil {
		t.Fatal("withdrawal without a new revision accepted")
	}
	raised := reviewed(first(t), ModeTwoPerson, "reviewer")
	raised.Exploitation.Status = ExploitInTheWild
	if err := CheckSuccessor(prev, []*Card{raised}); err == nil {
		t.Fatal("content changed at an equal revision (same updated_at) accepted")
	}
	widened := reviewed(first(t), ModeTwoPerson, "reviewer")
	widened.Affected[0].Ranges[0].Fixed = "9.9.9"
	if err := CheckSuccessor(prev, []*Card{widened}); err == nil {
		t.Fatal("range changed at an equal revision accepted")
	}

	next := func() *Card {
		c := reviewed(first(t), ModeTwoPerson, "reviewer")
		c.Revision = 2
		c.UpdatedAt = c.UpdatedAt.Add(2 * time.Hour)
		at := c.UpdatedAt
		c.Review.ReviewedAt = &at
		c.History = append(c.History, Change{Revision: 2, At: c.UpdatedAt, Note: "Corrected the fixed version."})
		return c
	}
	if err := CheckSuccessor(prev, []*Card{next()}); err != nil {
		t.Fatal(err)
	}
	stale := next()
	stale.UpdatedAt = prev[0].UpdatedAt
	stale.History[1].At = stale.UpdatedAt
	if err := CheckSuccessor(prev, []*Card{stale}); err == nil {
		t.Fatal("a new revision without a later updated_at accepted")
	}
	unlogged := next()
	unlogged.History[1].At = unlogged.UpdatedAt.Add(-time.Minute)
	if err := CheckSuccessor(prev, []*Card{unlogged}); err == nil {
		t.Fatal("a new revision whose history entry is not dated updated_at accepted")
	}

	older := reviewed(first(t), ModeTwoPerson, "reviewer")
	prev[0].Revision = 2
	if err := CheckSuccessor(prev, []*Card{older}); err == nil {
		t.Fatal("rollback accepted")
	}
}

// seeds are a reviewed and a withdrawn card, each with proof-of-concept
// links, workarounds and detection ideas, so the fuzzer starts on the
// review and nested-list paths.
func seeds(t testing.TB) [][]byte {
	raw, err := os.ReadFile("../../cards/OCA-2026-0001.json")
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, state := range []string{StateReviewed, StateWithdrawn} {
		c, err := Decode(raw, testNow)
		if err != nil {
			t.Fatal(err)
		}
		reviewed(c, ModeTwoPerson, "reviewer")
		if state == StateWithdrawn {
			c.Review.State, c.Review.WithdrawnReason = StateWithdrawn, "The vendor retracted the advisory."
		}
		if err := c.Validate(testNow); err != nil || len(c.PoC) == 0 || len(c.Workarounds) == 0 || len(c.Detection) == 0 {
			t.Fatalf("seed %s: %v", state, err)
		}
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func TestSeedsRoundTrip(t *testing.T) {
	for _, b := range seeds(t) {
		roundTrip(t, b)
	}
}

// roundTrip: a card that decodes encodes back to a card that decodes to
// the same content.
func roundTrip(t *testing.T, b []byte) {
	c, err := Decode(b, testNow)
	if err != nil {
		return
	}
	if c.Validate(testNow) != nil {
		t.Fatal("decoded card does not validate")
	}
	again, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(again, testNow)
	if err != nil {
		t.Fatalf("re-encoded card refused: %v", err)
	}
	d1, _ := Digest(c)
	d2, _ := Digest(back)
	if d1 != d2 {
		t.Fatal("round trip changed the card")
	}
}

func FuzzDecode(f *testing.F) {
	raw, _ := os.ReadFile("../../cards/OCA-2026-0001.json")
	f.Add(raw)
	for _, b := range seeds(f) {
		f.Add(b)
	}
	f.Add([]byte(`{"schema":"openctem.advisory-card/v1"}`))
	f.Fuzz(roundTrip)
}

func TestValidateRefusesFutureDates(t *testing.T) {
	far := time.Date(2062, 11, 18, 18, 0, 0, 0, time.UTC)
	cases := map[string]func(c *Card){
		"reviewed_at": func(c *Card) { c.Review.ReviewedAt = &far },
		"updated_at": func(c *Card) {
			c.UpdatedAt = far
			c.Review.ReviewedAt = &far
		},
		"published_at": func(c *Card) { c.PublishedAt = far },
		"history":      func(c *Card) { c.History[0].At = far },
		"retrieved_at": func(c *Card) { c.Sources[0].RetrievedAt = far },
		"first_seen":   func(c *Card) { c.PoC[0].FirstSeen = "2062-11-18" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := reviewed(first(t), ModeTwoPerson, "reviewer")
			mut(c)
			if err := c.Validate(testNow); err == nil || !strings.Contains(err.Error(), "in the future") {
				t.Fatalf("a date in 2062 accepted: %v", err)
			}
		})
	}
	// Up to MaxClockSkew ahead is a clock difference, not a typo.
	c := reviewed(first(t), ModeTwoPerson, "reviewer")
	if err := c.Validate(c.Review.ReviewedAt.Add(-MaxClockSkew + time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(c.Review.ReviewedAt.Add(-MaxClockSkew - time.Minute)); err == nil {
		t.Fatal("a reviewed_at past the skew accepted")
	}
}

func TestReviewersAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ReviewersFile)
	if _, err := LoadReviewers(path); err == nil {
		t.Fatal("a missing allowlist accepted")
	}
	if err := os.WriteFile(path, []byte("# reviewers\n\nAlice\nbob-2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rv, err := LoadReviewers(path)
	if err != nil {
		t.Fatal(err)
	}
	listed := reviewed(first(t), ModeTwoPerson, "alice")
	if err := CheckReviewers([]*Card{listed, first(t)}, rv); err != nil {
		t.Fatal(err)
	}
	stranger := reviewed(first(t), ModeTwoPerson, "mallory")
	if err := CheckReviewers([]*Card{stranger}, rv); err == nil {
		t.Fatal("a reviewer outside the allowlist accepted")
	}
	if err := os.WriteFile(path, []byte("alice bob\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReviewers(path); err == nil {
		t.Fatal("a malformed line accepted")
	}
}

func TestRepositoryReviewersFile(t *testing.T) {
	rv, err := LoadReviewers("../../cards/" + ReviewersFile)
	if err != nil || len(rv) == 0 {
		t.Fatal(len(rv), err)
	}
}

func TestReportedFastLane(t *testing.T) {
	c := first(t)
	if err := c.Validate(testNow); err != nil {
		t.Fatal(err)
	}
	blog := Source{ID: "blog", URL: "https://example.com/b", Publisher: "Blog", Tier: "researcher", Title: "b", RetrievedAt: c.UpdatedAt}
	cases := map[string]func(c *Card){
		"exploitation from a blog only": func(c *Card) {
			c.Sources = append(c.Sources, blog)
			c.Exploitation.Sources = []string{"blog"}
		},
		"poc from a blog only": func(c *Card) {
			c.Sources = append(c.Sources, blog)
			c.PoC[0].Sources = []string{"blog"}
		},
		"names a reviewer": func(c *Card) { c.Review.ReviewedBy = "someone" },
		"names a mode":     func(c *Card) { c.Review.Mode = ModeTwoPerson },
		"has a withdrawal": func(c *Card) { c.Review.WithdrawnReason = "x" },
		"unknown state":    func(c *Card) { c.Review.State = "fast" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := first(t)
			mut(c)
			if err := c.Validate(testNow); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// The same blog-only fact is fine once a person reviewed the card.
	r := reviewed(first(t), ModeTwoPerson, "reviewer")
	r.Sources = append(r.Sources, blog)
	r.PoC[0].Sources = []string{"blog"}
	if err := r.Validate(testNow); err != nil {
		t.Fatal(err)
	}
	// A reported card names no reviewer, so the allowlist does not apply.
	if err := CheckReviewers([]*Card{first(t)}, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
}
