package card

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// first is the repository's first card; every test mutates a copy of it.
func first(t *testing.T) *Card {
	t.Helper()
	raw, err := os.ReadFile("../../cards/OCA-2026-0001.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Decode(raw)
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
	cs, err := LoadDir("../../cards")
	if err != nil || len(cs) == 0 {
		t.Fatal(len(cs), err)
	}
	c := first(t)
	if c.Published() {
		t.Fatal("a card in review is not published")
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
			if err := c.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestReviewModes(t *testing.T) {
	c := reviewed(first(t), ModeTwoPerson, "reviewer")
	if err := c.Validate(); err != nil || !c.Published() {
		t.Fatal(err)
	}
	c = reviewed(first(t), ModeSingleReview, first(t).Review.Author)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c = reviewed(first(t), ModeTwoPerson, "reviewer")
	c.Review.State, c.Review.WithdrawnReason = StateWithdrawn, "The vendor retracted the advisory."
	if err := c.Validate(); err != nil || !c.Published() {
		t.Fatal(err)
	}
}

func TestDecodeStrict(t *testing.T) {
	raw, _ := json.Marshal(first(t))
	if _, err := Decode(append(raw[:len(raw)-1], []byte(`,"extra":1}`)...)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := Decode(append(raw, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := Decode(make([]byte, MaxCardBytes+1)); err == nil {
		t.Fatal("oversized card accepted")
	}
}

func TestLoadDirNameMustBeID(t *testing.T) {
	dir := t.TempDir()
	raw, _ := os.ReadFile("../../cards/OCA-2026-0001.json")
	if err := os.WriteFile(filepath.Join(dir, "OCA-2026-0002.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
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
	older := reviewed(first(t), ModeTwoPerson, "reviewer")
	prev[0].Revision = 2
	if err := CheckSuccessor(prev, []*Card{older}); err == nil {
		t.Fatal("rollback accepted")
	}
}

func FuzzDecode(f *testing.F) {
	raw, _ := os.ReadFile("../../cards/OCA-2026-0001.json")
	f.Add(raw)
	f.Add([]byte(`{"schema":"openctem.advisory-card/v1"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := Decode(b)
		if err == nil && c.Validate() != nil {
			t.Fatal("decoded card does not validate")
		}
	})
}
