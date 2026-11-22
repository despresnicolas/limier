package app

import (
	"testing"

	"limier/internal/scanners/dupes"
	"limier/internal/scanners/source"
)

func TestDebtMinutes(t *testing.T) {
	d := codeDetails{
		Secrets:            []source.Issue{{Rule: "secret.npm-token"}},                                 // 30
		Flaws:              []source.Issue{{Rule: "sast.xss"}, {Rule: "node.eol"}},                     // 30 + 60
		Smells:             []source.Issue{{Rule: "quality.console-log"}, {Rule: "quality.unknown-x"}}, // 2 + 10
		UnusedExports:      []source.Issue{{Rule: "imports.unused-export"}},                            // 2
		Duplication:        dupes.Report{Clones: make([]dupes.Clone, 2)},                               // 30
		Cycles:             [][]string{{"a", "b"}},                                                     // 60
		DeadFiles:          []string{"x.js"},                                                           // 10
		UnusedDependencies: []string{"lodash"},                                                         // 5
	}
	if got := debtMinutes(d); got != 239 {
		t.Fatalf("debt = %d, want 239", got)
	}
	if got := debtMinutes(codeDetails{}); got != 0 {
		t.Fatalf("empty debt = %d", got)
	}
}

func TestCodeRatings(t *testing.T) {
	iss := func(rule, sev string) []source.Issue { return []source.Issue{{Rule: rule, Severity: sev}} }
	cases := []struct {
		name          string
		d             codeDetails
		loc           int64
		debt          int
		sec, rel, mnt string
	}{
		{"empty project", codeDetails{}, 0, 0, "A", "A", "A"},
		{"info only", codeDetails{Flaws: iss("sast.x", source.Info)}, 100, 0, "A", "A", "A"},
		{"sast low", codeDetails{Flaws: iss("sast.x", source.Low)}, 100, 0, "B", "A", "A"},
		{"sast medium", codeDetails{Flaws: iss("sast.x", source.Medium)}, 100, 0, "C", "A", "A"},
		{"sast high", codeDetails{Flaws: iss("sast.x", source.High)}, 100, 0, "D", "A", "A"},
		{"secret high is blocker", codeDetails{Secrets: iss("secret.x", source.High)}, 100, 0, "E", "A", "A"},
		{"secret medium", codeDetails{Secrets: iss("secret.x", source.Medium)}, 100, 0, "D", "A", "A"},
		{"reliability rule", codeDetails{Smells: iss("quality.empty-catch", source.Medium)}, 100, 0, "A", "C", "A"},
		{"smell is not reliability", codeDetails{Smells: iss("quality.long-file", source.High)}, 100, 0, "A", "A", "A"},
		// 100 lines × 30 min = 3000 min of development.
		{"ratio 5%", codeDetails{}, 100, 150, "A", "A", "A"},
		{"ratio 5.03%", codeDetails{}, 100, 151, "A", "A", "B"},
		{"ratio 10%", codeDetails{}, 100, 300, "A", "A", "B"},
		{"ratio 20%", codeDetails{}, 100, 600, "A", "A", "C"},
		{"ratio 50%", codeDetails{}, 100, 1500, "A", "A", "D"},
		{"ratio 51%", codeDetails{}, 100, 1530, "A", "A", "E"},
		{"debt without code", codeDetails{}, 0, 30, "A", "A", "E"},
	}
	for _, c := range cases {
		sec, rel, mnt := codeRatings(c.d, c.loc, c.debt)
		if sec != c.sec || rel != c.rel || mnt != c.mnt {
			t.Errorf("%s: got %s %s %s, want %s %s %s", c.name, sec, rel, mnt, c.sec, c.rel, c.mnt)
		}
	}
}
