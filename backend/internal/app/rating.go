package app

import (
	"strings"

	"limier/internal/scanners/imports"
	"limier/internal/scanners/source"
)

// SonarQube-style ratings of a code scan (SPECS F3).

// shortcut: costs are estimates, tune with user feedback.
// remediationMinutes is the fixed SQALE remediation cost of one finding, per rule id.
var remediationMinutes = map[string]int{
	"quality.console-log":      2,
	"quality.debugger":         2,
	"quality.todo":             10,
	"quality.ts-any":           5,
	"quality.ts-ignore":        10,
	"quality.empty-catch":      10,
	"quality.nested-ternary":   5,
	"quality.too-many-params":  20,
	"quality.deep-nesting":     20,
	"quality.long-function":    30,
	"quality.complex-function": 30,
	"quality.long-file":        60,
	imports.RuleUnusedExport:   2,
	imports.RuleUnusedDep:      5,
	imports.RuleDeadFile:       10,
	imports.RuleCycle:          60,
	"dupes.block":              15,
	"node.eol":                 60,
}

// Fallback costs of rule families without their own entry.
const (
	secretMinutes  = 30 // rotate the key, then remove it from the code
	sastMinutes    = 30
	defaultMinutes = 10
)

// reliabilityRules are the quality rules that point at bugs rather than readability (Sonar "Bugs").
var reliabilityRules = map[string]bool{
	"quality.empty-catch": true, // swallowed errors
	"quality.debugger":    true, // stops the app in production
}

// devMinutesPerLine is Sonar's default cost to develop one line of code (sqale dev cost).
const devMinutesPerLine = 30

func ruleMinutes(rule string) int {
	if m, ok := remediationMinutes[rule]; ok {
		return m
	}
	switch {
	case strings.HasPrefix(rule, "secret."):
		return secretMinutes
	case strings.HasPrefix(rule, "sast."):
		return sastMinutes
	}
	return defaultMinutes
}

// debtMinutes sums the remediation cost of the findings, clones and import problems.
func debtMinutes(d codeDetails) int {
	n := 0
	for _, list := range [][]source.Issue{d.Secrets, d.Flaws, d.Smells, d.UnusedExports} {
		for _, i := range list {
			n += ruleMinutes(i.Rule)
		}
	}
	// shortcut: clones are capped at dupes.MaxClones, so huge projects underestimate duplication debt; count all blocks if it matters.
	n += len(d.Duplication.Clones) * remediationMinutes["dupes.block"]
	n += len(d.Cycles) * remediationMinutes[imports.RuleCycle]
	n += len(d.DeadFiles) * remediationMinutes[imports.RuleDeadFile]
	n += len(d.UnusedDependencies) * remediationMinutes[imports.RuleUnusedDep]
	return n
}

var sevRating = map[string]int{source.Low: 1, source.Medium: 2, source.High: 3, "critical": 4}

func letter(r int) string { return string(rune('A' + min(r, 4))) }

// worstRating maps the worst severity to a letter: none or info A, low B, medium C, high D, critical E.
// bump raises each finding one step: a leaked secret is a Sonar blocker, and code rules stop at high.
func worstRating(issues []source.Issue, keep func(string) bool, bump int) int {
	worst := 0
	for _, i := range issues {
		if r := sevRating[i.Severity]; r > 0 && keep(i.Rule) {
			worst = max(worst, min(r+bump, 4))
		}
	}
	return worst
}

// codeRatings returns the security, reliability and maintainability letters of a scan.
func codeRatings(d codeDetails, loc int64, debt int) (sec, rel, maint string) {
	all := func(string) bool { return true }
	s := max(worstRating(d.Secrets, all, 1), worstRating(d.Flaws, all, 0))
	r := worstRating(d.Smells, func(rule string) bool { return reliabilityRules[rule] }, 0)
	return letter(s), letter(r), maintainabilityRating(debt, loc)
}

// maintainabilityRating rates the debt ratio debt / (loc × 30 min): A ≤5 %, B ≤10 %, C ≤20 %, D ≤50 %, E above.
func maintainabilityRating(debt int, loc int64) string {
	if debt == 0 {
		return "A"
	}
	if loc <= 0 {
		return "E"
	}
	ratio := float64(debt) / float64(loc*devMinutesPerLine)
	for i, limit := range []float64{0.05, 0.10, 0.20, 0.50} {
		if ratio <= limit {
			return letter(i)
		}
	}
	return "E"
}
