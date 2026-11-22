// Package nodeeol flags a project that targets a Node.js major past or near its end of life.
// It reads .nvmrc, .node-version and package.json engines.node at the project root.
// shortcut: root files only, workspace packages are not read; walk them if users with monorepos ask.
package nodeeol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"limier/internal/scanners/source"
)

// Rule is the code finding id.
const Rule = "node.eol"

// eol maps a Node major to its end-of-life date (endoflife.date). Major 0 covers 0.10 and 0.12.
// shortcut: static table, update at each Node major release.
var eol = map[int]string{
	0: "2016-12-31", 4: "2018-04-30", 5: "2016-06-30", 6: "2019-04-30", 7: "2017-06-30",
	8: "2019-12-31", 9: "2018-06-30", 10: "2021-04-30", 11: "2019-06-01", 12: "2022-04-30",
	13: "2020-06-01", 14: "2023-04-30", 15: "2021-06-01", 16: "2023-09-11", 17: "2022-06-01",
	18: "2025-04-30", 19: "2023-06-01", 20: "2026-04-30", 21: "2024-06-01", 22: "2027-04-30",
	23: "2025-06-01", 24: "2028-04-30", 25: "2026-06-01", 26: "2029-04-30",
}

// ltsNames maps nvm's lts/<codename> aliases to their major. Moving aliases (lts/*, node,
// stable, latest, current, system) and unknown codenames are ignored: they follow the
// installed Node, not a fixed major.
var ltsNames = map[string]int{
	"argon": 4, "boron": 6, "carbon": 8, "dubnium": 10, "erbium": 12, "fermium": 14,
	"gallium": 16, "hydrogen": 18, "iron": 20, "jod": 22, "krypton": 24,
}

var (
	comparator = regexp.MustCompile(`(?:^|[^\d.])(<=?|>=?|[~^=])?\s*v?(\d+)`)
	nodeKey    = regexp.MustCompile(`"node"\s*:`)
)

// Analyze returns one issue per root file whose Node major is EOL (high) or ends within 6 months (medium).
func Analyze(dir string, now time.Time) []source.Issue {
	var out []source.Issue
	check := func(file string, line, major int) {
		d, ok := eol[major]
		if !ok {
			return // unknown major: newer than the table
		}
		end, _ := time.Parse(time.DateOnly, d)
		sev := ""
		switch {
		case !now.Before(end):
			sev = source.High
		case now.AddDate(0, 6, 0).After(end):
			sev = source.Medium
		default:
			return
		}
		out = append(out, source.Issue{Rule: Rule, Severity: sev, File: file, Line: line,
			Detail: fmt.Sprintf("Node %d · EOL %s", major, d)})
	}
	for _, name := range []string{".nvmrc", ".node-version"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		first, _, _ := strings.Cut(string(b), "\n")
		if m, ok := pinnedMajor(first); ok {
			check(name, 1, m)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
		var pkg struct {
			Engines struct {
				Node string `json:"node"`
			} `json:"engines"`
		}
		if json.Unmarshal(b, &pkg) == nil {
			if m, ok := LowestMajor(pkg.Engines.Node); ok {
				check("package.json", engineLine(b), m)
			}
		}
	}
	return out
}

// pinnedMajor reads a .nvmrc / .node-version line: "v16.20.2", "18", "lts/hydrogen".
func pinnedMajor(s string) (int, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if name, ok := strings.CutPrefix(s, "lts/"); ok {
		m, ok := ltsNames[name]
		return m, ok
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "node/"), "v")
	major, _, _ := strings.Cut(s, ".")
	m, err := strconv.Atoi(major)
	return m, err == nil
}

// LowestMajor returns the lowest Node major a semver range allows, e.g. ">=16" -> 16,
// "^14.17 || >=16" -> 14. Upper bounds ("<20") are skipped; "*" and "" give false.
func LowestMajor(rng string) (int, bool) {
	low, found := 0, false
	for _, alt := range strings.Split(rng, "||") {
		for _, c := range comparator.FindAllStringSubmatch(alt, -1) {
			if strings.HasPrefix(c[1], "<") {
				continue
			}
			if m, err := strconv.Atoi(c[2]); err == nil && (!found || m < low) {
				low, found = m, true
			}
			break // the first lower bound of an alternative is its minimum
		}
	}
	return low, found
}

// engineLine returns the line of engines.node in package.json, 1 if not found.
func engineLine(b []byte) int {
	start := bytes.Index(b, []byte(`"engines"`))
	if start < 0 {
		return 1
	}
	loc := nodeKey.FindIndex(b[start:])
	if loc == nil {
		return 1
	}
	return source.LineAt(b, start+loc[0])
}
