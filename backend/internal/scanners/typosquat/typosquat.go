// Package typosquat flags npm package names that imitate a popular package (typosquatting).
package typosquat

import (
	_ "embed"
	"strings"
)

// shortcut: static list from memory, refresh from a download-count dataset once a year.
// One name per line, most popular first: the line number is the rank.
//
//go:embed popular.txt
var popularTxt string

// legit holds real packages that sit one edit away from a popular name.
var legit = map[string]bool{
	"preact":   true, // react
	"utils":    true, // util
	"react-ga": true, // react-is
	"inherit":  true, // inherits
}

var (
	rank     = map[string]int{}    // popular name -> rank
	byNorm   = map[string]string{} // normalized key -> most popular name with that key
	byLen    = map[int][]string{}  // name length -> popular names, in rank order
	orgScope = map[string]bool{}   // scopes of popular packages, owned by their org on npm
)

func init() {
	for _, n := range strings.Split(popularTxt, "\n") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, dup := rank[n]; dup {
			continue
		}
		rank[n] = len(rank)
		if k := norm(n); byNorm[k] == "" {
			byNorm[k] = n
		}
		byLen[len(n)] = append(byLen[len(n)], n)
		if s := scope(n); s != "" {
			orgScope[s] = true
		}
	}
}

// Lookalike returns the popular npm package that name imitates, if any.
func Lookalike(name string) (popular string, ok bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if len(name) < 4 || legit[name] {
		return "", false
	}
	if _, isPopular := rank[name]; isPopular {
		return "", false
	}
	// Only the org can publish under its scope, so @babel/xyz or @types/xyz cannot be a squat.
	if orgScope[scope(name)] {
		return "", false
	}

	best := ""
	better := func(c string) {
		if best == "" || rank[c] < rank[best] {
			best = c
		}
	}
	if c := byNorm[norm(name)]; c != "" {
		better(c)
	}

	// shortcut: very short names collide with many legit packages (type/tape, nest/next), so the
	// edit-distance rule starts at 5 chars; lower it if real squats of 4-char names slip through.
	maxDist := 0
	switch {
	case len(name) >= 8:
		maxDist = 2
	case len(name) >= 5:
		maxDist = 1
	}
	scoped := strings.HasPrefix(name, "@")
	for l := len(name) - maxDist; l <= len(name)+maxDist && maxDist > 0; l++ {
		for _, c := range byLen[l] {
			if best != "" && rank[c] >= rank[best] {
				break // byLen is in rank order: nothing better in this bucket
			}
			// babel-core vs @babel/core are distinct legit packages: never compare across.
			if strings.HasPrefix(c, "@") != scoped {
				continue
			}
			// Distance 2 needs both names long: fsevents is not events.
			if d := osa(name, c, maxDist); d <= maxDist && (d == 1 || len(c) >= 8) {
				better(c)
				break
			}
		}
	}
	return best, best != ""
}

// norm drops separators and folds digit/letter swaps, so "cross_env" and "cr0ss-env" meet "cross-env".
func norm(s string) string { return normer.Replace(s) }

var normer = strings.NewReplacer("-", "", "_", "", ".", "", "0", "o", "1", "l")

func scope(s string) string {
	if i := strings.IndexByte(s, '/'); strings.HasPrefix(s, "@") && i > 0 {
		return s[:i]
	}
	return ""
}

// osa is the optimal-string-alignment (restricted Damerau-Levenshtein) distance between a and b.
// It returns max+1 as soon as the distance must exceed max.
func osa(a, b string, max int) int {
	prev2 := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		rowMin := i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d := min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d = min(d, prev2[j-2]+1)
			}
			cur[j] = d
			rowMin = min(rowMin, d)
		}
		if rowMin > max {
			return max + 1
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(b)]
}
