// Package ignore reads `limier-ignore` comments, the user's way to mark a false positive
// in the code (SPECS F3), and drops the matching code findings.
//
//	eval(x) // limier-ignore sast.eval -- input is a constant
//	// limier-ignore sast.eval, sast.xss -- alone on its line: applies to the next code line
//	/* limier-ignore-file quality.console-log -- CLI output */  (in the first 10 lines)
//
// A directive must name at least one rule: a bare `limier-ignore` would hide anything
// and is not accepted. A secret stays reported unless the directive gives a reason.
// Callers never pass dependency vulnerabilities, clones or node.eol: those can't be ignored.
package ignore

import (
	"bytes"
	"regexp"
	"strings"

	"limier/internal/scanners/source"
)

// fileHeader is how many first lines may hold a limier-ignore-file directive.
const fileHeader = 10

// Directive hides Rules on Line (0 = the whole file).
type Directive struct {
	Rules  []string
	Reason string
	Line   int
}

// Ignored is one finding a directive hid, kept for transparency in the Code tab.
type Ignored struct {
	Rule   string `json:"rule"`
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Reason string `json:"reason,omitempty"`
}

var (
	directiveRe = regexp.MustCompile(`(//|/\*|#|<!--)\s*limier-ignore(-file)?(?:\s(.*))?$`)
	ruleRe      = regexp.MustCompile(`^[a-z][a-z0-9-]*\.[a-z0-9.-]+$`)
)

// parseLine returns the directive of one line, with ok false when there is none.
// code tells whether real code comes before the comment on that line.
func parseLine(line string) (d Directive, file, code, ok bool) {
	m := directiveRe.FindStringSubmatchIndex(line)
	if m == nil {
		return d, false, false, false
	}
	rest := ""
	if m[6] >= 0 {
		rest = line[m[6]:m[7]]
	}
	rest = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(rest), "-->"), "*/"))
	rules, reason, _ := strings.Cut(rest, "--")
	for _, r := range strings.Split(rules, ",") {
		if r = strings.TrimSpace(r); ruleRe.MatchString(r) {
			d.Rules = append(d.Rules, r)
		}
	}
	d.Reason = strings.TrimSpace(reason)
	return d, m[4] >= 0, strings.TrimSpace(line[:m[0]]) != "", len(d.Rules) > 0
}

// Parse reads the directives of a raw file (comments are needed, so never the blanked Code).
// A trailing comment applies to its own line; a comment alone on its line applies to
// the next non-empty line that is not itself a directive.
func Parse(src []byte) []Directive {
	lines := strings.Split(string(bytes.ReplaceAll(src, []byte("\r\n"), []byte("\n"))), "\n")
	var out []Directive
	for i, l := range lines {
		if !strings.Contains(l, "limier-ignore") {
			continue
		}
		d, file, code, ok := parseLine(l)
		switch {
		case !ok:
		case file:
			if i < fileHeader {
				out = append(out, d) // Line 0: whole file
			}
		case code:
			d.Line = i + 1
			out = append(out, d)
		default:
			for j := i + 1; j < len(lines); j++ {
				if t := strings.TrimSpace(lines[j]); t != "" && !strings.Contains(t, "limier-ignore") {
					d.Line = j + 1
					out = append(out, d)
					break
				}
			}
		}
	}
	return out
}

// Filter removes from each list the issues a directive covers and returns them.
// It parses only the files that have issues.
func Filter(files []source.File, lists ...*[]source.Issue) []Ignored {
	src := make(map[string][]byte, len(files))
	for _, f := range files {
		src[f.Path] = f.Src
	}
	parsed := map[string][]Directive{}
	var ignored []Ignored
	for _, list := range lists {
		kept := (*list)[:0]
		for _, is := range *list {
			ds, done := parsed[is.File]
			if !done {
				ds = Parse(src[is.File])
				parsed[is.File] = ds
			}
			if d, hit := match(ds, is); hit {
				ignored = append(ignored, Ignored{Rule: is.Rule, File: is.File, Line: is.Line, Reason: d.Reason})
			} else {
				kept = append(kept, is)
			}
		}
		*list = kept
	}
	return ignored
}

func match(ds []Directive, is source.Issue) (Directive, bool) {
	for _, d := range ds {
		if d.Line != 0 && d.Line != is.Line {
			continue
		}
		// A secret is serious: hiding one needs a written reason.
		if strings.HasPrefix(is.Rule, "secret.") && d.Reason == "" {
			continue
		}
		for _, r := range d.Rules {
			if r == is.Rule {
				return d, true
			}
		}
	}
	return Directive{}, false
}
