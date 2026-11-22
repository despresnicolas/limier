// Package quality measures function complexity and spots code smells with quick fixes
// (SPECS F3). It reads source.File.Code only: nothing from the project is executed.
package quality

import (
	"bytes"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"limier/internal/scanners/source"
)

// Function is one JS/TS function with its metrics.
type Function struct {
	File       string `json:"file"`
	Name       string `json:"name"`
	Line       int    `json:"line"`
	EndLine    int    `json:"end_line"`
	Complexity int    `json:"complexity"`
	Lines      int    `json:"lines"`
	Params     int    `json:"params"`
	MaxNesting int    `json:"max_nesting"`
	Churn      int    `json:"churn"` // commits that changed the file in the period (AddChurn), 0 without git
	Score      int    `json:"score"` // churn × complexity, or complexity alone without git history
}

// FileHotspot is a file that is both complex and often changed (CodeScene-style hotspot).
type FileHotspot struct {
	File       string `json:"file"`
	Churn      int    `json:"churn"`
	Complexity int    `json:"complexity"` // of its most complex function
	Lines      int    `json:"lines"`
	Score      int    `json:"score"` // churn × complexity
}

// Report is the result of Analyze.
type Report struct {
	Issues        []source.Issue `json:"issues"` // sorted severity, file, line
	Functions     int            `json:"functions"`
	AvgComplexity float64        `json:"avg_complexity"`
	Hotspots      []Function     `json:"hotspots"`  // top 20 by score (ties: complexity, lines), complexity > 10 only
	HotFiles      []FileHotspot  `json:"hot_files"` // top 10 files by score, empty without git history

	all   []Function
	lines map[string]int // lines per code file
}

// QuickWins lists rule ids that are easy, low-risk fixes (shown as "facile à corriger").
var QuickWins = map[string]bool{
	"quality.nested-ternary": true,
	"quality.empty-catch":    true,
	"quality.console-log":    true,
	"quality.debugger":       true,
	"quality.ts-any":         true,
	"quality.ts-ignore":      true,
	"quality.todo":           true,
}

const anon = "(anonyme)"

var (
	// anchored at a literal hit found by find (a leading literal-free scan of RE2 is slow).
	blockCatchRe   = regexp.MustCompile(`^catch\s*(?:\([^()]*\)\s*)?\{\s*\}`)
	promiseCatchRe = regexp.MustCompile(`^catch\s*\(\s*(?:async\s*)?(?:(?:\([^()]*\)|[\w$]+)\s*(?::\s*[\w$<>\[\]]+\s*)?=>|function\s*\([^()]*\))\s*\{\s*\}\s*\)`)
	catchRe        = regexp.MustCompile(`^catch\b`)
	consoleRe      = regexp.MustCompile(`^console\s*\.\s*(?:log|debug)\b`)
	debuggerRe     = regexp.MustCompile(`^debugger\b`)
	anyRe          = regexp.MustCompile(`^any\b`)
	tsScriptRe     = regexp.MustCompile(`(?i)<script\b[^>]*\blang\s*=\s*["']?ts\b`)
	todoRe         = regexp.MustCompile(`\b(?:TODO|FIXME|HACK|XXX)\b`)
	directiveRe    = regexp.MustCompile(`@ts-(?:ignore|nocheck)\b|eslint-disable(?:-next-line|-line)?`)
	// name of an arrow / function expression from what precedes it: `const a: T =`, `key:`.
	nameRe = regexp.MustCompile(`([\w$]+)\s*(?:(?::[^=;{}()]*)?=|:)\s*(?:async\s*)?(?:<[^()=]*>\s*)?$`)
)

// control keywords whose `(…) {` is a block, not a method.
var control = map[string]bool{"if": true, "for": true, "while": true, "switch": true, "catch": true, "with": true, "await": true, "return": true, "typeof": true}

// words that end a backward scan over a return type: what precedes them is not a signature.
var stopWords = map[string]bool{
	"else": true, "try": true, "finally": true, "do": true, "class": true, "interface": true, "extends": true,
	"implements": true, "enum": true, "namespace": true, "module": true, "return": true, "default": true,
	"export": true, "import": true, "new": true, "case": true, "throw": true, "yield": true, "await": true,
	"const": true, "let": true, "var": true, "type": true, "declare": true,
}

// words that start a new statement, so any open ternary before them is finished.
var stmtWords = map[string]bool{
	"const": true, "let": true, "var": true, "return": true, "if": true, "for": true, "while": true,
	"function": true, "class": true, "export": true, "import": true, "throw": true,
}

var sevRank = map[string]int{source.High: 0, source.Medium: 1, source.Low: 2, source.Info: 3}

// Analyze computes function metrics and code-smell issues of the code files.
func Analyze(files []source.File) Report {
	r := Report{Issues: []source.Issue{}, lines: map[string]int{}}
	var all []Function
	total := 0
	for _, f := range files {
		if !f.IsCode() {
			continue
		}
		r.lines[f.Path] = bytes.Count(f.Src, []byte{'\n'}) + 1
		fns, issues := analyzeFile(f)
		r.Issues = append(r.Issues, issues...)
		for _, fn := range fns {
			total += fn.Complexity
		}
		all = append(all, fns...)
	}
	r.Functions = len(all)
	if len(all) > 0 {
		r.AvgComplexity = math.Round(float64(total)/float64(len(all))*10) / 10
	}
	r.all = all
	r.AddChurn(nil)
	sort.SliceStable(r.Issues, func(i, j int) bool {
		a, b := r.Issues[i], r.Issues[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return r
}

// AddChurn ranks the hotspots again with the commit count of each file (churn.Count): a complex
// file that changes all the time is where bugs hide. With no history it ranks by complexity alone.
func (r *Report) AddChurn(churn map[string]int) {
	r.Hotspots, r.HotFiles = []Function{}, []FileHotspot{}
	byFile := map[string]*FileHotspot{}
	for _, fn := range r.all {
		fn.Churn, fn.Score = churn[fn.File], fn.Complexity
		if len(churn) > 0 {
			fn.Score = fn.Churn * fn.Complexity
		}
		if fn.Complexity > 10 {
			r.Hotspots = append(r.Hotspots, fn)
		}
		if fn.Churn == 0 {
			continue
		}
		h := byFile[fn.File]
		if h == nil {
			h = &FileHotspot{File: fn.File, Churn: fn.Churn, Lines: r.lines[fn.File]}
			byFile[fn.File] = h
		}
		h.Complexity = max(h.Complexity, fn.Complexity)
		h.Score = h.Churn * h.Complexity
	}
	sort.SliceStable(r.Hotspots, func(i, j int) bool {
		a, b := r.Hotspots[i], r.Hotspots[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Complexity > b.Complexity || a.Complexity == b.Complexity && a.Lines > b.Lines
	})
	if len(r.Hotspots) > 20 {
		r.Hotspots = r.Hotspots[:20]
	}
	for _, h := range byFile {
		r.HotFiles = append(r.HotFiles, *h)
	}
	sort.Slice(r.HotFiles, func(i, j int) bool {
		a, b := r.HotFiles[i], r.HotFiles[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.File < b.File
	})
	if len(r.HotFiles) > 10 {
		r.HotFiles = r.HotFiles[:10]
	}
}

type file struct {
	source.File
	code   []byte
	match  []int32 // matching bracket offset for ()[]{}, -1 if none
	starts []int   // line start offsets
}

func (f *file) line(off int) int { return sort.SearchInts(f.starts, off+1) }

func analyzeFile(sf source.File) ([]Function, []source.Issue) {
	f := &file{File: sf, code: sf.Code, starts: []int{0}}
	for i, c := range sf.Src {
		if c == '\n' {
			f.starts = append(f.starts, i+1)
		}
	}
	f.matchBrackets()
	fns := f.functions()
	issues := f.walk(fns)
	issue := func(rule, sev string, off int, detail string) {
		issues = append(issues, source.Issue{Rule: rule, Severity: sev, File: f.Path, Line: f.line(off), Detail: detail})
	}

	out := make([]Function, len(fns))
	for i, fn := range fns {
		out[i] = fn.Function
		at := func(rule, sev, detail string) {
			issues = append(issues, source.Issue{Rule: rule, Severity: sev, File: f.Path, Line: fn.Line, EndLine: fn.EndLine, Detail: detail})
		}
		switch {
		case fn.Complexity > 30:
			at("quality.complex-function", source.High, fmt.Sprintf("complexité %d", fn.Complexity))
		case fn.Complexity > 15:
			at("quality.complex-function", source.Medium, fmt.Sprintf("complexité %d", fn.Complexity))
		}
		switch {
		case fn.Lines > 150:
			at("quality.long-function", source.Medium, fmt.Sprintf("%d lignes", fn.Lines))
		case fn.Lines > 80:
			at("quality.long-function", source.Low, fmt.Sprintf("%d lignes", fn.Lines))
		}
		if fn.Params > 5 {
			at("quality.too-many-params", source.Low, fmt.Sprintf("%d paramètres", fn.Params))
		}
		if fn.MaxNesting > 4 {
			issue("quality.deep-nesting", source.Low, fn.deepOff, fmt.Sprintf("profondeur %d", fn.MaxNesting))
		}
	}

	if _, n := source.Count([]source.File{sf}); n > 1000 {
		issue("quality.long-file", source.Medium, 0, fmt.Sprintf("%d lignes", n))
	} else if n > 500 {
		issue("quality.long-file", source.Low, 0, fmt.Sprintf("%d lignes", n))
	}

	for _, k := range f.find("catch", catchRe) {
		dot := f.prevIs(k, '.')
		if dot && promiseCatchRe.Match(f.code[k:]) || !dot && blockCatchRe.Match(f.code[k:]) {
			issue("quality.empty-catch", source.Medium, k, "")
		}
	}
	for _, k := range f.find("debugger", debuggerRe) {
		if !f.prevIs(k, '.') {
			issue("quality.debugger", source.Medium, k, "")
		}
	}
	if !isTest(f.Path) {
		if !isScriptOrConfig(f.Path) {
			if ks := f.find("console", consoleRe); len(ks) > 0 {
				issue("quality.console-log", source.Info, ks[0], strconv.Itoa(len(ks)))
			}
		}
		if f.Lang == "TypeScript" || (f.Lang == "Svelte" || f.Lang == "Vue") && tsScriptRe.Match(f.Src) {
			var ks []int
			for _, k := range f.find("any", anyRe) {
				p := prevNonWS(f.code, k)
				if p >= 0 && (f.code[p] == ':' || f.code[p] == '<' && bytes.HasPrefix(f.code[nextNonWS(f.code, k+3):], []byte(">")) ||
					p > 0 && string(f.code[p-1:p+1]) == "as" && (p < 2 || !isIdent(f.code[p-2]))) {
					ks = append(ks, k)
				}
			}
			if len(ks) > 0 {
				issue("quality.ts-any", source.Info, ks[0], strconv.Itoa(len(ks)))
			}
		}
	}

	for _, c := range f.comments() {
		text := f.Src[c[0]:c[1]]
		if m := todoRe.FindIndex(text); m != nil {
			ls, le := m[0], m[1]
			for ls > 0 && text[ls-1] != '\n' {
				ls--
			}
			if k := bytes.IndexByte(text[le:], '\n'); k >= 0 {
				le += k
			} else {
				le = len(text)
			}
			issue("quality.todo", source.Info, c[0]+m[0], commentText(text[ls:le]))
		}
		for _, m := range directiveRe.FindAll(text, -1) {
			if d := string(m); !strings.HasSuffix(d, "-line") {
				issue("quality.ts-ignore", source.Low, c[0]+bytes.Index(text, m), d)
			}
		}
	}
	return out, issues
}

// commentText strips comment markers and squeezes spaces, at most 80 runes.
func commentText(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.TrimSuffix(s, "*/")
	s = strings.TrimLeft(s, "/* \t")
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80])
	}
	return s
}

func isTest(p string) bool {
	base := path.Base(p)
	if strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") {
		return true
	}
	for _, d := range strings.Split(path.Dir(p), "/") {
		if d == "__tests__" || d == "test" || d == "tests" || d == "e2e" {
			return true
		}
	}
	return false
}

// isScriptOrConfig: CLI scripts and tool configs log on purpose.
func isScriptOrConfig(p string) bool {
	base := path.Base(p)
	if strings.Contains(base, ".config.") || strings.HasPrefix(base, ".") {
		return true
	}
	for _, d := range strings.Split(path.Dir(p), "/") {
		if d == "scripts" || d == "script" || d == "bin" || d == "tools" {
			return true
		}
	}
	return false
}

func (f *file) matchBrackets() {
	f.match = make([]int32, len(f.code))
	var st [3][]int32
	for i, c := range f.code {
		f.match[i] = -1
		k := strings.IndexByte("([{)]}", c)
		if k < 0 {
			continue
		}
		if k < 3 {
			st[k] = append(st[k], int32(i))
		} else if s := st[k-3]; len(s) > 0 {
			o := s[len(s)-1]
			st[k-3] = s[:len(s)-1]
			f.match[i], f.match[o] = o, int32(i)
		}
	}
}

type fn struct {
	Function
	open, close int
	depth       int
	deepOff     int
}

// functions finds every `{` that opens a function body, in offset order.
func (f *file) functions() []*fn {
	c := f.code
	var out []*fn
	for i, ch := range c {
		if ch != '{' || f.match[i] < 0 || i > 0 && c[i-1] == '$' {
			continue
		}
		var name string
		var start, params int
		j := prevNonWS(c, i)
		if j > 0 && c[j] == '>' && c[j-1] == '=' { // arrow with block body
			if po, pc, ok := f.paramsBefore(j - 1); ok {
				start, params, name = po, countParams(c[po+1:pc]), f.nameBefore(po)
			} else {
				k := prevNonWS(c, j-1)
				if k < 0 || !isIdent(c[k]) {
					continue
				}
				start, params = wordStart(c, k), 1
				name = f.nameBefore(start)
			}
		} else if po, pc, ok := f.paramsBefore(i); ok {
			k := prevNonWS(c, po)
			if k >= 0 && c[k] == '>' { // generics: foo<T>(…)
				k = prevNonWS(c, skipAngleBack(c, k))
			}
			if k >= 0 && c[k] == '*' {
				k = prevNonWS(c, k)
			}
			switch {
			case k < 0:
				continue
			case c[k] == ']':
				start, name = k, anon // computed method name
			case isIdent(c[k]):
				ws := wordStart(c, k)
				w := string(c[ws : k+1])
				if control[w] {
					continue
				}
				start, name = ws, w
				if w == "function" {
					name = f.nameBefore(ws)
				}
			default:
				continue
			}
			params = countParams(c[po+1 : pc])
		} else {
			continue
		}
		close := int(f.match[i])
		fl, el := f.line(start), f.line(close)
		out = append(out, &fn{Function: Function{File: f.Path, Name: name, Line: fl, EndLine: el,
			Complexity: 1, Lines: el - fl + 1, Params: params}, open: i, close: close})
	}
	return out
}

// paramsBefore finds the parameter list ending just before i (a `{` or the `=` of `=>`),
// skipping a TS return type annotation `(…): T`.
func (f *file) paramsBefore(i int) (int, int, bool) {
	c := f.code
	j := prevNonWS(c, i)
	if j < 0 || strings.IndexByte(":|&,=(<[?", c[j]) >= 0 {
		return 0, 0, false
	}
	if c[j] == ')' {
		return int(f.match[j]), j, f.match[j] >= 0
	}
	depth := 0
	// shortcut: return types longer than 400 bytes are not followed, upgrade if real code has them.
	for k := j; k >= 0 && j-k < 400; k-- {
		ch := c[k]
		switch {
		case ch == '>' && k > 0 && c[k-1] == '=':
			k--
		case ch == ')' || ch == ']' || ch == '}' || ch == '>':
			depth++
		case ch == '(' || ch == '[' || ch == '{' || ch == '<':
			if depth == 0 {
				return 0, 0, false
			}
			depth--
		case depth > 0:
		case ch == ':':
			p := prevNonWS(c, k)
			if p >= 0 && c[p] == ')' && f.match[p] >= 0 {
				return int(f.match[p]), p, true
			}
			return 0, 0, false
		case isIdent(ch):
			ws := wordStart(c, k)
			if stopWords[string(c[ws:k+1])] {
				return 0, 0, false
			}
			k = ws
		case strings.IndexByte(" \t\r\n.|&'\"`-", ch) < 0:
			return 0, 0, false
		}
	}
	return 0, 0, false
}

// nameBefore names a function expression from the code before it (`const x =`, `key:`).
func (f *file) nameBefore(i int) string {
	from := max(0, i-200)
	from += bytes.LastIndexAny(f.code[from:i], ";{}()") + 1 // keeps the regex window short
	if m := nameRe.FindSubmatch(f.code[from:i]); m != nil {
		return string(m[1])
	}
	return anon
}

func countParams(b []byte) int {
	if len(bytes.TrimSpace(b)) == 0 {
		return 0
	}
	n, depth, last := 1, 0, 0
	for k, ch := range b {
		switch ch {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}':
			depth--
		case '>':
			if k == 0 || b[k-1] != '=' {
				depth--
			}
		case ',':
			if depth == 0 {
				n++
				last = k
			}
		}
	}
	if last > 0 && len(bytes.TrimSpace(b[last+1:])) == 0 {
		n-- // trailing comma
	}
	return n
}

type ternary struct {
	depth int
	colon bool
}

// walk counts complexity and nesting per function (nested bodies excluded) and finds nested ternaries.
func (f *file) walk(fns []*fn) []source.Issue {
	c := f.code
	n := len(c)
	var issues []source.Issue
	var stack []*fn
	next := 0
	var tern []ternary
	depth := 0 // bracket depth, for ternary extents
	lastNested := 0
	endTern := func(d int, coloned bool) {
		for len(tern) > 0 && tern[len(tern)-1].depth >= d && (!coloned || tern[len(tern)-1].colon) {
			tern = tern[:len(tern)-1]
		}
	}
	top := func() *fn {
		if len(stack) == 0 {
			return nil
		}
		return stack[len(stack)-1]
	}
	for i := 0; i < n; i++ {
		ch := c[i]
		t := top()
		switch {
		case ch == '{':
			depth++
			if next < len(fns) && fns[next].open == i {
				stack = append(stack, fns[next])
				next++
			} else if t != nil && f.isBlock(i) {
				t.depth++
				if t.depth > t.MaxNesting {
					t.MaxNesting, t.deepOff = t.depth, i
				}
			}
		case ch == '}':
			endTern(depth, false)
			depth--
			if t != nil && i == t.close {
				stack = stack[:len(stack)-1]
			} else if t != nil && f.match[i] >= 0 && f.isBlock(int(f.match[i])) {
				t.depth--
			}
		case ch == '(' || ch == '[':
			depth++
		case ch == ')' || ch == ']':
			endTern(depth, false)
			depth--
		case ch == ';' || ch == ',':
			endTern(depth, false)
		case ch == ':':
			for k := len(tern) - 1; k >= 0 && tern[k].depth == depth; k-- {
				if !tern[k].colon {
					tern[k].colon = true
					break
				}
			}
		case ch == '\n':
			// ASI: `a ? b : c` then a new line starting with a word ends the ternary.
			p, q := prevNonWS(c, i), nextNonWS(c, i)
			if len(tern) > 0 && p >= 0 && q < n && (isIdent(c[p]) || strings.IndexByte(")]}'\"`", c[p]) >= 0) && isIdent(c[q]) {
				endTern(depth, true)
			}
		case (ch == '&' || ch == '|' || ch == '?') && i+1 < n && c[i+1] == ch:
			if t != nil {
				t.Complexity++
			}
			i++
		case ch == '?':
			if i+1 < n && c[i+1] == '.' && !(i+2 < n && c[i+2] >= '0' && c[i+2] <= '9') {
				continue // optional chaining
			}
			if q := nextNonWS(c, i+1); q < n && strings.IndexByte(":),;=", c[q]) >= 0 {
				continue // TS optional `a?: T`, `(a?) =>`
			}
			if t != nil {
				t.Complexity++
			}
			if len(tern) > 0 {
				if l := f.line(i); l != lastNested {
					lastNested = l
					issues = append(issues, source.Issue{Rule: "quality.nested-ternary", Severity: source.Low, File: f.Path, Line: l})
				}
			}
			tern = append(tern, ternary{depth: depth})
		case isIdent(ch):
			j := i
			for j < n && isIdent(c[j]) {
				j++
			}
			w := string(c[i:j])
			if p := prevNonWS(c, i); p < 0 || c[p] != '.' {
				switch w {
				// `do` is not counted: its `while` already is.
				case "if", "for", "while", "case", "catch":
					if t != nil {
						t.Complexity++
					}
				}
				if stmtWords[w] {
					endTern(depth, false)
				}
			}
			i = j - 1
		}
	}
	return issues
}

// isBlock reports whether the `{` at i opens a statement block (if/for/while/try/…),
// not an object literal or a JSX expression.
func (f *file) isBlock(i int) bool {
	j := prevNonWS(f.code, i)
	if j < 0 {
		return false
	}
	if f.code[j] == ')' {
		return true
	}
	if !isIdent(f.code[j]) {
		return false
	}
	switch string(f.code[wordStart(f.code, j) : j+1]) {
	case "else", "try", "finally", "do":
		return true
	}
	return false
}

// comments returns the [start, end) offsets of comments, found where Code is blank
// outside strings. Component markup is skipped (only <script> bodies hold JS).
func (f *file) comments() [][2]int {
	ranges := [][2]int{{0, len(f.Src)}}
	if f.Lang == "Svelte" || f.Lang == "Vue" {
		ranges = source.ScriptRanges(f.Src)
	}
	var out [][2]int
	c, s := f.code, f.Src
	for _, r := range ranges {
		var tmpl []int
		depth := 0
		inTmpl := false
		for k := r[0]; k < r[1]; k++ {
			ch := c[k]
			if inTmpl {
				switch {
				case ch == '`':
					inTmpl = false
				case ch == '$' && k+1 < r[1] && c[k+1] == '{':
					tmpl = append(tmpl, depth)
					depth++
					inTmpl = false
					k++
				}
				continue
			}
			switch {
			case ch == ' ' && s[k] == '/' && k+1 < r[1] && (s[k+1] == '/' || s[k+1] == '*'):
				end := r[1]
				if s[k+1] == '/' {
					if e := bytes.IndexByte(s[k:r[1]], '\n'); e >= 0 {
						end = k + e
					}
				} else if e := bytes.Index(s[k+2:r[1]], []byte("*/")); e >= 0 {
					end = k + 2 + e + 2
				}
				out = append(out, [2]int{k, end})
				k = end - 1
			case ch == '\'' || ch == '"':
				for k++; k < r[1] && c[k] != ch && c[k] != '\n'; k++ {
				}
			case ch == '`':
				inTmpl = true
			case ch == '{':
				depth++
			case ch == '}':
				depth--
				if len(tmpl) > 0 && tmpl[len(tmpl)-1] == depth {
					tmpl = tmpl[:len(tmpl)-1]
					inTmpl = true
				}
			}
		}
	}
	return out
}

// find returns the offsets of whole-word lit where the anchored re matches.
func (f *file) find(lit string, re *regexp.Regexp) []int {
	var out []int
	for k := 0; ; k += len(lit) {
		i := bytes.Index(f.code[k:], []byte(lit))
		if i < 0 {
			return out
		}
		k += i
		if (k == 0 || !isIdent(f.code[k-1])) && re.Match(f.code[k:]) {
			out = append(out, k)
		}
	}
}

func (f *file) prevIs(k int, ch byte) bool {
	p := prevNonWS(f.code, k)
	return p >= 0 && f.code[p] == ch
}

func prevNonWS(c []byte, i int) int {
	for i--; i >= 0; i-- {
		if ch := c[i]; ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r' {
			return i
		}
	}
	return -1
}

func nextNonWS(c []byte, i int) int {
	for ; i < len(c); i++ {
		if ch := c[i]; ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r' {
			return i
		}
	}
	return i
}

func wordStart(c []byte, k int) int {
	for k > 0 && isIdent(c[k-1]) {
		k--
	}
	return k
}

// skipAngleBack returns the offset of the `<` matching the `>` at k.
func skipAngleBack(c []byte, k int) int {
	d := 0
	for ; k >= 0; k-- {
		switch c[k] {
		case '>':
			d++
		case '<':
			if d--; d == 0 {
				return k
			}
		}
	}
	return 0
}

func isIdent(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}
