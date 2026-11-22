// Package dupes finds copy-pasted code (type-1 and type-2 clones) across the JS/TS
// files of a project, like jscpd but in pure Go.
package dupes

import (
	"bytes"
	"cmp"
	"math/bits"
	"path"
	"slices"
	"strings"

	"limier/internal/scanners/source"
)

const (
	MinTokens = 50  // window size: a clone is at least this many tokens
	MinLines  = 6   // and spans at least this many lines in every copy
	MaxClones = 100 // clones kept in the report
	// shortcut: windows with fewer distinct normalized tokens are skipped so data arrays and
	// tables don't flood the hash buckets; a smarter repetition filter would let us report
	// real duplicated data blocks, upgrade if users ask for them.
	minDistinct = 10
	// shortcut: each window is only compared with its maxPeers previous look-alikes, so code
	// pasted hundreds of times is still grouped by chaining but costs stay linear; upgrade
	// if huge copy groups come out split.
	maxPeers = 5
)

type Location struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	EndLine int    `json:"end_line"`
}

type Clone struct {
	Lines     int        `json:"lines"`
	Tokens    int        `json:"tokens"`
	Locations []Location `json:"locations"` // ≥ 2, sorted by file then line
}

type Report struct {
	Clones          []Clone `json:"clones"`           // biggest first, capped at MaxClones
	DuplicatedLines int     `json:"duplicated_lines"` // distinct cloned lines, one "original" per clone excluded
	TotalLines      int     `json:"total_lines"`      // non-blank lines of Code over analysed files
	Ratio           float64 `json:"ratio"`
}

// Normalized token ids. 0 separates files so no match ever crosses one.
const (
	tSep uint32 = iota
	tID
	tNum
	tStr
	tFirstFree
)

type tok struct {
	id         uint32
	line       int32
	start, end int32
}

// Analyze reports the clones among the code files.
func Analyze(files []source.File) Report {
	var rep Report
	vocab := map[string]uint32{}
	// Flat token stream of every file, with a separator before, between and after files.
	ids, lines, owner := []uint32{tSep}, []int32{0}, []int32{-1}
	var names []string
	var spans [][2]int
	for _, f := range files {
		// Tests repeat their arrange/act/assert boilerplate on purpose: counting it would drown real copy-paste.
		if !f.IsCode() || isTestPath(f.Path) {
			continue
		}
		rep.TotalLines += nonBlank(f.Code)
		toks := dropImports(f.Code, tokenize(f.Code, vocab))
		fi := int32(len(names))
		names = append(names, f.Path)
		s := len(ids)
		for _, t := range toks {
			ids, lines, owner = append(ids, t.id), append(lines, t.line), append(owner, fi)
		}
		spans = append(spans, [2]int{s, len(ids)})
		ids, lines, owner = append(ids, tSep), append(lines, 0), append(owner, -1)
	}

	pairs := matchPairs(ids, lines, owner, spans, len(vocab)+int(tFirstFree))
	rep.Clones, rep.DuplicatedLines = group(pairs, lines, owner, names)
	slices.SortStableFunc(rep.Clones, func(a, b Clone) int {
		return cmp.Compare(b.Lines*(len(b.Locations)-1), a.Lines*(len(a.Locations)-1))
	})
	if len(rep.Clones) > MaxClones {
		rep.Clones = rep.Clones[:MaxClones]
	}
	if rep.TotalLines > 0 {
		rep.Ratio = float64(rep.DuplicatedLines) / float64(rep.TotalLines)
	}
	return rep
}

type pair struct{ a, b, n int } // ids[a:a+n] == ids[b:b+n], a < b

// matchPairs returns the maximal matches of at least MinTokens tokens, found with a
// Rabin-Karp rolling hash over MinTokens-token windows.
func matchPairs(ids []uint32, lines, owner []int32, spans [][2]int, vocabSize int) []pair {
	const base = 1_000_003
	pw := uint64(1)
	for range MinTokens - 1 {
		pw *= base
	}
	// prev[i]: previous window start with the same hash, -1 if none. Found through a
	// small open-addressing table (hash → last window start), much faster than a Go map.
	prev := make([]int32, len(ids))
	for i := range prev {
		prev[i] = -1
	}
	shift := 64 - bits.Len(uint(2*len(ids)))
	keys, last := make([]uint64, 1<<(64-shift)), make([]int32, 1<<(64-shift))
	for i := range last {
		last[i] = -1
	}
	counts := make([]int32, vocabSize)
	for _, sp := range spans {
		s, e := sp[0], sp[1]
		if e-s < MinTokens {
			continue
		}
		distinct := 0
		add := func(t uint32) {
			if counts[t]++; counts[t] == 1 {
				distinct++
			}
		}
		del := func(t uint32) {
			if counts[t]--; counts[t] == 0 {
				distinct--
			}
		}
		var h uint64
		for k := s; k < s+MinTokens; k++ {
			add(ids[k])
			h = h*base + uint64(ids[k])
		}
		for i := s; ; i++ {
			if distinct >= minDistinct {
				k := (h * 0x9E3779B97F4A7C15) >> shift
				for last[k] >= 0 && keys[k] != h {
					k = (k + 1) & uint64(len(keys)-1)
				}
				prev[i], keys[k], last[k] = last[k], h, int32(i)
			}
			if i+MinTokens >= e {
				break
			}
			del(ids[i])
			add(ids[i+MinTokens])
			h = (h-uint64(ids[i])*pw)*base + uint64(ids[i+MinTokens])
		}
		for k := e - MinTokens; k < e; k++ {
			counts[ids[k]] = 0
		}
	}

	span := func(s, n int) int { return int(lines[s+n-1]-lines[s]) + 1 }
	// covered[d]: end (in the later copy) of the last match found at offset d; windows
	// inside it belong to that match, which keeps the whole pass linear.
	covered := map[int]int{}
	var pairs []pair
	for i := range prev {
		peers := 0
		for j := prev[i]; j >= 0 && peers < maxPeers; j = prev[j] {
			peers++
			d := i - int(j)
			if covered[d] > i || !slices.Equal(ids[j:int(j)+MinTokens], ids[i:i+MinTokens]) {
				continue // already reported, or a hash collision
			}
			a, b := int(j), i
			for ids[a-1] != tSep && ids[a-1] == ids[b-1] {
				a, b = a-1, b-1
			}
			n := i + MinTokens - b
			for ids[a+n] != tSep && ids[a+n] == ids[b+n] {
				n++
			}
			covered[d] = b + n
			if owner[a] == owner[b] && a+n > b {
				n = b - a // a repeat overlapping itself: keep only the non-overlapping part
			}
			if n >= MinTokens && span(a, n) >= MinLines && span(b, n) >= MinLines {
				pairs = append(pairs, pair{a, b, n})
			}
		}
	}
	return pairs
}

// group merges pairs sharing an identical region (3 copies → one Clone with 3 locations)
// and counts the duplicated lines.
func group(pairs []pair, lines, owner []int32, names []string) ([]Clone, int) {
	type region struct{ s, n int }
	idx := map[region]int{}
	var regions []region
	var parent []int
	find := func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	key := func(r region) int {
		k, ok := idx[r]
		if !ok {
			k = len(regions)
			idx[r] = k
			regions = append(regions, r)
			parent = append(parent, k)
		}
		return k
	}
	for _, p := range pairs {
		x, y := find(key(region{p.a, p.n})), find(key(region{p.b, p.n}))
		parent[x] = y
	}
	members := map[int][]region{}
	var roots []int
	for k, r := range regions {
		root := find(k)
		if members[root] == nil {
			roots = append(roots, root)
		}
		members[root] = append(members[root], r)
	}

	type fileLine struct{ file, line int32 }
	dup := map[fileLine]bool{}
	var clones []Clone
	for _, root := range roots {
		rs := members[root]
		// Regions are in token-stream order, which is file order (Walk sorts) then line.
		slices.SortFunc(rs, func(x, y region) int {
			if c := cmp.Compare(names[owner[x.s]], names[owner[y.s]]); c != 0 {
				return c
			}
			return cmp.Compare(x.s, y.s)
		})
		c := Clone{Tokens: rs[0].n}
		for k, r := range rs {
			l := Location{File: names[owner[r.s]], Line: int(lines[r.s]), EndLine: int(lines[r.s+r.n-1])}
			c.Locations = append(c.Locations, l)
			if c.Lines == 0 || l.EndLine-l.Line+1 < c.Lines {
				c.Lines = l.EndLine - l.Line + 1
			}
			if k == 0 {
				continue // the "original"
			}
			for t := r.s; t < r.s+r.n; t++ {
				dup[fileLine{owner[t], lines[t]}] = true
			}
		}
		clones = append(clones, c)
	}
	return clones, len(dup)
}

func nonBlank(code []byte) int {
	n := 0
	for l := range bytes.Lines(code) {
		if len(bytes.TrimSpace(l)) > 0 {
			n++
		}
	}
	return n
}

var keywords = map[string]bool{}

func init() {
	for _, k := range []string{
		"break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete",
		"do", "else", "export", "extends", "finally", "for", "function", "if", "import", "in",
		"instanceof", "new", "return", "super", "switch", "this", "throw", "try", "typeof", "var",
		"void", "while", "with", "yield", "let", "static", "async", "await", "of", "get", "set",
		"true", "false", "null", "undefined",
		"interface", "type", "enum", "implements", "private", "public", "protected", "readonly",
		"abstract", "declare", "namespace", "as", "keyof",
	} {
		keywords[k] = true
	}
}

// Longest first so greedy matching picks `===` before `==`.
var ops = []string{">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
	"=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=",
	"%=", "&=", "|=", "^=", "**", "<<", ">>"}

func isIdent(c byte) bool {
	return c == '_' || c == '$' || c >= 0x80 || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// tokenize lexes stripped code (comments and literal contents already blanked).
// Identifiers become ID, numbers NUM, quoted strings STR; keywords and punctuation keep
// their own ids so renamed copies still match.
// shortcut: template literals and regexes are lexed as their delimiters plus inner tokens,
// not one STR token; harmless for matching, upgrade if token counts must match jscpd.
func tokenize(code []byte, vocab map[string]uint32) []tok {
	intern := func(b []byte) uint32 {
		v, ok := vocab[string(b)]
		if !ok {
			v = uint32(len(vocab)) + tFirstFree
			vocab[string(b)] = v
		}
		return v
	}
	var toks []tok
	line := int32(1)
	for i, n := 0, len(code); i < n; {
		c := code[i]
		j := i + 1
		var id uint32
		switch {
		case c == '\n':
			line++
			i++
			continue
		case c <= ' ':
			i++
			continue
		case isDigit(c) || c == '.' && j < n && isDigit(code[j]):
			for j < n && (isIdent(code[j]) || code[j] == '.') {
				j++
			}
			id = tNum
		case isIdent(c):
			for j < n && isIdent(code[j]) {
				j++
			}
			id = tID
			if keywords[string(code[i:j])] {
				id = intern(code[i:j])
			}
		case c == '"' || c == '\'':
			end := bytes.IndexAny(code[j:], string(c)+"\n")
			if end >= 0 && code[j+end] == c {
				j += end + 1
				id = tStr
			} else {
				id = intern(code[i:j])
			}
		default:
			for _, op := range ops {
				if bytes.HasPrefix(code[i:], []byte(op)) {
					j = i + len(op)
					break
				}
			}
			id = intern(code[i:j])
		}
		toks = append(toks, tok{id, line, int32(i), int32(j)})
		i = j
	}
	return toks
}

// dropImports removes import, re-export and `const x = require(…)` statements: every
// module has a similar header, which is not copy-paste.
// shortcut: only statements starting a line are recognised and multi-line destructured
// requires are kept; upgrade if headers show up as clones.
func dropImports(code []byte, toks []tok) []tok {
	raw := func(k int) string {
		if k >= len(toks) {
			return ""
		}
		return string(code[toks[k].start:toks[k].end])
	}
	end := func(k int) int {
		j := k + 1
		switch raw(k) {
		case "import":
			if r := raw(j); r == "(" || r == "." {
				return k // dynamic import or import.meta: code
			}
			for j < len(toks) && toks[j].id != tStr {
				j++
			}
			j++
		case "export":
			if raw(j) == "type" {
				j++
			}
			switch raw(j) {
			case "{":
				for j < len(toks) && raw(j) != "}" {
					j++
				}
				j++
			case "*":
				j++
				if raw(j) == "as" {
					j += 2
				}
			default:
				return k
			}
			if raw(j) == "from" {
				j += 2
			}
		case "const", "let", "var":
			req := false
			for ; j < len(toks) && toks[j].line == toks[k].line; j++ {
				req = req || raw(j) == "require" && raw(j+1) == "("
			}
			if !req {
				return k
			}
		default:
			return k
		}
		if raw(j) == ";" {
			j++
		}
		return min(j, len(toks))
	}
	out := make([]tok, 0, len(toks))
	for k := 0; k < len(toks); {
		if k == 0 || toks[k-1].line != toks[k].line {
			if e := end(k); e > k {
				k = e
				continue
			}
		}
		out = append(out, toks[k])
		k++
	}
	return out
}

func isTestPath(p string) bool {
	for _, d := range []string{"test/", "tests/", "__tests__/", "e2e/", "fixtures/", "__mocks__/"} {
		if strings.HasPrefix(p, d) || strings.Contains(p, "/"+d) {
			return true
		}
	}
	base := path.Base(p)
	return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
}
