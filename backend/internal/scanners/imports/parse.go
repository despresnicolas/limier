package imports

import (
	"regexp"
	"strings"

	"limier/internal/scanners/source"
)

// imp is one import statement of a file.
type imp struct {
	spec     string
	line     int
	typeOnly bool
	names    []string // names taken from the target; "*" means all of them
}

// export is one named export of a file.
type export struct {
	name string
	line int
}

// The patterns run on File.Code, where comments are gone and string contents are
// blanked: each match ends just after the opening quote, the specifier is read from Src.
const pre = `(?:^|[^\w$.])`

var (
	reImport = regexp.MustCompile(pre + `import\s*(type\s+)?((?:[\w$]+\s*,\s*)?(?:\{[^}]*\}|\*\s*as\s+[\w$]+)|[\w$]+)\s*from\s*["']`)
	reReExp  = regexp.MustCompile(pre + `export\s*(type\s+)?(\{[^}]*\}|\*(?:\s*as\s+[\w$]+)?)\s*from\s*["']`)
	reSide   = regexp.MustCompile(pre + `import\s*["']`)
	reCall   = regexp.MustCompile(pre + `(?:require|import)\s*\(\s*["'` + "`]")
	reDecl   = regexp.MustCompile(pre + `export\s+(?:declare\s+)?(?:async\s+)?(?:abstract\s+)?(?:const\s+enum|const|let|var|function\s*\*?|class|enum|type|interface|namespace)\s+([\w$]+)`)
	reList   = regexp.MustCompile(pre + `export\s*(?:type\s+)?\{([^}]*)\}`)
	// reFunc finds functions declared in a file: `function f`, `const f = (…) =>`, `const f = async x =>`, `const f = function`.
	reFunc = regexp.MustCompile(pre + `(?:function\s*\*?\s*([\w$]+)|(?:const|let|var)\s+([\w$]+)\s*(?::[^=;]+)?=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=;]+)?=>|[\w$]+\s*=>))`)
)

// keyword returns the offset of the keyword of a match, past the boundary byte.
func keyword(code []byte, start int) int {
	if c := code[start]; c != 'i' && c != 'e' && c != 'r' {
		return start + 1
	}
	return start
}

// literal reads the string literal whose opening quote is at q-1 in Src.
// ok is false for an unterminated literal or a template with `${`.
func literal(src []byte, q int) (string, bool) {
	quote := src[q-1]
	end := q
	for end < len(src) && src[end] != quote && src[end] != '\n' {
		end++
	}
	if end >= len(src) || src[end] != quote {
		return "", false
	}
	s := string(src[q:end])
	return s, !strings.Contains(s, "${")
}

func parseImports(f source.File) []imp {
	var out []imp
	add := func(m []int, typeOnly bool, names []string) {
		if spec, ok := literal(f.Src, m[1]); ok && spec != "" {
			out = append(out, imp{spec: spec, line: f.LineAt(keyword(f.Code, m[0])), typeOnly: typeOnly, names: names})
		}
	}
	for _, m := range reImport.FindAllSubmatchIndex(f.Code, -1) {
		clause := string(f.Code[m[4]:m[5]])
		names, allTypes := clauseNames(clause, true)
		add(m, m[2] >= 0 || allTypes, names)
	}
	for _, m := range reReExp.FindAllSubmatchIndex(f.Code, -1) {
		names, allTypes := clauseNames(string(f.Code[m[4]:m[5]]), false)
		add(m, m[2] >= 0 || allTypes, names)
	}
	for _, m := range reSide.FindAllIndex(f.Code, -1) {
		add(m, false, nil)
	}
	for _, m := range reCall.FindAllIndex(f.Code, -1) {
		add(m, false, []string{"*"}) // the whole module object escapes
	}
	return out
}

// clauseNames returns the names an import/export clause takes from its target, and
// whether every one of them is an inline `type` import.
func clauseNames(clause string, isImport bool) ([]string, bool) {
	clause = strings.TrimSpace(clause)
	var names []string
	if strings.HasPrefix(clause, "*") {
		return []string{"*"}, false
	}
	allTypes := true
	if isImport && !strings.HasPrefix(clause, "{") {
		def, rest, _ := strings.Cut(clause, ",")
		names = append(names, "default")
		allTypes = false
		if strings.HasPrefix(strings.TrimSpace(def), "*") {
			names[0] = "*"
		}
		clause = strings.TrimSpace(rest)
		if strings.HasPrefix(clause, "*") {
			return append(names, "*"), false
		}
	}
	clause = strings.Trim(clause, "{} \t\r\n")
	for _, item := range strings.Split(clause, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if t, ok := strings.CutPrefix(item, "type "); ok {
			item = strings.TrimSpace(t)
		} else {
			allTypes = false
		}
		name, _, _ := strings.Cut(item, " ")
		names = append(names, name)
	}
	return names, allTypes && len(names) > 0
}

// parseExports returns the exported functions of a JS/TS file (components have props, not exports).
// Types, interfaces, classes and constants are left out: only unused public functions are reported.
func parseExports(f source.File) []export {
	all := parseAllExports(f)
	funcs := map[string]bool{}
	for _, m := range reFunc.FindAllSubmatch(f.Code, -1) {
		funcs[string(m[1])+string(m[2])] = true
	}
	out := all[:0]
	for _, e := range all {
		if funcs[e.name] {
			out = append(out, e)
		}
	}
	return out
}

func parseAllExports(f source.File) []export {
	if f.Lang == "Svelte" || f.Lang == "Vue" {
		// shortcut: `<script context="module">` exports of components are not listed, add them if users ask.
		return nil
	}
	var out []export
	for _, m := range reDecl.FindAllSubmatchIndex(f.Code, -1) {
		out = append(out, export{string(f.Code[m[2]:m[3]]), f.LineAt(keyword(f.Code, m[0]))})
	}
	for _, m := range reList.FindAllSubmatchIndex(f.Code, -1) {
		line := f.LineAt(keyword(f.Code, m[0]))
		for _, item := range strings.Split(string(f.Code[m[2]:m[3]]), ",") {
			item = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(item), "type "))
			fields := strings.Fields(item)
			if len(fields) == 0 {
				continue
			}
			name := fields[len(fields)-1] // `a as b` exports b
			if name != "default" {
				out = append(out, export{name, line})
			}
		}
	}
	return out
}
