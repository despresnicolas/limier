package source

import (
	"bytes"
	"sort"
)

// Language is the line count of one language (SPECS F3.1); JSON shape of code_metrics.languages.
type Language struct {
	Name     string `json:"name"`
	Files    int64  `json:"files"`
	Code     int64  `json:"code"`
	Comments int64  `json:"comments"`
	Blanks   int64  `json:"blanks"`
}

// Count returns per-language line counts of the code files, largest first, and the total code lines.
// Svelte/Vue markup lines count as code.
func Count(files []File) ([]Language, int64) {
	by := map[string]*Language{}
	var total int64
	for _, f := range files {
		if !f.IsCode() {
			continue
		}
		l := by[f.Lang]
		if l == nil {
			l = &Language{Name: f.Lang}
			by[f.Lang] = l
		}
		l.Files++
		code, comments, blanks := countLines(f)
		l.Code += code
		l.Comments += comments
		l.Blanks += blanks
		total += code
	}
	out := make([]Language, 0, len(by))
	for _, l := range by {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Code > out[j].Code || out[i].Code == out[j].Code && out[i].Name < out[j].Name
	})
	return out, total
}

func countLines(f File) (code, comments, blanks int64) {
	// isComment[k]: byte k is inside a comment; markup bytes of components are never comments.
	isComment := make([]bool, len(f.Src))
	if f.Lang == "Svelte" || f.Lang == "Vue" {
		for _, r := range ScriptRanges(f.Src) {
			_, c := stripJS(f.Src[r[0]:r[1]])
			copy(isComment[r[0]:r[1]], c)
		}
	} else {
		_, isComment = stripJS(f.Src)
	}
	start := 0
	for start <= len(f.Src) {
		end := bytes.IndexByte(f.Src[start:], '\n')
		if end < 0 {
			end = len(f.Src)
		} else {
			end += start
		}
		if start == len(f.Src) && end == start {
			break // no line after a trailing newline
		}
		hasText, hasCode := false, false
		for k := start; k < end; k++ {
			c := f.Src[k]
			if c == ' ' || c == '\t' || c == '\r' {
				continue
			}
			hasText = true
			if !isComment[k] {
				hasCode = true
				break
			}
		}
		switch {
		case !hasText:
			blanks++
		case hasCode:
			code++
		default:
			comments++
		}
		start = end + 1
	}
	return
}
