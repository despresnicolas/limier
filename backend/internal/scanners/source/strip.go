package source

import (
	"bytes"
	"regexp"
)

// Strip blanks comments and the contents of strings, template-literal text and regex
// literals to spaces, keeping quotes, newlines and every byte offset. `${…}` inside
// templates stays code. For Svelte/Vue only <script> blocks are kept; markup is blanked.
// shortcut: regex-vs-division is guessed from the previous token, a full JS lexer would be exact; upgrade if rules misfire on real projects.
func Strip(src []byte, lang string) []byte {
	if lang != "Svelte" && lang != "Vue" {
		out, _ := stripJS(src)
		return out
	}
	out := bytes.Repeat([]byte{' '}, len(src))
	for i, c := range src {
		if c == '\n' {
			out[i] = '\n'
		}
	}
	for _, r := range ScriptRanges(src) {
		s, _ := stripJS(src[r[0]:r[1]])
		copy(out[r[0]:r[1]], s)
	}
	return out
}

var scriptRe = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script\s*>`)

// ScriptRanges returns the [start, end) byte ranges of <script> bodies in a component.
func ScriptRanges(src []byte) [][2]int {
	var rs [][2]int
	for _, m := range scriptRe.FindAllSubmatchIndex(src, -1) {
		rs = append(rs, [2]int{m[2], m[3]})
	}
	return rs
}

// stripJS returns the blanked code and, per byte, whether it was inside a comment.
func stripJS(src []byte) ([]byte, []bool) {
	out := make([]byte, len(src))
	copy(out, src)
	comment := make([]bool, len(src))
	blank := func(from, to int, isComment bool) {
		for k := from; k < to && k < len(src); k++ {
			if src[k] != '\n' {
				out[k] = ' '
			}
			comment[k] = isComment
		}
	}
	var tmpl []int // brace depth at each `${` currently open
	depth := 0
	prev := byte(0) // last significant code byte
	prevWord := ""  // last identifier, to tell `return /re/` from `a / b`
	n := len(src)
	i := 0
	for i < n {
		c := src[i]
		switch {
		case c == '/' && i+1 < n && src[i+1] == '/':
			j := bytes.IndexByte(src[i:], '\n')
			if j < 0 {
				j = n - i
			}
			blank(i, i+j, true)
			i += j
			continue
		case c == '/' && i+1 < n && src[i+1] == '*':
			j := bytes.Index(src[i+2:], []byte("*/"))
			end := n
			if j >= 0 {
				end = i + 2 + j + 2
			}
			blank(i, end, true)
			i = end
			continue
		case c == '\'' || c == '"':
			j := i + 1
			for j < n && src[j] != c && src[j] != '\n' {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			blank(i+1, min(j, n), false)
			i = j + 1
			prev, prevWord = c, ""
			continue
		case c == '`' || (c == '}' && len(tmpl) > 0 && tmpl[len(tmpl)-1] == depth):
			if c == '}' {
				tmpl = tmpl[:len(tmpl)-1]
			}
			j := i + 1
			for j < n && src[j] != '`' {
				if src[j] == '\\' {
					j += 2
					continue
				}
				if src[j] == '$' && j+1 < n && src[j+1] == '{' {
					break
				}
				j++
			}
			blank(i+1, min(j, n), false)
			if j+1 < n && src[j] == '$' {
				tmpl = append(tmpl, depth)
				i = j + 2
				prev, prevWord = '{', ""
				continue
			}
			i = j + 1
			prev, prevWord = '`', ""
			continue
		case c == '/' && regexAllowed(prev, prevWord):
			j, inClass := i+1, false
			for j < n && src[j] != '\n' {
				if src[j] == '\\' {
					j += 2
					continue
				}
				if src[j] == '[' {
					inClass = true
				} else if src[j] == ']' {
					inClass = false
				} else if src[j] == '/' && !inClass {
					break
				}
				j++
			}
			if j >= n || src[j] != '/' {
				break // not a regex after all: treat as division
			}
			blank(i+1, j, false)
			i = j + 1
			prev, prevWord = '/', ""
			continue
		case c == '{':
			depth++
		case c == '}':
			depth--
		}
		if isIdent(c) {
			j := i
			for j < n && isIdent(src[j]) {
				j++
			}
			prevWord, prev = string(src[i:j]), src[j-1]
			i = j
			continue
		}
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			prev, prevWord = c, ""
		}
		i++
	}
	return out, comment
}

func regexAllowed(prev byte, word string) bool {
	switch word {
	case "":
	case "return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else", "do", "yield", "await":
		return true
	default:
		return false
	}
	if prev == 0 {
		return true
	}
	return bytes.IndexByte([]byte("(,=:[!&|?{};+-*%<>~^"), prev) >= 0
}

func isIdent(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}
