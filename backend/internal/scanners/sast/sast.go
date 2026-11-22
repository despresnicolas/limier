// Package sast flags possible security flaws in JS/TS code by patterns (SPECS F3).
// Structure is matched on File.Code, so comments and string contents never match;
// literal values are read from File.Src at the same offsets.
// shortcut: no data-flow analysis, a rule only sees the call or line it matches; upgrade to a JS AST with taint tracking if users report misses.
package sast

import (
	"bytes"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"limier/internal/scanners/source"
)

// fileCtx holds per-file facts computed once.
type fileCtx struct {
	f       source.File
	cpNames map[string]bool // receivers bound to child_process
}

type rule struct {
	id, sev, cwe string
	kw           []string // literals one of which is on every matching line
	re           *regexp.Regexp
	onSrc        bool // match Src instead of Code; the match must start on real code
	check        func(c *fileCtx, m []int) bool
}

var (
	userInput  = regexp.MustCompile(`\b(?:req|request)\.(?:params|query|body|url|path)\b|\bctx\.(?:params|query|request)\b|(?:^|[^.\w$])(?:params|query|body)\.\w`)
	redirectIn = regexp.MustCompile(`\b(?:req|request)\.(?:query|params|body)\b|searchParams|\blocation\.(?:search|hash)\b|(?:^|[^.\w$])query\.\w`)
	regexIn    = regexp.MustCompile(`\b(?:req|request)\.|(?:^|[^.\w$])(?:params|query|input|search)\b`)
	reqBody    = regexp.MustCompile(`\b(?:req|request)\.(?:body|query|params)\b|\bctx\.request\.body\b`)
	sqlKw      = regexp.MustCompile(`(?i)\b(?:select|insert|update|delete|where)\b`)
	shellTrue  = regexp.MustCompile(`\bshell\s*:\s*true\b`)
	credsTrue  = regexp.MustCompile(`\bcredentials\s*:\s*true\b`)
	credHeader = regexp.MustCompile(`(?i)['"]Access-Control-Allow-Credentials['"]\s*[,:]\s*['"]?true`)
	cookieCtx  = regexp.MustCompile(`(?i)cookie|samesite|httponly`)
	// An identifier ending with a secret-ish word, e.g. resetToken, api_key, salt.
	secretID = regexp.MustCompile(`(?i)\b\w*(?:token|secret|passw\w*|salt|otp|nonce|key|uuid)\b`)
	cpImport = regexp.MustCompile(`(?:(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*|import\s+(?:\*\s+as\s+)?(\w+)\s+from\s+)['"](?:node:)?child_process['"]`)
	isTest   = regexp.MustCompile(`(?:^|/)(?:test|tests|__tests__|e2e)/|\.(?:test|spec)\.[cm]?[jt]sx?$`)
)

var rules = []rule{
	{id: "sast.eval", sev: source.High, cwe: "CWE-95", kw: []string{"eval", "Function", "setTimeout", "setInterval"},
		re: regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(`),
		check: func(c *fileCtx, m []int) bool {
			code := c.f.Code
			switch code[m[0]] {
			case 'e':
				return m[0] == 0 || code[m[0]-1] != '.' && !bytes.HasSuffix(bytes.TrimRight(code[:m[0]], " "), []byte("function"))
			case 'n':
				return true
			}
			a := bytes.TrimSpace(firstArg(code, m[1]-1))
			return len(a) > 0 && isQuote(a[0]) || bytes.IndexByte(a, '+') >= 0 && bytes.ContainsAny(a, "'\"`")
		}},
	{id: "sast.command-injection", sev: source.High, cwe: "CWE-78", kw: []string{"exec", "spawn"},
		re:    regexp.MustCompile(`\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(`),
		check: checkCommand},
	{id: "sast.sql-injection", sev: source.High, cwe: "CWE-89", kw: []string{".query", ".execute", ".raw", "Unsafe"},
		re: regexp.MustCompile(`\.(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(`),
		check: func(c *fileCtx, m []int) bool {
			s, e := argSpan(c.f.Code, m[1]-1, true)
			a := c.f.Code[s:e]
			t := bytes.TrimSpace(a)
			built := len(t) > 0 && t[0] == '`' && bytes.Contains(t, []byte("${")) ||
				bytes.IndexByte(a, '+') >= 0 && bytes.ContainsAny(a, "'\"`")
			return built && sqlKw.Match(c.f.Src[s:e])
		}},
	{id: "sast.xss", sev: source.Medium, cwe: "CWE-79", kw: []string{"HTML", "document.write"},
		re: regexp.MustCompile(`\.(?:inner|outer)HTML\s*\+?=[^=]|\binsertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(|\bdangerouslySetInnerHTML\b`),
		check: func(c *fileCtx, m []int) bool {
			code := c.f.Code
			if bytes.HasPrefix(code[m[0]:], []byte("danger")) {
				return true
			}
			if code[m[1]-1] == '(' {
				s, e := argSpan(code, m[1]-1, false)
				a := code[s:e]
				if code[m[0]] == 'i' { // insertAdjacentHTML(position, html)
					if i := topComma(a); i >= 0 {
						a = a[i+1:]
					}
				}
				return !isLiteral(a)
			}
			eq := m[0] + bytes.IndexByte(code[m[0]:m[1]], '=')
			rhs := restOfLine(code, eq+1)
			if i := bytes.IndexByte(rhs, ';'); i >= 0 {
				rhs = rhs[:i]
			}
			return !isLiteral(rhs)
		}},
	{id: "sast.tls-disabled", sev: source.High, cwe: "CWE-295", kw: []string{"rejectUnauthorized", "strictSSL", "insecure"},
		re: regexp.MustCompile(`\brejectUnauthorized\s*:\s*false\b|\bstrictSSL\s*:\s*false\b|\binsecure\s*:\s*true\b`),
		check: func(c *fileCtx, m []int) bool {
			// insecure: true only matters for an HTTP client agent.
			return c.f.Code[m[0]] != 'i' || bytes.Contains(c.f.Src, []byte("axios")) || bytes.Contains(c.f.Code, []byte("Agent"))
		}},
	{id: "sast.tls-disabled", sev: source.High, cwe: "CWE-295", kw: []string{"NODE_TLS_REJECT_UNAUTHORIZED"}, onSrc: true,
		re: regexp.MustCompile(`(?:\.NODE_TLS_REJECT_UNAUTHORIZED|\[\s*['"]NODE_TLS_REJECT_UNAUTHORIZED['"]\s*\])\s*=\s*['"]?0\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*:\s*['"]?0\b`)},
	{id: "sast.weak-hash", sev: source.Medium, cwe: "CWE-328", kw: []string{"createHash", "MD5", "SHA1"},
		re: regexp.MustCompile(`\bcreateHash\s*\(\s*['"]|\b(?:MD5|SHA1)\s*\(`),
		check: func(c *fileCtx, m []int) bool {
			if c.f.Code[m[0]] == 'c' {
				v := strings.ToLower(literalAt(c.f.Src, m[1]-1))
				return v == "md5" || v == "sha1" || v == "md4"
			}
			return bytes.Contains(c.f.Src, []byte("crypto-js"))
		}},
	{id: "sast.weak-random", sev: source.Low, cwe: "CWE-338", kw: []string{"Math.random"},
		re: regexp.MustCompile(`\bMath\.random\s*\(`),
		check: func(c *fileCtx, m []int) bool {
			return secretID.Match(lineWindow(c.f.Code, m[0], 2))
		}},
	{id: "sast.path-traversal", sev: source.Medium, cwe: "CWE-22", kw: []string{"path.", "File", "Stream", "unlink"},
		re: regexp.MustCompile(`(?:\bpath\.(?:join|resolve)|\b(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|appendFile|appendFileSync|unlink|unlinkSync|sendFile))\s*\(`),
		check: func(c *fileCtx, m []int) bool {
			s, e := argSpan(c.f.Code, m[1]-1, false)
			return userInput.Match(c.f.Code[s:e])
		}},
	{id: "sast.open-redirect", sev: source.Medium, cwe: "CWE-601", kw: []string{"redirect", "location"},
		re: regexp.MustCompile(`\bredirect\s*\(|\blocation\.href\s*=[^=]|\bwindow\.location\s*=[^=]|\blocation\.(?:assign|replace)\s*\(`),
		check: func(c *fileCtx, m []int) bool {
			code := c.f.Code
			if code[m[1]-1] == '(' {
				s, e := argSpan(code, m[1]-1, false)
				return redirectIn.Match(code[s:e])
			}
			return redirectIn.Match(restOfLine(code, m[1]-1))
		}},
	{id: "sast.regex-injection", sev: source.Low, cwe: "CWE-1333", kw: []string{"RegExp"},
		re: regexp.MustCompile(`\bnew\s+RegExp\s*\(`),
		check: func(c *fileCtx, m []int) bool {
			a := firstArg(c.f.Code, m[1]-1)
			return !isLiteral(a) && regexIn.Match(a) && !bytes.Contains(bytes.ToLower(a), []byte("escape"))
		}},
	{id: "sast.prototype-pollution", sev: source.Medium, cwe: "CWE-1321", kw: []string{"key", "prop", "attr", "__proto__", "Object.assign", "merge", "Merge", "extend", "defaultsDeep"},
		re: regexp.MustCompile(`\[\s*(?:key|prop|attr)\s*\]\s*\[[^\]\n]+\]\s*=[^=]|\.__proto__(?:\.\w+)?\s*=[^=]|\bObject\.assign\s*\(|\b(?:merge|mergeWith|defaultsDeep|extend|deepmerge|deepMerge)\s*\(`),
		check: func(c *fileCtx, m []int) bool {
			if c.f.Code[m[1]-1] != '(' {
				return true
			}
			s, e := argSpan(c.f.Code, m[1]-1, false)
			return reqBody.Match(c.f.Code[s:e])
		}},
	{id: "sast.cors-wildcard", sev: source.Medium, cwe: "CWE-942", kw: []string{"origin"},
		re: regexp.MustCompile(`\borigin\s*:\s*(?:true\b|['"] ['"])`),
		check: func(c *fileCtx, m []int) bool {
			if c.f.Code[m[1]-1] != 'e' && c.f.Src[m[1]-2] != '*' {
				return false
			}
			return credsTrue.Match(lineWindow(c.f.Code, m[0], 5))
		}},
	{id: "sast.cors-wildcard", sev: source.Medium, cwe: "CWE-942", kw: []string{"Access-Control-Allow-Origin", "access-control-allow-origin"}, onSrc: true,
		re: regexp.MustCompile(`(?i)['"]Access-Control-Allow-Origin['"]\s*[,:]\s*['"]\*['"]`),
		check: func(c *fileCtx, m []int) bool {
			return credHeader.Match(c.f.Src)
		}},
	{id: "sast.insecure-cookie", sev: source.Low, cwe: "CWE-614", kw: []string{"httpOnly", "secure"},
		re: regexp.MustCompile(`\b(?:httpOnly|secure)\s*:\s*false\b`),
		check: func(c *fileCtx, m []int) bool {
			// secure: false alone is common in SMTP/DB configs: require a cookie nearby.
			return c.f.Code[m[0]] == 'h' || cookieCtx.Match(lineWindow(c.f.Code, m[0], 3))
		}},
	{id: "sast.jwt-none", sev: source.High, cwe: "CWE-347", kw: []string{"algorithm"},
		re: regexp.MustCompile(`\balgorithms?\s*:\s*\[?\s*['"]`),
		check: func(c *fileCtx, m []int) bool {
			return strings.EqualFold(literalAt(c.f.Src, m[1]-1), "none")
		}},
	{id: "sast.jwt-none", sev: source.Medium, cwe: "CWE-347", kw: []string{"ignoreExpiration"},
		re: regexp.MustCompile(`\bignoreExpiration\s*:\s*true\b`)},
	{id: "sast.unsafe-deserialization", sev: source.High, cwe: "CWE-502", kw: []string{"unserialize"},
		re: regexp.MustCompile(`\bunserialize\s*\(`),
		check: func(c *fileCtx, m []int) bool {
			return bytes.Contains(c.f.Src, []byte("node-serialize")) || bytes.Contains(c.f.Src, []byte("serialize-javascript"))
		}},
	{id: "sast.unsafe-deserialization", sev: source.Low, cwe: "CWE-502", kw: []string{"load"},
		re: regexp.MustCompile(`(?i)\b(?:js)?yaml\.load\s*\(`),
		check: func(c *fileCtx, m []int) bool {
			s, e := argSpan(c.f.Code, m[1]-1, false)
			return bytes.Contains(c.f.Src, []byte("js-yaml")) && !bytes.Contains(bytes.ToLower(c.f.Code[s:e]), []byte("schema"))
		}},
}

var markupRules = []rule{
	{id: "sast.xss", sev: source.Medium, cwe: "CWE-79", kw: []string{"{@html"}, re: regexp.MustCompile(`\{@html\s`)},
	{id: "sast.xss", sev: source.Medium, cwe: "CWE-79", kw: []string{"v-html"}, re: regexp.MustCompile(`\bv-html\s*=`)},
}

// Analyze runs every rule on the code files and returns issues sorted by
// severity (high first), file and line.
func Analyze(files []source.File) []source.Issue {
	var out []source.Issue
	for _, f := range files {
		if !f.IsCode() || len(f.Code) != len(f.Src) {
			continue
		}
		c := &fileCtx{f: f}
		type key struct {
			id   string
			line int
		}
		seen := map[key]bool{}
		add := func(r rule, off int) {
			line := f.LineAt(off)
			k := key{r.id, line}
			if seen[k] {
				return
			}
			seen[k] = true
			sev := r.sev
			if isTest.MatchString(f.Path) {
				sev = lower(sev)
			}
			out = append(out, source.Issue{Rule: r.id, Severity: sev, File: f.Path, Line: line,
				Detail: r.cwe + " · " + snippet(f.Src, off)})
		}
		for _, r := range rules {
			text := f.Code
			if r.onSrc {
				text = f.Src
			}
			for _, m := range find(r, text) {
				if r.onSrc && (f.Code[m[0]] != f.Src[m[0]]) { // starts in a comment or inside a string
					continue
				}
				if r.check == nil || r.check(c, m) {
					add(r, m[0])
				}
			}
		}
		if f.Lang == "Svelte" || f.Lang == "Vue" {
			scripts := source.ScriptRanges(f.Src)
			for _, r := range markupRules {
				for _, m := range find(r, f.Src) {
					if !inRanges(scripts, m[0]) {
						add(r, m[0])
					}
				}
			}
		}
	}
	rank := map[string]int{source.High: 0, source.Medium: 1, source.Low: 2, source.Info: 3}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
	return out
}

// find runs r.re only on the lines holding one of r.kw: one regex pass over a
// whole file is NFA-slow, bytes.Index is not.
// shortcut: a match must start on a keyword line and end within 2 lines, a rule split over more lines is missed; fine for idiomatic code.
func find(r rule, text []byte) [][]int {
	var out [][]int
	done := map[int]bool{}
	for _, kw := range r.kw {
		k := []byte(kw)
		for i := 0; ; {
			j := bytes.Index(text[i:], k)
			if j < 0 {
				break
			}
			at := i + j
			i = at + len(k)
			s := bytes.LastIndexByte(text[:at], '\n') + 1
			if done[s] {
				continue
			}
			done[s] = true
			e := len(text)
			for n, p := 0, at; n < 3; n++ { // the keyword line plus two, for calls like origin:\n true
				q := bytes.IndexByte(text[p:], '\n')
				if q < 0 {
					break
				}
				p += q + 1
				e = p
			}
			for _, m := range r.re.FindAllIndex(text[s:e], -1) {
				if bytes.IndexByte(text[s:s+m[0]], '\n') < 0 { // starts on this line
					out = append(out, []int{s + m[0], s + m[1]})
				}
			}
		}
	}
	return out
}

// checkCommand flags child_process calls whose command is built at runtime.
func checkCommand(c *fileCtx, m []int) bool {
	code, src := c.f.Code, c.f.Src
	if !bytes.Contains(src, []byte("child_process")) {
		return false
	}
	if c.cpNames == nil {
		c.cpNames = map[string]bool{"child_process": true, "childProcess": true}
		for _, sm := range cpImport.FindAllSubmatch(src, -1) {
			c.cpNames[string(sm[1])+string(sm[2])] = true
		}
	}
	if m[0] > 0 && code[m[0]-1] == '.' { // re.exec(s) is RegExp, only cp.exec(…) counts
		i := m[0] - 1
		for i > 0 && isIdent(code[i-1]) {
			i--
		}
		if !c.cpNames[string(code[i:m[0]-1])] {
			return false
		}
	} else if bytes.HasSuffix(bytes.TrimRight(code[:m[0]], " "), []byte("function")) {
		return false
	}
	s, e := argSpan(code, m[1]-1, false)
	if r := bytes.TrimLeft(code[min(e+1, len(code)):], " \t"); len(r) > 0 && r[0] == '{' {
		return false // method definition exec(cmd) { … }
	}
	name := string(bytes.TrimRight(code[m[0]:m[1]-1], " \t"))
	if (strings.HasPrefix(name, "spawn") || strings.HasPrefix(name, "execFile")) && !shellTrue.Match(code[s:e]) {
		return false
	}
	return !isLiteral(firstArg(code, m[1]-1))
}

// argSpan returns the [s, e) span inside the call parenthesis at open; first stops
// at the first top-level comma.
func argSpan(code []byte, open int, first bool) (int, int) {
	depth := 0
	limit := min(len(code), open+4000)
	for i := open + 1; i < limit; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return open + 1, i
			}
			depth--
		case ',':
			if first && depth == 0 {
				return open + 1, i
			}
		}
	}
	return open + 1, limit
}

func firstArg(code []byte, open int) []byte {
	s, e := argSpan(code, open, true)
	return code[s:e]
}

func topComma(a []byte) int {
	depth := 0
	for i, ch := range a {
		switch ch {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// isLiteral reports whether a stripped expression is one plain string or number.
func isLiteral(a []byte) bool {
	a = bytes.TrimSpace(a)
	if len(a) == 0 {
		return false
	}
	if a[0] >= '0' && a[0] <= '9' {
		return true
	}
	if len(a) < 2 || !isQuote(a[0]) || a[len(a)-1] != a[0] {
		return false
	}
	return len(bytes.Trim(a[1:len(a)-1], " \n\r\t")) == 0 // contents blanked; `${` would remain
}

// literalAt returns the string literal value whose opening quote is at Src[q].
func literalAt(src []byte, q int) string {
	if q >= len(src) || !isQuote(src[q]) {
		return ""
	}
	end := bytes.IndexByte(src[q+1:min(len(src), q+200)], src[q])
	if end < 0 {
		return ""
	}
	return string(src[q+1 : q+1+end])
}

func restOfLine(b []byte, off int) []byte {
	end := bytes.IndexByte(b[off:], '\n')
	if end < 0 {
		return b[off:]
	}
	return b[off : off+end]
}

// lineWindow returns the lines from n before to n after the line holding off.
func lineWindow(b []byte, off, n int) []byte {
	s := off
	for k := 0; k <= n && s > 0; {
		s--
		if b[s] == '\n' {
			k++
		}
	}
	e := off
	for k := 0; k <= n && e < len(b); e++ {
		if b[e] == '\n' {
			k++
		}
	}
	return b[s:e]
}

func snippet(src []byte, off int) string {
	s := strings.TrimSpace(string(restOfLine(src, off)))
	if utf8.RuneCountInString(s) <= 60 {
		return s
	}
	r := []rune(s)
	return string(r[:59]) + "…"
}

func lower(sev string) string {
	switch sev {
	case source.High:
		return source.Medium
	case source.Medium:
		return source.Low
	}
	return source.Info
}

func inRanges(rs [][2]int, off int) bool {
	for _, r := range rs {
		if off >= r[0] && off < r[1] {
			return true
		}
	}
	return false
}

func isQuote(b byte) bool { return b == '"' || b == '\'' || b == '`' }

func isIdent(b byte) bool {
	return b == '_' || b == '$' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}
