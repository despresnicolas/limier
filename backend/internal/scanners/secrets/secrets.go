// Package secrets finds credentials committed in a project's files (SPECS F3).
// It only reads the bytes given by source.Walk; a secret never leaves it in clear.
package secrets

import (
	"bytes"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"limier/internal/scanners/source"
)

type rule struct {
	id       string
	sev      string
	re       *regexp.Regexp
	group    int      // submatch holding the secret, 0 = whole match
	keywords []string // the file must contain one of them (case-sensitive) before the regex runs
	ctx      string   // the lowercased file must contain it too
	detail   string   // fixed Detail instead of the masked secret
}

var rules = []rule{
	{id: "secret.aws-access-key", sev: source.High, re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), keywords: []string{"AKIA", "ASIA"}},
	{id: "secret.aws-secret-key", sev: source.High, re: regexp.MustCompile(`(?i)aws[a-z0-9_.-]*(?:secret|sk)[a-z0-9_.-]*["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+]|$)`), group: 1, ctx: "aws"},
	{id: "secret.github-token", sev: source.High, re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})`), keywords: []string{"gh", "github_pat_"}},
	{id: "secret.gitlab-token", sev: source.High, re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`), keywords: []string{"glpat-"}},
	{id: "secret.slack-token", sev: source.High, re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`), keywords: []string{"xox"}},
	{id: "secret.slack-webhook", sev: source.High, re: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+`), keywords: []string{"hooks.slack.com"}},
	{id: "secret.stripe-live-key", sev: source.High, re: regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{20,}`), keywords: []string{"k_live_"}},
	{id: "secret.stripe-test-key", sev: source.Low, re: regexp.MustCompile(`\bsk_test_[A-Za-z0-9]{20,}`), keywords: []string{"sk_test_"}},
	{id: "secret.google-api-key", sev: source.High, re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`), keywords: []string{"AIza"}},
	{id: "secret.anthropic-key", sev: source.High, re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`), keywords: []string{"sk-ant-"}},
	// "sk-ant-…" fails the plain branch at its second '-', so the two rules never overlap.
	{id: "secret.openai-key", sev: source.High, re: regexp.MustCompile(`\bsk-(?:proj-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})`), keywords: []string{"sk-"}},
	{id: "secret.npm-token", sev: source.High, re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), keywords: []string{"npm_"}},
	{id: "secret.npm-token", sev: source.High, re: regexp.MustCompile(`_authToken\s*=\s*["']?([^\s"']+)`), group: 1, keywords: []string{"_authToken"}},
	{id: "secret.sendgrid-key", sev: source.High, re: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`), keywords: []string{"SG."}},
	{id: "secret.twilio-key", sev: source.High, re: regexp.MustCompile(`\b(?:SK|AC)[0-9a-fA-F]{32}\b`), keywords: []string{"SK", "AC"}, ctx: "twilio"},
	{id: "secret.private-key", sev: source.High, re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`), keywords: []string{"PRIVATE KEY"}, detail: "clé privée"},
	{id: "secret.jwt", sev: source.Medium, re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), keywords: []string{"eyJ"}},
	// Starts with the literal "://" so the regexp engine can jump between candidates.
	{id: "secret.url-credentials", sev: source.High, re: regexp.MustCompile("://([^\\s:/@'\"`<>]+):([^\\s/@'\"`<>]+)@[A-Za-z0-9.-]+"), group: 2, keywords: []string{"://"}},
}

// genericValue matches what follows a secret word ending a key: `": "v"`, ` = 'v'`, `=v`.
// Anchored at each word end so a key must END with it (`author`, `password_hash` stay quiet).
var genericValue = regexp.MustCompile("^[\"']?[ \t]*[:=][ \t]*(?:\"([^\"\n]*)\"|'([^'\n]*)'|`([^`\n]*)`|([^\\s,;'\"`#]+))")

var genericWords = []string{"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "auth", "privatekey", "private_key", "access_key", "accesskey"}

var placeholderWords = []string{"xxx", "your_", "your-", "<", "changeme", "change_me", "example", "dummy", "test", "placeholder", "${", "{{", "process.env", "import.meta.env", "****", "redacted", "sample", "fake", "replace", "generate", "insert_", "insert-"}

// Analyze returns the leaked secrets of files, high severity first.
func Analyze(files []source.File) []source.Issue {
	var out []source.Issue
	seen := map[string]bool{}
	add := func(f source.File, id, sev string, line int, detail string) {
		key := fmt.Sprint(id, "\x00", f.Path, "\x00", line)
		if seen[key] {
			return
		}
		seen[key] = true
		if isTestPath(f.Path) || isExamplePath(f.Path) {
			sev = lower(sev)
		}
		out = append(out, source.Issue{Rule: id, Severity: sev, File: f.Path, Line: line, Detail: detail})
	}
	for _, f := range files {
		if skipFile(f.Path) {
			continue
		}
		lowSrc := asciiLower(f.Src)
		providerLines := map[int]bool{}
		for _, r := range rules {
			if !containsAny(f.Src, r.keywords) || (r.ctx != "" && !bytes.Contains(lowSrc, []byte(r.ctx))) {
				continue
			}
			for _, m := range r.re.FindAllSubmatchIndex(f.Src, -1) {
				v := string(f.Src[m[2*r.group]:m[2*r.group+1]])
				if r.id == "secret.url-credentials" && (placeholder(string(f.Src[m[2]:m[3]])) || placeholder(v) || v == string(f.Src[m[2]:m[3]])) {
					// shortcut: user == password (postgres:postgres@…) is taken as a local default, flag it once dev defaults get their own rule
					continue
				}
				if r.detail == "" && placeholder(strings.TrimPrefix(v, "sk_test_")) {
					continue
				}
				d := r.detail
				if d == "" {
					d = mask(v)
				}
				line := f.LineAt(m[0])
				providerLines[line] = true
				add(f, r.id, r.sev, line, d)
			}
		}
		genericScan(f, lowSrc, providerLines, add)
		if n := envValues(f); n > 0 {
			add(f, "secret.env-file", source.High, 1, fmt.Sprint(n))
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

func genericScan(f source.File, lowSrc []byte, skipLines map[int]bool, add func(source.File, string, string, int, string)) {
	start, line := 0, 1
	for start < len(f.Src) {
		end := bytes.IndexByte(f.Src[start:], '\n')
		if end < 0 {
			end = len(f.Src)
		} else {
			end += start
		}
		if !skipLines[line] {
			genericLine(f, lowSrc, start, end, line, add)
		}
		start, line = end+1, line+1
	}
}

func genericLine(f source.File, lowSrc []byte, start, end, line int, add func(source.File, string, string, int, string)) {
	low := lowSrc[start:end]
	for _, w := range genericWords {
		for from := 0; ; {
			i := bytes.Index(low[from:], []byte(w))
			if i < 0 {
				break
			}
			ks, ke := from+i, from+i+len(w)
			from = ke
			m := genericValue.FindSubmatchIndex(f.Src[start+ke : end])
			if m == nil {
				continue
			}
			g := 1
			for g < 4 && m[2*g] < 0 {
				g++
			}
			if g == 4 && f.IsCode() {
				continue // unquoted in code is an identifier or a call, not a literal
			}
			vs, ve := start+ke+m[2*g], start+ke+m[2*g+1]
			if f.IsCode() && (f.Code[vs-1] != f.Src[vs-1] || (ve > vs && f.Code[vs] != ' ')) {
				continue // the quote or the "literal" is inside a comment
			}
			v := string(f.Src[vs:ve])
			if len(v) < 8 || strings.ContainsAny(v, " \t") || placeholder(v) || entropy(v) < 3.5 {
				continue
			}
			for ks > 0 && isKeyChar(low[ks-1]) {
				ks--
			}
			add(f, "secret.generic", source.Medium, line, string(f.Src[start+ks:start+ke])+" = "+mask(v))
		}
	}
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

// asciiLower keeps offsets aligned with the source, unlike bytes.ToLower on UTF-8.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// envValues counts the real values of a .env file, 0 for templates and other Env files (.npmrc…).
func envValues(f source.File) int {
	base := path.Base(f.Path)
	if f.Lang != "Env" || (base != ".env" && !strings.HasPrefix(base, ".env.")) {
		return 0
	}
	switch path.Ext(base) {
	case ".example", ".sample", ".template", ".dist", ".defaults", ".tpl":
		return 0
	}
	n := 0
	for _, l := range strings.Split(string(f.Src), "\n") {
		l = strings.TrimSpace(l)
		k, v, ok := strings.Cut(strings.TrimPrefix(l, "export "), "=")
		if !ok || strings.HasPrefix(l, "#") || strings.TrimSpace(k) == "" {
			continue
		}
		v = strings.TrimSpace(v)
		if i := strings.Index(v, " #"); i >= 0 && v[0] != '"' && v[0] != '\'' {
			v = strings.TrimSpace(v[:i])
		}
		v = strings.Trim(v, `"'`)
		if v != "" && !placeholder(v) {
			n++
		}
	}
	return n
}

func skipFile(p string) bool {
	switch path.Base(p) {
	case "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock":
		return true
	}
	return strings.HasSuffix(p, ".map")
}

// isExamplePath matches templates such as .env.example or config.sample.json: values there are usually fake.
func isExamplePath(p string) bool {
	base := strings.ToLower(path.Base(p))
	for _, w := range []string{".example", ".sample", ".template", ".dist"} {
		if strings.Contains(base, w) {
			return true
		}
	}
	return false
}

func isTestPath(p string) bool {
	for _, d := range []string{"test/", "tests/", "__tests__/", "fixtures/", "__fixtures__/", "mocks/", "__mocks__/"} {
		if strings.HasPrefix(p, d) || strings.Contains(p, "/"+d) {
			return true
		}
	}
	base := path.Base(p)
	return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
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

func placeholder(v string) bool {
	l := strings.ToLower(v)
	for _, w := range placeholderWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	switch l {
	case "password", "pass", "secret", "token", "user", "username", "true", "false", "null", "undefined":
		return true
	}
	// mostly one character: "aaaaaaaa", "00000000"
	counts := map[rune]int{}
	for _, c := range l {
		counts[c]++
		if counts[c]*2 > utf8.RuneCountInString(l) {
			return true
		}
	}
	return strings.HasPrefix(v, "$")
}

func entropy(v string) float64 {
	counts := map[rune]float64{}
	n := 0.0
	for _, c := range v {
		counts[c]++
		n++
	}
	e := 0.0
	for _, c := range counts {
		e -= c / n * math.Log2(c/n)
	}
	return e
}

// mask keeps 4 characters so the user recognises the secret without the Code tab exposing it.
func mask(v string) string {
	r := []rune(v)
	return fmt.Sprintf("%s…(%d car.)", string(r[:min(4, len(r))]), len(r))
}

func containsAny(b []byte, words []string) bool {
	if len(words) == 0 {
		return true
	}
	for _, w := range words {
		if bytes.Contains(b, []byte(w)) {
			return true
		}
	}
	return false
}
