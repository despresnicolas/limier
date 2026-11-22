package imports

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"limier/internal/scanners"
	"limier/internal/scanners/source"
)

// pkg is one package.json of the project (the root, or a workspace).
type pkg struct {
	dir     string // "" for the root
	file    string // path of the package.json
	name    string
	raw     map[string]any
	deps    []string // dependencies then devDependencies, as declared
	depSet  map[string]bool
	entries []string // files named by main/module/exports/… (see entryFields)
}

// tsconf holds the alias settings of a tsconfig.json/jsconfig.json, `extends` applied.
type tsconf struct {
	base      string // baseUrl, as a root-relative dir
	hasBase   bool
	paths     map[string][]string
	pathsBase string
}

type analyzer struct {
	all    map[string]source.File // every file by path
	code   map[string]bool
	pkgs   map[string]*pkg // by dir
	byName map[string]*pkg // workspace packages by name
	ts     map[string]*tsconf
}

var exts = []string{".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".svelte", ".vue"}

// TS ESM writes the output extension in imports: ./x.js means ./x.ts.
var tsFor = map[string][]string{".js": {".ts", ".tsx"}, ".jsx": {".tsx"}, ".mjs": {".mts"}, ".cjs": {".cts"}}

var builtins = map[string]bool{}

func init() {
	for _, b := range strings.Fields(`assert async_hooks buffer child_process cluster console constants crypto dgram
		diagnostics_channel dns domain events fs http http2 https inspector module net os path perf_hooks process
		punycode querystring readline repl stream string_decoder sys timers tls trace_events tty url util v8 vm wasi
		worker_threads zlib`) {
		builtins[b] = true
	}
}

func newAnalyzer(files []source.File) *analyzer {
	a := &analyzer{all: map[string]source.File{}, code: map[string]bool{}, pkgs: map[string]*pkg{}, byName: map[string]*pkg{}, ts: map[string]*tsconf{}}
	for _, f := range files {
		a.all[f.Path] = f
		if f.IsCode() {
			a.code[f.Path] = true
		}
	}
	for _, f := range files {
		if path.Base(f.Path) != "package.json" {
			continue
		}
		var raw map[string]any
		m, err := scanners.ParseManifest(f.Src)
		if err != nil || json.Unmarshal(f.Src, &raw) != nil {
			continue
		}
		p := &pkg{dir: dirOf(f.Path), file: f.Path, name: m.Name, raw: raw, depSet: map[string]bool{}}
		for _, deps := range []map[string]string{m.Dependencies, m.DevDependencies} {
			for _, n := range sortedKeys(deps) {
				if !p.depSet[n] {
					p.depSet[n] = true
					p.deps = append(p.deps, n)
				}
			}
		}
		a.pkgs[p.dir] = p
		if p.dir != "" && p.name != "" {
			a.byName[p.name] = p
		}
	}
	if a.pkgs[""] == nil { // no root package.json: still one package for ownership
		a.pkgs[""] = &pkg{depSet: map[string]bool{}}
	}
	for _, p := range a.pkgs {
		for _, field := range []string{"main", "module", "browser", "types", "typings", "exports", "bin"} {
			for _, s := range stringLeaves(p.raw[field]) {
				if f, ok := a.entryFile(p.dir, s); ok {
					p.entries = append(p.entries, f)
				}
			}
		}
	}
	return a
}

func dirOf(p string) string {
	if d := path.Dir(p); d != "." {
		return d
	}
	return ""
}

// owner returns the package whose directory most closely contains p.
func (a *analyzer) owner(p string) *pkg {
	for d := dirOf(p); ; d = dirOf(d) {
		if pk := a.pkgs[d]; pk != nil {
			return pk
		}
		if d == "" {
			return a.pkgs[""]
		}
	}
}

func stringLeaves(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, stringLeaves(x)...)
		}
		return out
	case map[string]any:
		var out []string
		for _, k := range sortedKeys(t) {
			out = append(out, stringLeaves(t[k])...)
		}
		return out
	}
	return nil
}

var reBuildDir = regexp.MustCompile(`^(?:dist|build|lib|out|esm|cjs)/`)

// entryFile resolves a path from package.json; built paths (dist/x.js, dist/x.d.ts)
// are mapped back to src/ since build output is not scanned.
func (a *analyzer) entryFile(dir, p string) (string, bool) {
	if strings.Contains(p, "*") {
		return "", false // shortcut: exports patterns ("./*") are not expanded, glob them if dead files show up there.
	}
	p = path.Join(dir, p)
	if f, ok := a.resolveFile(p); ok {
		return f, true
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(p, dir), "/")
	if !reBuildDir.MatchString(rel) {
		return "", false
	}
	rel = strings.TrimSuffix(reBuildDir.ReplaceAllString(rel, "src/"), ".d.ts")
	return a.resolveFile(path.Join(dir, rel))
}

// resolveFile finds the file a path refers to, trying extensions and index files.
func (a *analyzer) resolveFile(p string) (string, bool) {
	if p == ".." || strings.HasPrefix(p, "../") {
		return "", false
	}
	if _, ok := a.all[p]; ok {
		return p, true
	}
	ext := path.Ext(p)
	for _, e := range tsFor[ext] {
		if c := strings.TrimSuffix(p, ext) + e; a.code[c] {
			return c, true
		}
	}
	for _, e := range exts {
		if a.code[p+e] {
			return p + e, true
		}
	}
	for _, e := range exts {
		if c := path.Join(p, "index"+e); a.code[c] {
			return c, true
		}
	}
	return "", false
}

// target is what a specifier points to.
type target struct {
	files      []string // local files
	pkg        string   // package root name (external or workspace)
	external   bool
	unresolved bool
}

func pkgRoot(spec string) string {
	parts := strings.SplitN(spec, "/", 3)
	if strings.HasPrefix(spec, "@") && len(parts) > 1 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

// isAsset reports a non-code import (./logo.svg, ./x.css): not counted as unresolved.
func isAsset(spec string) bool {
	e := path.Ext(spec)
	if e == "" {
		return false
	}
	for _, c := range exts {
		if e == c {
			return false
		}
	}
	return true
}

func (a *analyzer) local(p, spec string) target {
	if f, ok := a.resolveFile(p); ok {
		return target{files: []string{f}}
	}
	return target{unresolved: !isAsset(spec)}
}

func (a *analyzer) resolve(from string, own *pkg, spec string) target {
	if i := strings.IndexAny(spec, "?#"); i > 0 {
		spec = spec[:i] // Vite queries (?raw, ?url)
	}
	switch {
	case spec == "" || strings.ContainsAny(spec, ":\x00") || strings.HasPrefix(spec, "#"):
		// node:, virtual:, astro:, URLs and package.json "imports" (#x).
		// shortcut: "#x" subpath imports are not resolved, read package.json "imports" if projects use them.
		return target{}
	case spec == "." || spec == ".." || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../"):
		return a.local(path.Join(dirOf(from), spec), spec)
	case strings.HasPrefix(spec, "/"):
		return a.local(path.Join(own.dir, spec[1:]), spec)
	}
	cfg := a.tsFor(dirOf(from))
	if cfg != nil {
		if subs, ok := matchPaths(cfg.paths, spec); ok {
			for _, s := range subs {
				if f, ok := a.resolveFile(path.Join(cfg.pathsBase, s)); ok {
					return target{files: []string{f}}
				}
			}
			return target{unresolved: !isAsset(spec)}
		}
	}
	if rest, ok := strings.CutPrefix(spec, "$lib"); ok && (rest == "" || rest[0] == '/') {
		return a.local(path.Join(own.dir, "src/lib", rest), spec)
	}
	if strings.HasPrefix(spec, "$") {
		return target{} // SvelteKit virtual modules ($app/*, $env/*, $service-worker)
	}
	if strings.HasPrefix(spec, "~/") || strings.HasPrefix(spec, "@/") {
		if f, ok := a.resolveFile(path.Join(own.dir, "src", spec[2:])); ok {
			return target{files: []string{f}}
		}
		return a.local(path.Join(own.dir, spec[2:]), spec)
	}
	if cfg != nil && cfg.hasBase {
		if f, ok := a.resolveFile(path.Join(cfg.base, spec)); ok {
			return target{files: []string{f}}
		}
	}
	root := pkgRoot(spec)
	if ws := a.byName[root]; ws != nil {
		t := target{pkg: root}
		if sub := strings.TrimPrefix(spec[len(root):], "/"); sub != "" {
			for _, d := range []string{"", "src"} {
				if f, ok := a.resolveFile(path.Join(ws.dir, d, sub)); ok {
					t.files = []string{f}
					return t
				}
			}
			// shortcut: workspace "exports" subpath maps are not read, only <ws>/x and <ws>/src/x; read them if imports show as unlinked.
		}
		t.files = ws.entries
		if len(t.files) == 0 {
			for _, c := range []string{"src/index", "index"} {
				if f, ok := a.resolveFile(path.Join(ws.dir, c)); ok {
					t.files = []string{f}
					break
				}
			}
		}
		return t
	}
	if builtins[root] && !own.depSet[root] {
		return target{}
	}
	return target{pkg: root, external: true}
}

// matchPaths applies tsconfig "paths": the longest matching pattern wins.
// A bare "*" catch-all is ignored so plain package imports stay packages.
func matchPaths(paths map[string][]string, spec string) ([]string, bool) {
	best, bestLen := "", -1
	for pat := range paths {
		pre, suf, wild := strings.Cut(pat, "*")
		if pat == "*" || (!wild && pat != spec) || (wild && (!strings.HasPrefix(spec, pre) || !strings.HasSuffix(spec[len(pre):], suf))) {
			continue
		}
		if len(pre) > bestLen || len(pre) == bestLen && pat < best {
			best, bestLen = pat, len(pre)
		}
	}
	if bestLen < 0 {
		return nil, false
	}
	pre, suf, wild := strings.Cut(best, "*")
	star := ""
	if wild {
		star = spec[len(pre) : len(spec)-len(suf)]
	}
	var out []string
	for _, t := range paths[best] {
		out = append(out, strings.Replace(t, "*", star, 1))
	}
	return out, true
}

// tsFor returns the nearest tsconfig.json/jsconfig.json of a directory.
func (a *analyzer) tsFor(dir string) *tsconf {
	if c, ok := a.ts[dir]; ok {
		return c
	}
	var c *tsconf
	for _, n := range []string{"tsconfig.json", "jsconfig.json"} {
		if _, ok := a.all[path.Join(dir, n)]; ok {
			c = a.loadTS(path.Join(dir, n), 0)
			break
		}
	}
	if c == nil && dir != "" {
		c = a.tsFor(dirOf(dir))
	}
	a.ts[dir] = c
	return c
}

func (a *analyzer) loadTS(p string, depth int) *tsconf {
	f, ok := a.all[p]
	if !ok {
		return nil
	}
	var raw struct {
		Extends         any `json:"extends"`
		CompilerOptions struct {
			BaseURL *string             `json:"baseUrl"`
			Paths   map[string][]string `json:"paths"`
		} `json:"compilerOptions"`
	}
	if json.Unmarshal(jsonc(f.Src), &raw) != nil {
		return nil
	}
	c := &tsconf{}
	pathsDir := dirOf(p)
	// shortcut: only one level of local `extends` is followed, packages (@tsconfig/x) are not; follow deeper if aliases go missing.
	if ext, _ := raw.Extends.(string); depth == 0 && strings.HasPrefix(ext, ".") {
		if !strings.HasSuffix(ext, ".json") {
			ext += ".json"
		}
		if parent := a.loadTS(path.Join(dirOf(p), ext), depth+1); parent != nil {
			*c = *parent
			pathsDir = parent.pathsBase
		}
	}
	if b := raw.CompilerOptions.BaseURL; b != nil {
		c.base, c.hasBase = path.Join(dirOf(p), *b), true
	}
	if raw.CompilerOptions.Paths != nil {
		c.paths, pathsDir = raw.CompilerOptions.Paths, dirOf(p)
	}
	c.pathsBase = pathsDir
	if c.hasBase {
		c.pathsBase = c.base
	}
	if c.base == "." {
		c.base = ""
	}
	if c.pathsBase == "." {
		c.pathsBase = ""
	}
	return c
}

var reTrailingComma = regexp.MustCompile(`,(\s*[}\]])`)

// jsonc strips comments and trailing commas from tsconfig-style JSON.
func jsonc(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inStr:
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				i++
				out = append(out, b[i])
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		default:
			out = append(out, c)
		}
	}
	// shortcut: a string value ending in ",}" would lose its comma, harmless for paths/baseUrl.
	return reTrailingComma.ReplaceAll(out, []byte("$1"))
}
