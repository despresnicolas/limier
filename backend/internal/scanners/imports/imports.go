// Package imports builds the import graph of a Node.js project (SPECS F3.3) from the
// source files alone, and derives circular imports, dead files, unused exports and
// unused dependencies from it. Imports are found by pattern, not by a full parser.
package imports

import (
	"cmp"
	"path"
	"regexp"
	"slices"
	"strings"

	"limier/internal/scanners/source"
)

// Node is a local file (ID = its path) or an external package (ID = package root name).
type Node struct {
	ID       string
	External bool
	Package  string
}

// Edge is "From imports To". TypeOnly when every import between them is `import type`.
// Circular when both ends are in the same runtime import cycle.
type Edge struct {
	From, To string
	TypeOnly bool
	Circular bool
}

// Report is the result of Analyze.
type Report struct {
	Nodes            []Node
	Edges            []Edge
	ImportedPackages map[string]bool // external packages imported by local files
	PackageUsage     map[string]int  // package → distinct local files importing it
	Cycles           [][]string      // runtime cycles a→b→c (back to a implied), shortest first
	UnusedDeps       []string        // "name", or "workspaceDir: name"
	DeadFiles        []string
	UnusedExports    []source.Issue
	Unresolved       int // relative or aliased imports that resolve to no file
}

// MaxCycles caps Report.Cycles.
const MaxCycles = 50

// Rule ids.
const (
	RuleCycle        = "imports.cycle"
	RuleDeadFile     = "imports.dead-file"
	RuleUnusedDep    = "imports.unused-dep"
	RuleUnusedExport = "imports.unused-export"
)

// Analyze builds the import graph of files (as read by source.Walk).
func Analyze(files []source.File) Report {
	a := newAnalyzer(files)
	r := Report{ImportedPackages: map[string]bool{}, PackageUsage: map[string]int{}}
	type key struct{ from, to string }
	edges := map[key]*Edge{}
	usedNames := map[string]map[string]bool{} // target file → names imported from it
	filePkgs := map[string]map[string]bool{}  // file → packages (external or workspace) it imports
	exportsOf := map[string][]export{}
	var codePaths []string
	for _, f := range files {
		if !f.IsCode() {
			continue
		}
		codePaths = append(codePaths, f.Path)
		exportsOf[f.Path] = parseExports(f)
		own := a.owner(f.Path)
		for _, im := range parseImports(f) {
			t := a.resolve(f.Path, own, im.spec)
			if t.unresolved {
				r.Unresolved++
			}
			if t.pkg != "" {
				addSet(filePkgs, f.Path, t.pkg)
			}
			tos := t.files
			if t.external {
				tos = []string{t.pkg}
				r.ImportedPackages[t.pkg] = true
			}
			for _, to := range tos {
				if !t.external && !a.code[to] {
					continue // JSON or other non-code file
				}
				if e := edges[key{f.Path, to}]; e != nil {
					e.TypeOnly = e.TypeOnly && im.typeOnly
				} else {
					edges[key{f.Path, to}] = &Edge{From: f.Path, To: to, TypeOnly: im.typeOnly}
				}
				if !t.external {
					for _, n := range im.names {
						addSet(usedNames, to, n)
					}
				}
			}
		}
	}
	for _, f := range codePaths {
		for p := range filePkgs[f] {
			if r.ImportedPackages[p] {
				r.PackageUsage[p]++
			}
		}
	}

	for _, e := range edges {
		r.Edges = append(r.Edges, *e)
	}
	slices.SortFunc(r.Edges, func(x, y Edge) int { return cmp.Or(cmp.Compare(x.From, y.From), cmp.Compare(x.To, y.To)) })
	for _, p := range codePaths {
		r.Nodes = append(r.Nodes, Node{ID: p})
	}
	for _, p := range sortedKeys(r.ImportedPackages) {
		r.Nodes = append(r.Nodes, Node{ID: p, External: true, Package: p})
	}

	runtime, all := map[string][]string{}, map[string][]string{}
	for _, e := range r.Edges {
		if !a.code[e.To] {
			continue
		}
		all[e.From] = append(all[e.From], e.To)
		if !e.TypeOnly {
			runtime[e.From] = append(runtime[e.From], e.To)
		}
	}
	var comp map[string]int
	r.Cycles, comp = findCycles(codePaths, runtime)
	for i, e := range r.Edges {
		if c, ok := comp[e.From]; ok && !e.TypeOnly && comp[e.To] == c {
			r.Edges[i].Circular = true
		}
	}

	entry := a.entries(codePaths)
	hasEntry := map[*pkg]bool{}
	var queue []string
	reached := map[string]bool{}
	for _, p := range codePaths {
		if entry[p] {
			hasEntry[a.owner(p)] = true
			reached[p] = true
			queue = append(queue, p)
		}
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, to := range all[p] {
			if !reached[to] {
				reached[to] = true
				queue = append(queue, to)
			}
		}
	}
	dead := map[string]bool{}
	for _, p := range codePaths {
		// shortcut: a package with no entry point found reports no dead files (better silent than wrong); add entry conventions when users hit it.
		if !reached[p] && hasEntry[a.owner(p)] {
			dead[p] = true
			r.DeadFiles = append(r.DeadFiles, p)
		}
	}

	for _, p := range codePaths {
		if entry[p] || dead[p] || usedNames[p]["*"] {
			continue
		}
		seen := map[string]bool{}
		for _, ex := range exportsOf[p] {
			if !seen[ex.name] && !usedNames[p][ex.name] {
				r.UnusedExports = append(r.UnusedExports, source.Issue{Rule: RuleUnusedExport, Severity: source.Info, File: p, Line: ex.line, Detail: ex.name})
			}
			seen[ex.name] = true
		}
	}

	r.UnusedDeps = a.unusedDeps(codePaths, filePkgs)
	return r
}

// Issues lists the findings: cycles, dead files, unused dependencies, unused exports.
func (r Report) Issues() []source.Issue {
	var out []source.Issue
	for _, c := range r.Cycles {
		out = append(out, source.Issue{Rule: RuleCycle, Severity: source.Medium, File: c[0], Detail: strings.Join(append(slices.Clone(c), c[0]), " → ")})
	}
	for _, f := range r.DeadFiles {
		out = append(out, source.Issue{Rule: RuleDeadFile, Severity: source.Low, File: f})
	}
	for _, d := range r.UnusedDeps {
		file, name := "package.json", d
		if dir, n, ok := strings.Cut(d, ": "); ok {
			file, name = dir+"/package.json", n
		}
		out = append(out, source.Issue{Rule: RuleUnusedDep, Severity: source.Low, File: file, Detail: name})
	}
	return append(out, r.UnusedExports...)
}

// findCycles runs Tarjan's SCC and returns one shortest cycle per cyclic component,
// plus the component id of every node in a cycle.
func findCycles(nodes []string, adj map[string][]string) ([][]string, map[string]int) {
	index, low, onStack := map[string]int{}, map[string]int{}, map[string]bool{}
	var stack []string
	var sccs [][]string
	var visit func(v string)
	visit = func(v string) {
		index[v], low[v] = len(index), len(index)
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range adj[v] {
			if _, seen := index[w]; !seen {
				visit(w)
				low[v] = min(low[v], low[w])
			} else if onStack[w] {
				low[v] = min(low[v], index[w])
			}
		}
		if low[v] == index[v] {
			var scc []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			sccs = append(sccs, scc)
		}
	}
	for _, v := range nodes {
		if _, seen := index[v]; !seen {
			visit(v)
		}
	}
	comp := map[string]int{}
	var cycles [][]string
	for i, scc := range sccs {
		if len(scc) == 1 && !slices.Contains(adj[scc[0]], scc[0]) {
			continue
		}
		for _, v := range scc {
			comp[v] = i
		}
		cycles = append(cycles, shortestCycle(slices.Min(scc), adj, comp, i))
	}
	slices.SortFunc(cycles, func(x, y []string) int { return cmp.Or(cmp.Compare(len(x), len(y)), slices.Compare(x, y)) })
	if len(cycles) > MaxCycles {
		cycles = cycles[:MaxCycles]
	}
	return cycles, comp
}

// shortestCycle finds, by BFS inside component c, the shortest path from s back to s.
func shortestCycle(s string, adj map[string][]string, comp map[string]int, c int) []string {
	parent := map[string]string{s: ""}
	queue := []string{s}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, v := range adj[u] {
			if v == s {
				var cyc []string
				for x := u; x != ""; x = parent[x] {
					cyc = append(cyc, x)
				}
				slices.Reverse(cyc)
				return cyc
			}
			if _, seen := parent[v]; !seen {
				if cv, in := comp[v]; in && cv == c {
					parent[v] = u
					queue = append(queue, v)
				}
			}
		}
	}
	return []string{s}
}

var (
	reEntryBase = regexp.MustCompile(`\.(?:test|spec|stories|story|config)\.|^\.`)
	reHTMLSrc   = regexp.MustCompile(`(?i)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']`)
	reToken     = regexp.MustCompile(`[\w@./-]+`)
)

var testDirs = map[string]bool{"__tests__": true, "__mocks__": true, "test": true, "tests": true, "e2e": true, "cypress": true, "playwright": true}

var entryStems = map[string]bool{
	"index": true, "main": true, "server": true, "app": true, "src/index": true, "src/main": true,
	"middleware": true, "src/middleware": true, "instrumentation": true, "src/instrumentation": true, // Next
	"src/hooks": true, "src/hooks.server": true, "src/hooks.client": true, "src/service-worker": true, "src/service-worker/index": true, // SvelteKit
}

var entryDirs = []string{"scripts/", "bin/", "src/routes/", "src/params/", "pages/", "app/", "src/pages/", "src/app/"}

// Nuxt auto-imports whole folders, so they are entries only in Nuxt packages.
var nuxtDirs = []string{"pages/", "layouts/", "plugins/", "middleware/", "server/", "composables/", "components/", "utils/"}

// entries returns the code files that are entry points of their package.
func (a *analyzer) entries(codePaths []string) map[string]bool {
	entry := map[string]bool{}
	for _, p := range a.pkgs {
		for _, f := range p.entries {
			entry[f] = true
		}
		scripts, _ := p.raw["scripts"].(map[string]any)
		for _, s := range stringLeaves(scripts) {
			for _, tok := range reToken.FindAllString(s, -1) {
				if strings.Contains(tok, "/") || slices.Contains(exts, path.Ext(tok)) {
					if f, ok := a.resolveFile(path.Join(p.dir, tok)); ok {
						entry[f] = true
					}
				}
			}
		}
	}
	for _, f := range a.all {
		if f.Lang != "HTML" {
			continue
		}
		own := a.owner(f.Path)
		for _, m := range reHTMLSrc.FindAllSubmatch(f.Src, -1) {
			src := string(m[1])
			p := path.Join(dirOf(f.Path), src)
			if strings.HasPrefix(src, "/") {
				p = path.Join(own.dir, src)
			}
			if r, ok := a.resolveFile(p); ok {
				entry[r] = true
			}
		}
	}
	for _, f := range codePaths {
		own := a.owner(f)
		rel := strings.TrimPrefix(strings.TrimPrefix(f, own.dir), "/")
		segs := strings.Split(rel, "/")
		dirs := entryDirs
		if own.depSet["nuxt"] {
			dirs = append(slices.Clone(dirs), nuxtDirs...)
		}
		if reEntryBase.MatchString(path.Base(rel)) ||
			entryStems[strings.TrimSuffix(rel, path.Ext(rel))] ||
			slices.ContainsFunc(segs[:len(segs)-1], func(s string) bool { return testDirs[s] }) ||
			slices.ContainsFunc(dirs, func(d string) bool { return strings.HasPrefix(rel, d) }) {
			entry[f] = true
		}
	}
	return entry
}

// binAliases are the commands a package installs under another name.
var binAliases = map[string][]string{
	"typescript": {"tsc"}, "@sveltejs/kit": {"svelte-kit"}, "@playwright/test": {"playwright"},
	"npm-run-all": {"run-s", "run-p"}, "npm-run-all2": {"run-s", "run-p", "npm-run-all"},
	"@biomejs/biome": {"biome"}, "@vue/cli-service": {"vue-cli-service"}, "@angular/cli": {"ng"},
	"@nestjs/cli": {"nest"}, "@changesets/cli": {"changeset"}, "@babel/cli": {"babel"},
	"webpack-cli": {"webpack"}, "@storybook/cli": {"storybook", "sb"}, "@stryker-mutator/core": {"stryker"},
}

// implicitByLang are dependencies used by having files of a language, not by import.
var implicitByLang = map[string]string{"typescript": "TypeScript", "svelte": "Svelte", "vue": "Vue"}

// peerOf are dependencies that another package loads itself, without an import in the project.
// shortcut: hand-picked list, not read from the packages' peerDependencies (they are not scanned); extend it on reported false positives.
var peerOf = map[string]string{
	"@sveltejs/vite-plugin-svelte": "@sveltejs/kit", "@vitejs/plugin-vue": "nuxt",
	"@nestjs/platform-express": "@nestjs/core", "rxjs": "@nestjs/common", "reflect-metadata": "@nestjs/common",
	"pg": "@prisma/adapter-pg", "@prisma/client": "prisma", "react-dom": "next",
}

var reESLintName = regexp.MustCompile(`^(@[^/]+)?/?eslint-(?:config|plugin)(?:-(.+))?$`)

func (a *analyzer) unusedDeps(codePaths []string, filePkgs map[string]map[string]bool) []string {
	var out []string
	for _, dir := range sortedKeys(a.pkgs) {
		p := a.pkgs[dir]
		if len(p.deps) == 0 {
			continue
		}
		imported := map[string]bool{}
		for _, f := range codePaths {
			// Root dependencies are hoisted to every workspace, so the root counts imports from anywhere.
			if dir == "" || a.owner(f) == p {
				for n := range filePkgs[f] {
					imported[n] = true
				}
			}
		}
		langs := map[string]bool{}
		var config strings.Builder
		for _, f := range a.all {
			if a.owner(f.Path) != p {
				continue
			}
			langs[f.Lang] = true
			base := path.Base(f.Path)
			if strings.Contains(base, ".config.") || strings.HasPrefix(base, ".") || strings.HasPrefix(base, "tsconfig") ||
				strings.HasPrefix(base, "postcss") || dirOf(f.Path) == dir && (f.Lang == "JSON" || f.Lang == "YAML" || f.Lang == "TOML") &&
				base != "package.json" && base != "package-lock.json" && base != "pnpm-lock.yaml" {
				config.Write(f.Src)
				config.WriteByte('\n')
			}
		}
		scripts := strings.Join(stringLeaves(p.raw["scripts"]), "\n")
		cfg := config.String()
		var used func(name string) bool
		used = func(name string) bool {
			if imported[name] || containsWord(cfg, name) || langs[implicitByLang[name]] {
				return true
			}
			last := name[strings.LastIndex(name, "/")+1:]
			if containsWord(scripts, name) || containsWord(scripts, last) ||
				slices.ContainsFunc(binAliases[name], func(b string) bool { return containsWord(scripts, b) }) {
				return true
			}
			if host, ok := peerOf[name]; ok && used(host) {
				return true
			}
			// .prettierrc without extension is not read by source.Walk; plugins are only loaded by prettier.
			if strings.HasPrefix(name, "prettier-plugin-") && used("prettier") {
				return true
			}
			if m := reESLintName.FindStringSubmatch(name); m != nil {
				short := strings.Trim(m[1]+"/"+m[2], "/")
				if short != "" && containsWord(cfg, short) {
					return true
				}
			}
			if t, ok := strings.CutPrefix(name, "@types/"); ok {
				if s, n, scoped := strings.Cut(t, "__"); scoped {
					t = "@" + s + "/" + n
				}
				return t == "node" || builtins[t] || used(t)
			}
			return false
		}
		for _, n := range p.deps {
			if used(n) {
				continue
			}
			if dir != "" {
				n = dir + ": " + n
			}
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// containsWord reports whether w appears in s not glued to other name characters.
func containsWord(s, w string) bool {
	isName := func(c byte) bool {
		return c == '_' || c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
	}
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(w)
		if (start == 0 || !isName(s[start-1])) && (end == len(s) || !isName(s[end])) {
			return true
		}
		i = start + 1
	}
}

func addSet(m map[string]map[string]bool, k, v string) {
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][v] = true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
