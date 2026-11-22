package scanners

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/url"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LockGraph is the dependency graph of a lockfile. Nodes are "name@version".
type LockGraph struct {
	Direct map[string]bool     // dependencies declared by the root or a workspace
	Deps   map[string][]string // node → the nodes it depends on
	Risks  map[string][]string // node → supply-chain signals read from the lockfile (see Risk*)
}

func newLockGraph() LockGraph {
	return LockGraph{Direct: map[string]bool{}, Deps: map[string][]string{}, Risks: map[string][]string{}}
}

// Supply-chain signals of a package, stored as "kind" or "kind:detail".
const (
	RiskInstallScript = "install-script" // runs code at install time
	RiskGit           = "git"            // "git:<url>": fetched from a git repository
	RiskHTTP          = "http"           // "http:<url>": tarball over plain http
	RiskFile          = "file"           // "file:<path>": local tarball or folder outside the workspaces
	RiskRegistry      = "registry"       // "registry:<host>": registry other than npm's
	RiskTyposquat     = "typosquat"      // "typosquat:<popular>": name close to a popular package
)

func (g LockGraph) addRisk(id, risk string) {
	if id != "" && risk != "" && !slices.Contains(g.Risks[id], risk) {
		g.Risks[id] = append(g.Risks[id], risk)
	}
}

// SourceRisk classifies where a package comes from: a resolved URL, a berry resolution or a pnpm
// tarball/repo. It returns "" for the public npm registry and for plain versions.
func SourceRisk(ref string) string {
	switch {
	case ref == "":
		return ""
	case strings.HasPrefix(ref, "git+"), strings.HasPrefix(ref, "git://"), strings.HasPrefix(ref, "git@"),
		strings.HasPrefix(ref, "github:"), strings.HasPrefix(ref, "gitlab:"), strings.HasPrefix(ref, "bitbucket:"),
		strings.Contains(ref, "#commit="), strings.Contains(ref, "codeload.github.com/"):
		return RiskGit + ":" + redactURL(ref)
	case strings.HasPrefix(ref, "file:"), strings.HasPrefix(ref, "link:"), strings.HasPrefix(ref, "portal:"):
		return RiskFile + ":" + ref[strings.IndexByte(ref, ':')+1:]
	case strings.HasPrefix(ref, "http://"):
		return RiskHTTP + ":" + redactURL(ref)
	case strings.HasPrefix(ref, "https://"):
		u, err := url.Parse(ref)
		if err != nil {
			return ""
		}
		switch h := u.Hostname(); h {
		case "registry.npmjs.org", "registry.yarnpkg.com":
			return ""
		default:
			return RiskRegistry + ":" + h
		}
	}
	return ""
}

// redactURL drops credentials, query and fragment: lockfiles may carry tokens in them.
func redactURL(ref string) string {
	if !strings.Contains(ref, "://") { // scp-like "git@host:repo" or "github:user/repo"
		if i := strings.IndexByte(ref, '@'); i >= 0 && strings.HasPrefix(ref, "git@") {
			return ref[i+1:]
		}
		return strings.SplitN(ref, "#", 2)[0]
	}
	u, err := url.Parse(ref)
	if err != nil { // "git+ssh://git@host:repo": keep what follows the credentials
		ref, _, _ = strings.Cut(ref, "#")
		ref, _, _ = strings.Cut(ref, "?")
		return ref[strings.LastIndexByte(ref, '@')+1:]
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

func (g LockGraph) addDirect(id string) { g.Direct[id] = true }

func (g LockGraph) addEdge(from, to string) {
	if from != to {
		g.Deps[from] = append(g.Deps[from], to)
	}
}

// Via returns, for each package reached through another one, the sorted names of the
// direct dependencies that pull it in: "who brought this transitive package here".
func (g LockGraph) Via() map[string][]string {
	via := map[string]map[string]bool{}
	for d := range g.Direct {
		name := lockIDName(d)
		seen := map[string]bool{d: true}
		queue := append([]string{}, g.Deps[d]...)
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			if seen[n] {
				continue
			}
			seen[n] = true
			if via[n] == nil {
				via[n] = map[string]bool{}
			}
			via[n][name] = true
			queue = append(queue, g.Deps[n]...)
		}
	}
	out := make(map[string][]string, len(via))
	for n, names := range via {
		list := make([]string, 0, len(names))
		for name := range names {
			list = append(list, name)
		}
		sort.Strings(list)
		out[n] = list
	}
	return out
}

// Packages returns every "name@version" of the graph, sorted.
func (g LockGraph) Packages() []string {
	seen := map[string]bool{}
	for d := range g.Direct {
		seen[d] = true
	}
	for from, tos := range g.Deps {
		seen[from] = true
		for _, to := range tos {
			seen[to] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// SplitLockID splits "name@version", scoped names included.
func SplitLockID(id string) (name, version string) {
	name = lockIDName(id)
	return name, strings.TrimPrefix(id[len(name):], "@")
}

// lockIDName returns "name" of "name@version", scoped names included. The version may hold
// "@" itself: "a@git+ssh://git@github.com/…".
func lockIDName(id string) string {
	if i := strings.IndexByte(id[min(1, len(id)):], '@'); i >= 0 {
		return id[:i+1]
	}
	return id
}

// stripPeers drops pnpm's peer suffix: "4.0.1(svelte@5.0.0)" → "4.0.1".
func stripPeers(v string) string {
	if i := strings.IndexByte(v, '('); i >= 0 {
		return v[:i]
	}
	return v
}

type pnpmDep struct {
	Version string `yaml:"version"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmDep `yaml:"dependencies"`
	DevDependencies      map[string]pnpmDep `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmDep `yaml:"optionalDependencies"`
}

type pnpmSnapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
	// Only on "packages" entries. pnpm writes no tarball for its configured registry, so a custom
	// registry set in .npmrc goes unseen.
	Resolution struct {
		Tarball, Repo, Type, Directory string
	} `yaml:"resolution"`
	// shortcut: pnpm 9 lockfiles dropped requiresBuild, so install scripts are seen in v6 lockfiles only;
	// read the registry's hasInstallScript if users ask.
	RequiresBuild bool   `yaml:"requiresBuild"`
	Name          string `yaml:"name"` // v6 keys of git and file packages lack the name: "file:x.tgz"
}

type pnpmDoc struct {
	Importers map[string]pnpmImporter `yaml:"importers"`
	Packages  map[string]pnpmSnapshot `yaml:"packages"`  // v6: dependencies live here, keys start with "/"
	Snapshots map[string]pnpmSnapshot `yaml:"snapshots"` // v9
}

// PnpmLockGraph builds the graph of a pnpm-lock.yaml (v6 to v9). The file may hold several
// YAML documents (pnpm's own env lockfile first): every document is read.
// shortcut: v5 lockfiles ("/name/version" keys) yield an empty graph, rare since pnpm 8; support them if asked.
func PnpmLockGraph(lock []byte) (LockGraph, error) {
	g := newLockGraph()
	dec := yaml.NewDecoder(bytes.NewReader(lock))
	for {
		var doc pnpmDoc
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return g, err
		}
		snaps := doc.Snapshots
		if snaps == nil {
			snaps = map[string]pnpmSnapshot{}
			for k, p := range doc.Packages {
				snaps[strings.TrimPrefix(k, "/")] = p
			}
		}
		// key is the snapshot key of a dependency; "" for workspace links.
		key := func(name, version string) string {
			if strings.HasPrefix(version, "link:") || version == "" {
				return ""
			}
			// alias: "string-width@4.2.3"; URLs hold "@" too: "git+ssh://git@…"
			if v := stripPeers(version); strings.Contains(v, "@") && !strings.Contains(v, ":") {
				return version
			}
			return name + "@" + version
		}
		for k, p := range doc.Packages {
			id := stripPeers(strings.TrimPrefix(k, "/"))
			if doc.Snapshots == nil && !strings.HasPrefix(k, "/") && p.Name != "" {
				id = p.Name + "@" + id // matches key(name, version): v6 importers use the bare key as version
			}
			if p.RequiresBuild {
				g.addRisk(id, RiskInstallScript)
			}
			switch r := p.Resolution; {
			case r.Type == "git":
				g.addRisk(id, RiskGit+":"+redactURL(r.Repo))
			case r.Type == "directory":
				g.addRisk(id, RiskFile+":"+r.Directory)
			default:
				g.addRisk(id, SourceRisk(r.Tarball))
			}
		}
		for _, imp := range doc.Importers {
			for _, deps := range []map[string]pnpmDep{imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies} {
				for name, d := range deps {
					if k := key(name, d.Version); k != "" {
						g.addDirect(stripPeers(k))
					}
				}
			}
		}
		for k, s := range snaps {
			from := stripPeers(k)
			for _, deps := range []map[string]string{s.Dependencies, s.OptionalDependencies} {
				for name, v := range deps {
					if to := key(name, v); to != "" {
						g.addEdge(from, stripPeers(to))
					}
				}
			}
		}
	}
	return g, nil
}

// YarnLockGraph builds the graph of a yarn.lock, classic (v1) or berry. Classic lockfiles
// do not list the project's own dependencies: they come from the manifests.
func YarnLockGraph(lock []byte, manifests ...Manifest) (LockGraph, error) {
	if bytes.Contains(lock, []byte("__metadata:")) {
		return yarnBerryGraph(lock)
	}
	g := newLockGraph()
	entries := parseYarnV1(lock)
	for _, m := range manifests {
		for _, deps := range []map[string]string{m.Dependencies, m.DevDependencies, m.OptionalDependencies} {
			for name, rng := range deps {
				if e, ok := entries[name+"@"+rng]; ok {
					g.addDirect(e.id)
				}
			}
		}
	}
	// shortcut: yarn.lock never says which packages have install scripts; read the registry's
	// hasInstallScript if users ask.
	for _, e := range entries {
		g.addRisk(e.id, SourceRisk(e.resolved))
		for name, rng := range e.deps {
			if to, ok := entries[name+"@"+rng]; ok {
				g.addEdge(e.id, to.id)
			}
		}
	}
	dedupEdges(g)
	return g, nil
}

type yarnEntry struct {
	id       string
	resolved string
	deps     map[string]string
}

// parseYarnV1 maps each descriptor ("name@range") to its resolved entry.
func parseYarnV1(lock []byte) map[string]*yarnEntry {
	out := map[string]*yarnEntry{}
	var cur *yarnEntry
	var descs []string
	inDeps := false
	sc := bufio.NewScanner(bytes.NewReader(lock))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 0 && strings.HasSuffix(trimmed, ":"):
			cur, inDeps = &yarnEntry{deps: map[string]string{}}, false
			descs = descs[:0]
			for _, d := range strings.Split(strings.TrimSuffix(trimmed, ":"), ",") {
				d = strings.Trim(strings.TrimSpace(d), `"`)
				descs = append(descs, d)
				out[d] = cur
			}
		case cur == nil:
		case indent == 2:
			inDeps = trimmed == "dependencies:" || trimmed == "optionalDependencies:"
			if v, ok := strings.CutPrefix(trimmed, "version "); ok && len(descs) > 0 {
				cur.id = lockIDName(descs[0]) + "@" + strings.Trim(v, `"`)
			}
			if v, ok := strings.CutPrefix(trimmed, "resolved "); ok {
				cur.resolved = strings.Trim(v, `"`)
			}
		case indent == 4 && inDeps:
			name, rng, ok := splitYarnPair(trimmed)
			if ok {
				cur.deps[name] = rng
			}
		}
	}
	for k, e := range out {
		if e.id == "" {
			delete(out, k)
		}
	}
	return out
}

// splitYarnPair splits `"@scope/a" "^1.0.0"` or `a ^1.0.0`.
func splitYarnPair(s string) (string, string, bool) {
	var name string
	if strings.HasPrefix(s, `"`) {
		end := strings.Index(s[1:], `"`)
		if end < 0 {
			return "", "", false
		}
		name, s = s[1:end+1], s[end+2:]
	} else {
		i := strings.IndexByte(s, ' ')
		if i < 0 {
			return "", "", false
		}
		name, s = s[:i], s[i:]
	}
	return name, strings.Trim(strings.TrimSpace(s), `"`), true
}

type berryEntry struct {
	Version              string            `yaml:"version"`
	Resolution           string            `yaml:"resolution"` // "name@npm:1.0.0", "name@https://…#commit=…"
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

func yarnBerryGraph(lock []byte) (LockGraph, error) {
	g := newLockGraph()
	var raw map[string]berryEntry
	if err := yaml.Unmarshal(lock, &raw); err != nil {
		return g, err
	}
	byDesc := map[string]string{} // descriptor → node
	workspaces := map[string]berryEntry{}
	for keys, e := range raw {
		if keys == "__metadata" {
			continue
		}
		for _, d := range strings.Split(keys, ",") {
			d = strings.TrimSpace(d)
			if strings.Contains(d, "@workspace:") {
				workspaces[d] = e
				continue
			}
			byDesc[d] = lockIDName(d) + "@" + e.Version
		}
	}
	// berry writes "name@npm:^1.0.0" keys; dependency values are "npm:^1.0.0" or a bare range.
	lookup := func(name, rng string) (string, bool) {
		if id, ok := byDesc[name+"@"+rng]; ok {
			return id, true
		}
		id, ok := byDesc[name+"@npm:"+rng]
		return id, ok
	}
	for _, e := range workspaces {
		for _, deps := range []map[string]string{e.Dependencies, e.OptionalDependencies} {
			for name, rng := range deps {
				if id, ok := lookup(name, rng); ok {
					g.addDirect(id)
				}
			}
		}
	}
	for keys, e := range raw {
		if keys == "__metadata" || strings.Contains(keys, "@workspace:") {
			continue
		}
		from := lockIDName(strings.TrimSpace(strings.Split(keys, ",")[0])) + "@" + e.Version
		// shortcut: berry writes "npm:" whatever the registry, so a custom one set in .yarnrc.yml goes unseen.
		if i := strings.IndexByte(e.Resolution[min(1, len(e.Resolution)):], '@'); i >= 0 {
			ref, _, _ := strings.Cut(e.Resolution[i+2:], "::") // drop "::locator=…"
			g.addRisk(from, SourceRisk(ref))
		}
		for _, deps := range []map[string]string{e.Dependencies, e.OptionalDependencies} {
			for name, rng := range deps {
				if to, ok := lookup(name, rng); ok {
					g.addEdge(from, to)
				}
			}
		}
	}
	dedupEdges(g)
	return g, nil
}

// dedupEdges removes the duplicate edges left by entries shared by several descriptors.
func dedupEdges(g LockGraph) {
	for k, list := range g.Deps {
		sort.Strings(list)
		g.Deps[k] = compact(list)
	}
}

func compact(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}
