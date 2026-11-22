package scanners

import (
	"sort"
	"strings"
)

// Manifest is the subset of package.json we use.
type Manifest struct {
	Name                 string
	Dependencies         map[string]string
	DevDependencies      map[string]string
	OptionalDependencies map[string]string
	PeerDependencies     map[string]string
	Workspaces           []string
	Overrides            map[string]any // npm
	PnpmOverrides        map[string]any // pnpm.overrides
	Resolutions          map[string]any // yarn
	PackageManager       string
}

// ParseManifest parses a package.json. "workspaces" may be an array or
// {"packages": [...]}.
func ParseManifest(data []byte) (Manifest, error) {
	v, err := decode(data)
	if err != nil {
		return Manifest{}, err
	}
	ws := get(v, "workspaces")
	if _, ok := ws.(map[string]any); ok {
		ws = get(ws, "packages")
	}
	return Manifest{
		Name:                 asStr(get(v, "name")),
		Dependencies:         asStrMap(get(v, "dependencies")),
		DevDependencies:      asStrMap(get(v, "devDependencies")),
		OptionalDependencies: asStrMap(get(v, "optionalDependencies")),
		PeerDependencies:     asStrMap(get(v, "peerDependencies")),
		Workspaces:           asStrs(ws),
		Overrides:            asObj(get(v, "overrides")),
		PnpmOverrides:        asObj(get(v, "pnpm", "overrides")),
		Resolutions:          asObj(get(v, "resolutions")),
		PackageManager:       asStr(get(v, "packageManager")),
	}, nil
}

// DirectDeps merges manifests into name -> isDev. A dependency is dev only
// if it is dev-only in every manifest where it appears.
func DirectDeps(manifests ...Manifest) map[string]bool {
	out := map[string]bool{}
	for _, m := range manifests {
		prod := map[string]bool{}
		for _, deps := range []map[string]string{m.Dependencies, m.OptionalDependencies, m.PeerDependencies} {
			for name := range deps {
				prod[name] = true
			}
		}
		for name := range prod {
			out[name] = false
		}
		for name := range m.DevDependencies {
			if prod[name] {
				continue
			}
			if _, seen := out[name]; !seen {
				out[name] = true
			}
		}
	}
	return out
}

type lockEntry struct {
	name     string
	version  string
	link     bool
	resolved string
	install  bool // hasInstallScript
	deps     []string
}

// npmLock is a parsed package-lock.json (v2/v3): entries by "packages" key, and the
// root and workspace folders (keys without node_modules/).
type npmLock struct {
	entries map[string]lockEntry
	roots   []string
}

func parseNpmLock(lock []byte) (*npmLock, error) {
	v, err := decode(lock)
	if err != nil {
		return nil, err
	}
	l := &npmLock{entries: map[string]lockEntry{}}
	for key, raw := range asObj(get(v, "packages")) {
		e := lockEntry{
			name:     asStr(get(raw, "name")),
			version:  asStr(get(raw, "version")),
			link:     asBool(get(raw, "link")),
			resolved: asStr(get(raw, "resolved")),
			install:  asBool(get(raw, "hasInstallScript")),
		}
		if e.name == "" {
			e.name = lockKeyName(key)
		}
		fields := []string{"dependencies", "optionalDependencies", "peerDependencies"}
		if !strings.Contains(key, "node_modules/") { // root or workspace folder
			fields = append(fields, "devDependencies")
			l.roots = append(l.roots, key)
		}
		for _, f := range fields {
			for dep := range asObj(get(raw, f)) {
				e.deps = append(e.deps, dep)
			}
		}
		sort.Strings(e.deps) // deterministic tie-breaking
		l.entries[key] = e
	}
	if get(v, "packages") == nil {
		l.addV1(asObj(get(v, "dependencies")))
	}
	sort.Strings(l.roots)
	return l, nil
}

// addV1 maps a v1 lockfile (nested "dependencies" with "requires") onto v2 "packages" keys.
// shortcut: v1 does not list the root's own dependencies, so top-level packages nobody requires
// stand in for them; Via may name the wrong direct dependency for a package that is both, fine for npm ≤ 6 lockfiles.
func (l *npmLock) addV1(deps map[string]any) {
	required := map[string]bool{}
	var walk func(prefix string, deps map[string]any)
	walk = func(prefix string, deps map[string]any) {
		for name, raw := range deps {
			key := prefix + "node_modules/" + name
			// shortcut: v1 has no hasInstallScript, so install scripts go unseen; fine for npm ≤ 6 lockfiles.
			e := lockEntry{name: name, version: asStr(get(raw, "version")), resolved: asStr(get(raw, "resolved"))}
			for dep := range asObj(get(raw, "requires")) {
				e.deps = append(e.deps, dep)
				required[dep] = true
			}
			sort.Strings(e.deps)
			l.entries[key] = e
			walk(key+"/", asObj(get(raw, "dependencies")))
		}
	}
	walk("", deps)
	root := lockEntry{}
	for name := range deps {
		if !required[name] {
			root.deps = append(root.deps, name)
		}
	}
	sort.Strings(root.deps)
	l.entries[""] = root
	l.roots = append(l.roots, "")
}

// follow resolves symlinked workspace entries to their target folder.
func (l *npmLock) follow(key string) string {
	if e := l.entries[key]; e.link && e.resolved != "" {
		if _, ok := l.entries[e.resolved]; ok {
			return e.resolved
		}
	}
	return key
}

// resolve applies Node's lookup: from/node_modules/dep, then each parent.
func (l *npmLock) resolve(from, dep string) (string, bool) {
	base := from
	for {
		cand := "node_modules/" + dep
		if base != "" {
			cand = base + "/" + cand
		}
		if _, ok := l.entries[cand]; ok {
			return cand, true
		}
		if base == "" {
			return "", false
		}
		if i := strings.LastIndex(base, "node_modules/"); i > 0 {
			base = strings.TrimSuffix(base[:i], "/")
		} else {
			base = ""
		}
	}
}

// id is "name@version" of an installed package, "" for project folders and workspace links.
func (l *npmLock) id(key string) string {
	if !strings.Contains(key, "node_modules/") || l.follow(key) != key {
		return ""
	}
	e := l.entries[key]
	if e.name == "" || e.version == "" {
		return ""
	}
	return e.name + "@" + e.version
}

// NpmLockPaths parses a package-lock.json (v1 to v3) and returns, for each
// "name@version", the shortest chain of package names from a direct
// dependency (of the root or of a workspace) to it. v1 lockfiles yield an
// approximate map (see addV1).
func NpmLockPaths(lock []byte) (map[string][]string, error) {
	l, err := parseNpmLock(lock)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	type item struct {
		key  string
		path []string
	}
	var queue []item
	for _, r := range l.roots {
		for _, dep := range l.entries[r].deps {
			if key, ok := l.resolve(r, dep); ok {
				queue = append(queue, item{key, []string{dep}})
			}
		}
	}
	visited := map[string]bool{}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		key := l.follow(it.key)
		if visited[key] {
			continue
		}
		visited[key] = true
		e := l.entries[key]
		if id := e.name + "@" + e.version; e.name != "" && e.version != "" {
			if _, ok := out[id]; !ok {
				out[id] = it.path
			}
		}
		for _, dep := range e.deps {
			if next, ok := l.resolve(key, dep); ok && !visited[l.follow(next)] {
				path := append(append([]string{}, it.path...), dep)
				queue = append(queue, item{next, path})
			}
		}
	}
	return out, nil
}

// NpmLockGraph builds the dependency graph of a package-lock.json (v1 to v3).
func NpmLockGraph(lock []byte) (LockGraph, error) {
	l, err := parseNpmLock(lock)
	if err != nil {
		return LockGraph{}, err
	}
	g := newLockGraph()
	for _, r := range l.roots {
		for _, dep := range l.entries[r].deps {
			if key, ok := l.resolve(r, dep); ok {
				if id := l.id(key); id != "" {
					g.addDirect(id)
				}
			}
		}
	}
	for key := range l.entries {
		from := l.id(key)
		if from == "" {
			continue
		}
		// Links never get here (id is ""): workspace and file: folders are project code, not packages.
		if e := l.entries[key]; e.install {
			g.addRisk(from, RiskInstallScript)
		}
		g.addRisk(from, SourceRisk(l.entries[key].resolved))
		for _, dep := range l.entries[key].deps {
			if next, ok := l.resolve(key, dep); ok {
				if to := l.id(next); to != "" {
					g.addEdge(from, to)
				}
			}
		}
	}
	return g, nil
}

// lockKeyName extracts the package name from a "packages" key such as
// "node_modules/a/node_modules/@scope/b".
func lockKeyName(key string) string {
	i := strings.LastIndex(key, "node_modules/")
	if i < 0 {
		return ""
	}
	return key[i+len("node_modules/"):]
}
