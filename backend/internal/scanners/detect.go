package scanners

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workspace is a sub-package of a monorepo.
type Workspace struct {
	Dir  string // relative to repository root
	Name string // "name" of its package.json (may be "")
}

// Detection is the result of inspecting a repository for Node.js tooling.
type Detection struct {
	NodeProject    bool
	IgnoreReason   string // why NodeProject is false, e.g. "no package.json at repository root"
	PackageManager string // "npm" | "pnpm" | "yarn"
	Lockfile       string // root lockfile path, "" when none
	Workspaces     []Workspace
}

// Reasons why a folder is not a Node.js project.
const (
	ReasonNoPackageJSON      = "no package.json at repository root"
	ReasonInvalidPackageJSON = "invalid package.json at repository root"
)

type packageJSON struct {
	Name           string          `json:"name"`
	PackageManager string          `json:"packageManager"`
	Workspaces     json.RawMessage `json:"workspaces"`
}

// workspacePatterns extracts globs from "workspaces": either an array or
// an object {"packages": [...]} (yarn classic).
func (p packageJSON) workspacePatterns() []string {
	if len(p.Workspaces) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(p.Workspaces, &arr); err == nil {
		return arr
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(p.Workspaces, &obj); err == nil {
		return obj.Packages
	}
	return nil
}

// DetectFromFiles inspects a repository for Node.js tooling. tree holds the file paths
// (relative, "/" separated); read returns a file's content, or an fs.ErrNotExist error.
func DetectFromFiles(tree []string, read func(path string) ([]byte, error)) (Detection, error) {
	files := make(map[string]bool, len(tree))
	for _, p := range tree {
		files[strings.TrimPrefix(p, "./")] = true
	}
	var d Detection

	if !files["package.json"] {
		d.IgnoreReason = ReasonNoPackageJSON
		return d, nil
	}
	raw, err := read("package.json")
	if err != nil {
		return Detection{}, fmt.Errorf("detect: read package.json: %w", err)
	}
	var root packageJSON
	if err := json.Unmarshal(raw, &root); err != nil {
		d.IgnoreReason = ReasonInvalidPackageJSON + ": " + err.Error()
		return d, nil
	}
	d.NodeProject = true
	d.PackageManager, d.Lockfile = detectPackageManager(files, root.PackageManager)

	patterns := root.workspacePatterns()
	if files["pnpm-workspace.yaml"] {
		raw, err := read("pnpm-workspace.yaml")
		if err != nil {
			return Detection{}, fmt.Errorf("detect: read pnpm-workspace.yaml: %w", err)
		}
		var ws struct {
			Packages []string `yaml:"packages"`
		}
		if err := yaml.Unmarshal(raw, &ws); err == nil {
			patterns = append(patterns, ws.Packages...)
		}
	}
	if len(patterns) == 0 {
		return d, nil
	}

	for _, dir := range matchWorkspaceDirs(tree, patterns) {
		w := Workspace{Dir: dir}
		if raw, err := read(dir + "/package.json"); err == nil {
			var pj packageJSON
			if json.Unmarshal(raw, &pj) == nil {
				w.Name = pj.Name
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return Detection{}, fmt.Errorf("detect: read %s/package.json: %w", dir, err)
		}
		d.Workspaces = append(d.Workspaces, w)
	}
	return d, nil
}

// detectPackageManager picks the package manager from root lockfiles
// (pnpm > yarn > npm), then from the "packageManager" field, defaulting to npm.
func detectPackageManager(files map[string]bool, field string) (pm, lockfile string) {
	for _, c := range []struct{ file, pm string }{
		{"pnpm-lock.yaml", "pnpm"},
		{"yarn.lock", "yarn"},
		{"package-lock.json", "npm"},
		{"npm-shrinkwrap.json", "npm"},
	} {
		if files[c.file] {
			return c.pm, c.file
		}
	}
	name, _, _ := strings.Cut(strings.TrimSpace(field), "@")
	switch name {
	case "pnpm", "yarn", "npm":
		return name, ""
	}
	return "npm", ""
}

func inNodeModules(p string) bool {
	return p == "node_modules" || strings.HasPrefix(p, "node_modules/") || strings.Contains(p, "/node_modules/")
}

// matchWorkspaceDirs expands workspace globs against the directories
// containing a package.json (root excluded). Patterns starting with "!" exclude.
func matchWorkspaceDirs(tree []string, patterns []string) []string {
	var include, exclude [][]string
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		p = normalizePattern(strings.TrimPrefix(p, "!"))
		if p == "" {
			continue
		}
		segs := strings.Split(p, "/")
		if neg {
			exclude = append(exclude, segs)
		} else {
			include = append(include, segs)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range tree {
		if path.Base(p) != "package.json" || inNodeModules(p) {
			continue
		}
		dir := path.Dir(p)
		if dir == "." || seen[dir] {
			continue
		}
		segs := strings.Split(dir, "/")
		if !matchAny(include, segs) || matchAny(exclude, segs) {
			continue
		}
		seen[dir] = true
		out = append(out, dir)
	}
	sort.Strings(out)
	return out
}

func normalizePattern(p string) string {
	p = strings.TrimSpace(p)
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	p = strings.TrimSuffix(p, "/package.json")
	return strings.Trim(p, "/")
}

func matchAny(patterns [][]string, segs []string) bool {
	for _, pat := range patterns {
		if matchSegments(pat, segs) {
			return true
		}
	}
	return false
}

// matchSegments matches path segments against a glob split on "/", where
// "**" matches zero or more segments and other segments use path.Match.
func matchSegments(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if matchSegments(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	if ok, err := path.Match(pat[0], segs[0]); err != nil || !ok {
		return false
	}
	return matchSegments(pat[1:], segs[1:])
}
