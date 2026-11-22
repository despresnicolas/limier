// Package fixbot patches package.json for local fixes: version bumps of direct dependencies and
// overrides of transitive ones (F4).
package fixbot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// SetDependency moves a direct dependency to version in package.json, keeping its range
// operator ("^", "~", ">=", "=" or none) and the key order. Every dependency field that lists
// pkg is updated. Ranges that are not a plain version (git, file:, workspace:, 1.x...) are refused.
func SetDependency(manifest []byte, pkg, version string) ([]byte, error) {
	root, err := parseObject(manifest)
	if err != nil {
		return nil, fmt.Errorf("package.json: %w", err)
	}
	found := false
	for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		raw, ok := root.vals[field].(json.RawMessage)
		if !ok {
			continue
		}
		deps, err := parseObject(raw)
		if err != nil {
			continue
		}
		current, ok := deps.vals[pkg].(json.RawMessage)
		if !ok {
			continue
		}
		var spec string
		if err := json.Unmarshal(current, &spec); err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		m := plainRange.FindStringSubmatch(strings.TrimSpace(spec))
		if m == nil {
			return nil, fmt.Errorf("%s: unsupported version range %q for %s", field, spec, pkg)
		}
		deps.set(pkg, m[1]+version)
		root.vals[field] = deps
		found = true
	}
	if !found {
		return nil, fmt.Errorf("%s is not a direct dependency in package.json", pkg)
	}
	return encode(root, detectIndent(manifest))
}

// SetOverride pins a transitive package at version in the root package.json: "overrides" for npm,
// "pnpm.overrides" for pnpm, "resolutions" for yarn. An existing plain entry for pkg is raised
// (keeping its range operator) only when lower; any other existing value is refused.
// shortcut: only the bare "pkg" key is read, not scoped keys ("**/pkg", "pkg@<1.2", "parent>pkg")
// nor pnpm-workspace.yaml overrides; parse them if users report duplicate entries.
func SetOverride(manifest []byte, packageManager, pkg, version string) ([]byte, error) {
	root, err := parseObject(manifest)
	if err != nil {
		return nil, fmt.Errorf("package.json: %w", err)
	}
	var field string
	var overrides *object
	switch packageManager {
	case "pnpm":
		field, overrides = "pnpm.overrides", root.object("pnpm").object("overrides")
	case "yarn":
		field, overrides = "resolutions", root.object("resolutions")
	default:
		field, overrides = "overrides", root.object("overrides")
	}
	spec := version
	if current, ok := overrides.vals[pkg].(json.RawMessage); ok {
		var s string
		if err := json.Unmarshal(current, &s); err != nil {
			return nil, fmt.Errorf("%s: unsupported override for %s: %s", field, pkg, current)
		}
		m := plainRange.FindStringSubmatch(strings.TrimSpace(s))
		if m == nil {
			return nil, fmt.Errorf("%s: unsupported override %q for %s", field, s, pkg)
		}
		have, err1 := semver.NewVersion(strings.TrimLeft(strings.TrimSpace(s), "^~>=v"))
		want, err2 := semver.NewVersion(version)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%s: cannot compare %q with %s for %s", field, s, version, pkg)
		}
		if !have.LessThan(want) {
			return manifest, nil
		}
		spec = m[1] + version
	}
	overrides.set(pkg, spec)
	return encode(root, detectIndent(manifest))
}

// encode writes package.json with a final newline, without escaping <, > and & (">=18" stays readable).
func encode(root *object, indent string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var plainRange = regexp.MustCompile(`^(\^|~|>=|=)?v?\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.+-]*)?$`)

// DefaultBranchPrefix is the first segment of fix branches when the project sets none.
const DefaultBranchPrefix = "fix"

// branchPrefix allows slash-separated segments of letters, digits, '.', '_' and '-', never
// starting with '-' or '.', so the prefix is a valid git ref part and never read as an option.
var branchPrefix = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*$`)

// ValidBranchPrefix checks a user-chosen prefix such as "fix" or "deps/limier".
func ValidBranchPrefix(p string) error {
	if len(p) > 50 || !branchPrefix.MatchString(p) || strings.Contains(p, "..") || strings.HasSuffix(p, ".lock") || strings.HasSuffix(p, ".") {
		return fmt.Errorf("invalid branch prefix %q: use letters, digits, '.', '_', '-' and '/' (50 max)", p)
	}
	return nil
}

// BumpBranchName is the branch of a version bump; dir separates workspaces of a monorepo.
// An invalid prefix falls back to DefaultBranchPrefix.
func BumpBranchName(prefix, dir, pkg, version string) string {
	if ValidBranchPrefix(prefix) != nil {
		prefix = DefaultBranchPrefix
	}
	name := prefix + "/bump-"
	if dir != "" {
		name += slug(dir) + "-"
	}
	return name + slug(pkg) + "-" + slug(version)
}

// OverrideBranchName is the branch of an override; overrides only live in the root package.json.
func OverrideBranchName(prefix, pkg, version string) string {
	if ValidBranchPrefix(prefix) != nil {
		prefix = DefaultBranchPrefix
	}
	return prefix + "/override-" + slug(pkg) + "-" + slug(version)
}

// GroupBranchName is the branch holding all low-risk bumps (no semver boundary crossed) of a project.
func GroupBranchName(prefix string) string {
	if ValidBranchPrefix(prefix) != nil {
		prefix = DefaultBranchPrefix
	}
	return prefix + "/bump-minor-patch"
}

// InstallCommand is what the user runs on a fix branch: Limier only edits package.json, not the lockfile.
func InstallCommand(packageManager string) string {
	switch packageManager {
	case "pnpm":
		return "pnpm install"
	case "yarn":
		return "yarn"
	}
	return "npm install"
}

var nonSlug = regexp.MustCompile(`[^a-z0-9.-]+`)

func slug(s string) string {
	return strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

var indentRe = regexp.MustCompile(`\n([ \t]+)"`)

func detectIndent(b []byte) string {
	if m := indentRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return "  "
}

// object is a JSON object preserving key order.
type object struct {
	keys []string
	vals map[string]any // json.RawMessage or *object
}

func parseObject(b []byte) (*object, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected a JSON object")
	}
	o := &object{vals: map[string]any{}}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		if _, dup := o.vals[key]; !dup {
			o.keys = append(o.keys, key)
		}
		o.vals[key] = raw
	}
	return o, nil
}

// object returns the child object at key, creating it (appended last) if missing.
func (o *object) object(key string) *object {
	switch v := o.vals[key].(type) {
	case *object:
		return v
	case json.RawMessage:
		if child, err := parseObject(v); err == nil {
			o.vals[key] = child
			return child
		}
	}
	child := &object{vals: map[string]any{}}
	o.set(key, child)
	return child
}

func (o *object) set(key string, v any) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

func (o *object) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := marshal(k)
		if err != nil {
			return nil, err
		}
		vb, err := marshal(o.vals[k])
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// marshal is json.Marshal without escaping <, > and & (keys such as "ws@<8" stay readable).
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
