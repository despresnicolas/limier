package scanners

import (
	"encoding/json"
	"sort"
	"strings"
)

// NpmPurl returns the package URL of an npm package: "@scope/a" → "pkg:npm/%40scope/a@1.0.0".
func NpmPurl(name, version string) string {
	return "pkg:npm/" + strings.Replace(name, "@", "%40", 1) + "@" + version
}

// BuildCycloneDX writes a CycloneDX 1.5 JSON SBOM of a lockfile graph (SPECS F2.2).
func BuildCycloneDX(g LockGraph) ([]byte, error) {
	type component struct {
		Type    string `json:"type"`
		BOMRef  string `json:"bom-ref"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	}
	type dependency struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn,omitempty"`
	}
	doc := struct {
		BOMFormat    string       `json:"bomFormat"`
		SpecVersion  string       `json:"specVersion"`
		Version      int          `json:"version"`
		Components   []component  `json:"components"`
		Dependencies []dependency `json:"dependencies"`
	}{BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1, Components: []component{}, Dependencies: []dependency{}}
	for _, id := range g.Packages() {
		name, version := SplitLockID(id)
		purl := NpmPurl(name, version)
		doc.Components = append(doc.Components, component{Type: "library", BOMRef: purl, Name: name, Version: version, Purl: purl})
		var on []string
		for _, to := range g.Deps[id] {
			on = append(on, NpmPurl(SplitLockID(to)))
		}
		sort.Strings(on)
		doc.Dependencies = append(doc.Dependencies, dependency{Ref: purl, DependsOn: compact(on)})
	}
	return json.Marshal(doc)
}
