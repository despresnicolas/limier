package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// npmAbbrevDoc is the part of the abbreviated npm document
// (Accept: application/vnd.npm.install-v1+json) that ParentBump needs.
type npmAbbrevDoc struct {
	Versions map[string]struct {
		Dependencies         map[string]string `json:"dependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		Deprecated           json.RawMessage   `json:"deprecated"`
	} `json:"versions"`
}

func (c *Client) npmAbbrev(ctx context.Context, name string) (npmAbbrevDoc, error) {
	var doc npmAbbrevDoc
	hdr := http.Header{"Accept": {"application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8"}}
	raw, err := c.getBytes(ctx, "GET", c.ep.NPM+"/"+npmEscape(name), nil, hdr, maxBodySize)
	if err != nil {
		return doc, err
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return doc, fmt.Errorf("vulndb: npm %s: decode: %w", name, err)
	}
	return doc, nil
}

// ParentBump returns the smallest version of parent, above parentFrom, whose dependency tree brings
// child at fixed or above. ok is false when no published version does.
//
// A parent version qualifies when it no longer depends on child, or when every published stable
// child version its range allows is >= fixed. Requiring the lowest match (not only the highest,
// which a fresh resolve installs) makes sure a child version already locked in package-lock.json
// cannot stay in place after `npm install` re-resolves the bumped parent. Prerelease and
// deprecated parent versions are skipped, as are ranges that are not semver (tags, URLs, aliases).
//
// shortcut: only looks at child as a DIRECT dependency of parent (depth 2), deeper chains fall
// back to overrides; walk the tree with more registry documents if overrides prove too noisy.
func (c *Client) ParentBump(ctx context.Context, parent, parentFrom, child, fixed string) (string, bool, error) {
	from, err := semver.NewVersion(strings.TrimSpace(parentFrom))
	if err != nil {
		return "", false, fmt.Errorf("vulndb: parent bump: version %q: %w", parentFrom, err)
	}
	fix, err := semver.NewVersion(strings.TrimSpace(fixed))
	if err != nil {
		return "", false, fmt.Errorf("vulndb: parent bump: fixed %q: %w", fixed, err)
	}
	pdoc, err := c.npmAbbrev(ctx, strings.TrimSpace(parent))
	if err != nil {
		return "", false, err
	}
	cdoc, err := c.npmAbbrev(ctx, strings.TrimSpace(child))
	if err != nil {
		return "", false, err
	}

	childVers := stableSorted(cdoc)
	for _, pv := range stableSorted(pdoc) {
		if !pv.GreaterThan(from) {
			continue
		}
		m := pdoc.Versions[pv.Original()]
		if isDeprecated(m.Deprecated) {
			continue
		}
		rng, deps := m.Dependencies[child], true
		if _, ok := m.Dependencies[child]; !ok {
			rng, deps = m.OptionalDependencies[child]
		}
		if !deps {
			return pv.Original(), true, nil
		}
		con, err := semver.NewConstraint(strings.TrimSpace(rng))
		if err != nil {
			continue // dist-tag, URL, git or npm: alias
		}
		for _, cv := range childVers {
			if con.Check(cv) {
				if !cv.LessThan(fix) {
					return pv.Original(), true, nil
				}
				break // lowest match is still vulnerable
			}
		}
	}
	return "", false, nil
}

// stableSorted returns the document's non-prerelease versions in ascending order.
func stableSorted(doc npmAbbrevDoc) []*semver.Version {
	out := make([]*semver.Version, 0, len(doc.Versions))
	for v := range doc.Versions {
		sv, err := semver.StrictNewVersion(v)
		if err == nil && sv.Prerelease() == "" {
			out = append(out, sv)
		}
	}
	sort.Sort(semver.Collection(out))
	return out
}

func isDeprecated(raw json.RawMessage) bool {
	var msg string
	return len(raw) > 0 && json.Unmarshal(raw, &msg) == nil && msg != ""
}
