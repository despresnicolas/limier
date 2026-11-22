package app

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"limier/internal/db/dbq"
)

// PackageQuery is a parsed "Where is this package?" search: a name, then an optional exact version or semver range.
type PackageQuery struct {
	Name    string
	Version string              // exact version, or ""
	Range   *semver.Constraints // semver range, or nil
}

const maxPackageQuery = 256

// Characters of an npm name, in any case: the name part of a search is used as an ILIKE pattern.
var packageNameRe = regexp.MustCompile(`^@?[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]*)?$`)

// ParsePackageQuery reads `name`, `name@1.2.3` or `name@<range>` (e.g. `^1.6`, `<1.7.0`). A scoped name starts with @.
func ParsePackageQuery(q string) (PackageQuery, error) {
	q = strings.TrimSpace(q)
	if q == "" || len(q) > maxPackageQuery {
		return PackageQuery{}, fmt.Errorf("%w: the search must have 1 to %d characters", ErrInvalid, maxPackageQuery)
	}
	name, ver, hasVer := q, "", false
	if i := strings.LastIndex(q, "@"); i > 0 {
		name, ver, hasVer = q[:i], strings.TrimSpace(q[i+1:]), true
	}
	if !packageNameRe.MatchString(name) {
		return PackageQuery{}, fmt.Errorf("%w: invalid package name %q", ErrInvalid, name)
	}
	out := PackageQuery{Name: name}
	switch {
	case !hasVer:
	case ver == "":
		return PackageQuery{}, fmt.Errorf("%w: missing version after @", ErrInvalid)
	default:
		if v, err := semver.StrictNewVersion(strings.TrimPrefix(ver, "v")); err == nil {
			out.Version = v.Original()
		} else if c, err := semver.NewConstraint(ver); err == nil {
			out.Range = c
		} else {
			return PackageQuery{}, fmt.Errorf("%w: invalid version or range %q", ErrInvalid, ver)
		}
	}
	return out, nil
}

// PackageHit is one package found in the last deps scan of a project.
type PackageHit struct {
	dbq.SearchPackagesRow
	// DeclaredIn lists the manifest directories declaring a direct dependency ("" is the root).
	DeclaredIn []string `json:"declared_in,omitempty"`
}

type PackageSearch struct {
	Items     []PackageHit `json:"items"`
	Truncated bool         `json:"truncated"`
}

// shortcut: results stop at 500 rows, and a range filters these rows afterwards, so a very common name
// with a range can miss matches; upgrade to SQL-side semver filtering if a portfolio reaches that size.
const maxPackageHits = 500

// SearchPackages finds where a package is used, across the last deps scan of every project (F5.x).
func (a *App) SearchPackages(ctx context.Context, raw string) (PackageSearch, error) {
	pq, err := ParsePackageQuery(raw)
	if err != nil {
		return PackageSearch{}, err
	}
	params := dbq.SearchPackagesParams{Pattern: pq.Name, MaxRows: maxPackageHits + 1}
	if pq.Version != "" || pq.Range != nil {
		params.Exact = true
	} else {
		params.Pattern = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(pq.Name)
	}
	if pq.Version != "" {
		params.Version = &pq.Version
	}
	rows, err := a.q.SearchPackages(ctx, params)
	if err != nil {
		return PackageSearch{}, err
	}
	out := PackageSearch{Items: []PackageHit{}, Truncated: len(rows) > maxPackageHits}
	declared := map[int64]map[string][]string{}
	for _, r := range rows[:min(len(rows), maxPackageHits)] {
		if pq.Range != nil {
			v, err := semver.NewVersion(r.Version)
			if err != nil || !pq.Range.Check(v) {
				continue
			}
		}
		h := PackageHit{SearchPackagesRow: r}
		if r.Direct {
			d, ok := declared[r.ProjectID]
			if !ok {
				if p, err := a.q.GetProject(ctx, r.ProjectID); err == nil {
					d = a.DeclaredIn(ctx, p)
				}
				declared[r.ProjectID] = d
			}
			h.DeclaredIn = d[r.Name]
		}
		out.Items = append(out.Items, h)
	}
	return out, nil
}
