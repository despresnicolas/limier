package httpapi

import (
	"net/http"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"

	"limier/internal/db/dbq"
)

type driftProject struct {
	ID   int64  `json:"id"`
	Path string `json:"path"`
}

type driftVersion struct {
	Version   string         `json:"version"`
	OpenVulns int32          `json:"open_vulns"`
	Projects  []driftProject `json:"projects"`
}

type driftPackage struct {
	Name          string         `json:"name"`
	Projects      int            `json:"projects"`
	LatestVersion string         `json:"latest_version"`
	Spread        int            `json:"spread"`
	Vulnerable    bool           `json:"vulnerable"`
	Versions      []driftVersion `json:"versions"`
}

const driftLimit = 200

// versionDrift lists packages used at different versions across projects (F5 portfolio).
func (s *Server) versionDrift(w http.ResponseWriter, r *http.Request) {
	all, err := queryBool(r, "all")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// shortcut: all=1 reads every indirect package of every project in one query, page it if portfolios grow past ~100 projects.
	rows, err := s.q.VersionDriftRows(r.Context(), all != nil && *all)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, groupDrift(rows, driftLimit))
}

// groupDrift groups rows by package, keeps packages with 2+ versions, and sorts them:
// vulnerable first, then by major spread, then by project count.
func groupDrift(rows []dbq.VersionDriftRowsRow, limit int) []driftPackage {
	byName := map[string]*driftPackage{}
	seen := map[string]map[int64]bool{}
	var order []string
	for _, row := range rows {
		p := byName[row.Name]
		if p == nil {
			p = &driftPackage{Name: row.Name}
			byName[row.Name] = p
			seen[row.Name] = map[int64]bool{}
			order = append(order, row.Name)
		}
		if p.LatestVersion == "" {
			p.LatestVersion = row.LatestVersion
		}
		if !seen[row.Name][row.ProjectID] {
			seen[row.Name][row.ProjectID] = true
			p.Projects++
		}
		var v *driftVersion
		for i := range p.Versions {
			if p.Versions[i].Version == row.Version {
				v = &p.Versions[i]
			}
		}
		if v == nil {
			p.Versions = append(p.Versions, driftVersion{Version: row.Version, Projects: []driftProject{}})
			v = &p.Versions[len(p.Versions)-1]
		}
		v.OpenVulns = max(v.OpenVulns, row.OpenVulns)
		v.Projects = append(v.Projects, driftProject{ID: row.ProjectID, Path: row.ProjectPath})
		p.Vulnerable = p.Vulnerable || row.OpenVulns > 0
	}
	out := make([]driftPackage, 0, len(order))
	for _, name := range order {
		p := byName[name]
		if len(p.Versions) < 2 {
			continue
		}
		sort.Slice(p.Versions, func(i, j int) bool { return versionLess(p.Versions[i].Version, p.Versions[j].Version) })
		p.Spread = majorSpread(p.Versions[0].Version, p.Versions[len(p.Versions)-1].Version)
		out = append(out, *p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Vulnerable != b.Vulnerable {
			return a.Vulnerable
		}
		if a.Spread != b.Spread {
			return a.Spread > b.Spread
		}
		if a.Projects != b.Projects {
			return a.Projects > b.Projects
		}
		return a.Name < b.Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// versionLess orders by semver; unparsable versions sort after valid ones, by text.
func versionLess(a, b string) bool {
	av, aerr := semver.NewVersion(strings.TrimSpace(a))
	bv, berr := semver.NewVersion(strings.TrimSpace(b))
	switch {
	case aerr == nil && berr == nil:
		return av.LessThan(bv)
	case aerr == nil:
		return true
	case berr == nil:
		return false
	}
	return a < b
}

// majorSpread counts the majors between the lowest and highest version, 0 when one cannot be parsed.
func majorSpread(low, high string) int {
	lv, err := semver.NewVersion(strings.TrimSpace(low))
	if err != nil {
		return 0
	}
	hv, err := semver.NewVersion(strings.TrimSpace(high))
	if err != nil || hv.Major() < lv.Major() {
		return 0
	}
	return int(hv.Major() - lv.Major())
}
