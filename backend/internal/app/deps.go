package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/riverqueue/river"

	"limier/internal/db/dbq"
	"limier/internal/scanners"
	"limier/internal/scanners/typosquat"
	"limier/internal/vulndb"
)

// pkgRef is a dependency found in a scan.
type pkgRef struct {
	ID                             int64
	Ecosystem, Name, Version, Purl string
	Direct, Dev                    bool
	Path                           []string
	Via                            []string // direct dependencies pulling in a transitive package
	Latest                         string
	Deprecated                     bool
	ReleasedAt                     *time.Time
	LatestPublishedAt              *time.Time // publish date of the latest version
	Maintainers                    *int32
	Scorecard                      *float64
	RepositoryURL                  string   // https URL of the source repository (direct dependencies only)
	Risks                          []string // supply-chain signals, see scanners.Risk*
}

func pkgKey(name, version string) string { return name + "@" + version }

// lockfiles lists the lockfiles read, the one matching the detected package manager first.
var lockfiles = map[string][]string{
	"npm":  {"package-lock.json", "npm-shrinkwrap.json"},
	"pnpm": {"pnpm-lock.yaml"},
	"yarn": {"yarn.lock"},
}

// errNoLockfile is shown to the user: Limier does not guess versions (SPECS F2.1).
var errNoLockfile = permanent("no lockfile: commit package-lock.json, pnpm-lock.yaml or yarn.lock, then scan again")

// workScanDeps reads the project's lockfile in Go, queries OSV and builds the SBOM (SPECS F2.1, F2.2).
// Nothing from the project is run.
func (a *App) workScanDeps(ctx context.Context, job *river.Job[ScanDepsArgs]) error {
	return runScan(ctx, a, job, job.Args.ScanID, func(ctx context.Context, scan dbq.Scan) error {
		p, err := a.q.GetProject(ctx, scan.ProjectID)
		if err != nil {
			return err
		}
		rel, err := a.resolveLocal(p.LocalPath)
		if err != nil {
			return permanent("local directory unavailable: %v", err)
		}
		dir := filepath.Join(a.cfg.LocalReposRoot, rel)
		if commit := headCommit(dir); commit != "" {
			_ = a.q.SetScanCommit(ctx, dbq.SetScanCommitParams{ID: scan.ID, CommitSha: commit})
		}

		manifests := readManifests(dir, a.workspaceDirs(ctx, p))
		graph, paths, err := readLockGraph(dir, p.PackageManager, manifests)
		if err != nil {
			return err
		}
		direct := scanners.DirectDeps(manifests...)
		via := graph.Via()
		pkgs := map[string]*pkgRef{}
		for _, id := range graph.Packages() {
			name, version := scanners.SplitLockID(id)
			isDev, isDirect := direct[name]
			pk := &pkgRef{
				Ecosystem: "npm", Name: name, Version: version, Purl: scanners.NpmPurl(name, version),
				Direct: isDirect, Dev: isDirect && isDev, Path: paths[id],
			}
			if !isDirect {
				pk.Via = via[id]
			}
			pk.Risks = graph.Risks[id]
			if popular, ok := typosquat.Lookalike(name); ok {
				pk.Risks = append(pk.Risks, scanners.RiskTyposquat+":"+popular)
			}
			pkgs[id] = pk
		}
		vulns, err := a.osvVulns(ctx, pkgs, nil)
		if err != nil {
			return err
		}
		a.enrichPackages(ctx, pkgs)

		sbomDoc, err := scanners.BuildCycloneDX(graph)
		if err != nil {
			return err
		}
		uri, err := a.store.Put(ctx, fmt.Sprintf("projects/%d/scans/%d", p.ID, scan.ID), sbomDoc)
		if err != nil {
			return fmt.Errorf("store sbom: %w", err)
		}
		if _, err := a.q.CreateSBOM(ctx, dbq.CreateSBOMParams{ScanID: scan.ID, Format: "cyclonedx-json", StorageUri: uri}); err != nil {
			return err
		}
		return a.processDeps(ctx, p, scan, pkgs, vulns)
	})
}

func (a *App) workspaceDirs(ctx context.Context, p dbq.Project) []string {
	var dirs []string
	if ws, err := a.q.ListWorkspaces(ctx, &p.ID); err == nil {
		for _, w := range ws {
			dirs = append(dirs, w.Subdir)
		}
	}
	return dirs
}

// readManifests reads the root and workspace package.json files; unreadable ones only reduce precision.
func readManifests(dir string, workspaces []string) []scanners.Manifest {
	var out []scanners.Manifest
	for _, sub := range append([]string{""}, workspaces...) {
		b, err := os.ReadFile(filepath.Join(dir, sub, "package.json"))
		if err != nil {
			continue
		}
		if m, err := scanners.ParseManifest(b); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// readLockGraph parses the project's lockfile into its dependency graph and, for npm, the
// dependency path of each package.
// shortcut: only the root lockfile is read, not nested ones outside workspaces; walk the tree if users ask.
func readLockGraph(dir, pm string, manifests []scanners.Manifest) (scanners.LockGraph, map[string][]string, error) {
	names := append(append([]string{}, lockfiles[pm]...), "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock")
	for _, name := range names {
		lock, err := os.ReadFile(filepath.Join(dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return scanners.LockGraph{}, nil, err
		}
		var g scanners.LockGraph
		paths := map[string][]string{}
		switch name {
		case "pnpm-lock.yaml":
			g, err = scanners.PnpmLockGraph(lock)
		case "yarn.lock":
			g, err = scanners.YarnLockGraph(lock, manifests...)
		default:
			if paths, err = scanners.NpmLockPaths(lock); err == nil {
				g, err = scanners.NpmLockGraph(lock)
			}
		}
		if err != nil {
			return g, nil, permanent("unreadable %s: %v", name, err)
		}
		return g, paths, nil
	}
	return scanners.LockGraph{}, nil, errNoLockfile
}

// osvVulns asks OSV which packages are vulnerable, then fetches the full records of the
// vulnerabilities not in known (see dropKnown).
// A partial answer fails the scan: a missing advisory would look like a clean package.
func (a *App) osvVulns(ctx context.Context, pkgs map[string]*pkgRef, known map[string]prevFinding) (map[string][]scanners.OSVVuln, error) {
	var keys []string
	var qs []vulndb.PackageQuery
	for k, pk := range pkgs {
		// Links, git and file versions are not registry releases: OSV knows nothing about them.
		if pk.Version == "" || pk.Version[0] < '0' || pk.Version[0] > '9' {
			continue
		}
		keys = append(keys, k)
		qs = append(qs, vulndb.PackageQuery{Ecosystem: "npm", Name: pk.Name, Version: pk.Version})
	}
	ids, err := a.vuln.QueryBatch(ctx, qs)
	if err != nil {
		return nil, fmt.Errorf("OSV: %w", err)
	}
	ids = dropKnown(keys, ids, pkgs, known)
	var all []string
	for _, list := range ids {
		all = append(all, list...)
	}
	raw, err := a.vuln.GetVulns(ctx, all)
	if err != nil {
		return nil, fmt.Errorf("OSV: %w", err)
	}
	out := map[string][]scanners.OSVVuln{}
	for i, list := range ids {
		for _, id := range list {
			b, ok := raw[id]
			if !ok {
				continue // withdrawn since the batch query
			}
			v, err := scanners.ParseOSVVuln(b)
			if err != nil {
				return nil, fmt.Errorf("OSV %s: %w", id, err)
			}
			out[keys[i]] = append(out[keys[i]], v)
		}
	}
	return out, nil
}

// dropKnown removes from ids (aligned with keys) the vulnerabilities that known already reports on
// the same package name, so that a recheck fetches and inserts only the new ones.
func dropKnown(keys []string, ids [][]string, pkgs map[string]*pkgRef, known map[string]prevFinding) [][]string {
	if len(known) == 0 {
		return ids
	}
	out := make([][]string, len(ids))
	for i, list := range ids {
		for _, id := range list {
			if _, ok := known[id+"|"+pkgs[keys[i]].Name]; !ok {
				out[i] = append(out[i], id)
			}
		}
	}
	return out
}

// enrichPackages adds latest version, deprecation and release date to every package, direct or
// indirect (F2.2): indirect ones show their latest version under the direct dependency pulling them in.
// shortcut: one registry + one deps.dev request per distinct package (8 in flight), so a big
// monorepo adds ~30 s to the scan; cache PackageInfo across scans if that becomes a pain.
func (a *App) enrichPackages(ctx context.Context, pkgs map[string]*pkgRef) {
	var names []string
	seen := map[string]bool{}
	for _, p := range pkgs {
		if !seen[p.Name] {
			seen[p.Name] = true
			names = append(names, p.Name)
		}
	}
	if len(names) == 0 {
		return
	}
	infos, errs := a.vuln.NPMPackages(ctx, names)
	if len(errs) > 0 {
		a.log.InfoContext(ctx, "npm metadata unavailable for some packages", "count", len(errs))
	}
	for name, info := range infos {
		a.releases.Store(name, info.ReleasedAt)
	}
	for _, p := range pkgs {
		info, ok := infos[p.Name]
		if !ok {
			continue
		}
		p.Latest = info.Latest
		_, p.Deprecated = info.Deprecated[p.Version]
		if t, ok := info.ReleasedAt[p.Version]; ok {
			p.ReleasedAt = &t
		}
		if t, ok := info.ReleasedAt[info.Latest]; ok {
			p.LatestPublishedAt = &t
		}
	}
	a.enrichHealth(ctx, pkgs)
}

// enrichHealth adds the Scorecard score, maintainer count and source repository of the latest version of each direct dependency.
// shortcut: direct dependencies only (3 requests each), since the user acts on those; extend to indirect
// ones with a cross-scan cache if users ask.
func (a *App) enrichHealth(ctx context.Context, pkgs map[string]*pkgRef) {
	latest := map[string]string{}
	for _, p := range pkgs {
		if p.Direct && p.Latest != "" {
			latest[p.Name] = p.Latest
		}
	}
	if len(latest) == 0 {
		return
	}
	health := a.vuln.PackageHealths(ctx, latest)
	for _, p := range pkgs {
		h, ok := health[p.Name]
		if !ok || !p.Direct {
			continue
		}
		p.Scorecard = h.Scorecard
		p.RepositoryURL = h.Repository
		if h.Maintainers != nil {
			n := int32(*h.Maintainers)
			p.Maintainers = &n
		}
	}
}
