package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/riverqueue/river"

	"limier/internal/db/dbq"
	"limier/internal/fixbot"
	"limier/internal/scanners"
	"limier/internal/vulndb"
)

// Limier proposes fixes (CVE fixes and version bumps),
// a user accepts or rejects each one, and an accepted fix becomes a branch committed into the
// local repository. The working tree and the checked-out branch are never touched.

// LocalFixProposal is a fix Limier can apply to a local project, with the decision taken on it.
type LocalFixProposal struct {
	// Kind is "bump" (a direct dependency in its manifest) or "override" (a transitive package pinned
	// in the root package.json: overrides, pnpm.overrides or resolutions).
	Kind             string        `json:"kind"`
	ManifestDir      string        `json:"manifest_dir"`
	PackageName      string        `json:"package_name"`
	FromVersion      string        `json:"from_version"`
	ToVersion        string        `json:"to_version"`
	UpdateType       string        `json:"update_type"` // patch, minor or major
	Dev              bool          `json:"dev"`
	VulnerabilityIDs []string      `json:"vulnerability_ids"`
	Severity         string        `json:"severity"`
	InKev            bool          `json:"in_kev"`
	Malicious        bool          `json:"malicious"`
	Priority         float64       `json:"priority"`
	Branch           string        `json:"branch"`
	Decision         *dbq.LocalFix `json:"decision"`
	// Transitive lists, for a bump, the vulnerable transitive packages it fixes through this parent.
	Transitive []string `json:"transitive,omitempty"`
	// Via lists, for an override, the direct dependencies that pull the package in.
	Via []string `json:"via,omitempty"`
	// ReleasedAt is the publish date of ToVersion, when known.
	ReleasedAt *time.Time `json:"released_at"`
	// TooFresh is true when ToVersion is younger than min_release_age_days (see releaseAge).
	TooFresh bool `json:"too_fresh"`
	// RepositoryURL is the https URL of the package's source repository, "" when unknown (see vulndb.RepoURL).
	RepositoryURL string `json:"repository_url"`
	FixEffort
}

// FixEffort estimates the work needed to adapt the code to a fix.
type FixEffort struct {
	// Breaking is true when semver allows breaking changes (major, or minor in 0.x).
	Breaking bool `json:"breaking"`
	// BreakingSteps is the number of breaking boundaries crossed (-1: unknown version scheme).
	BreakingSteps int `json:"breaking_steps"`
	// UsageFiles is the number of project files importing the package; nil without a code scan.
	UsageFiles *int `json:"usage_files"`
	// Effort is "low", "medium" or "high"; EffortReason explains it.
	Effort       string `json:"effort"`
	EffortReason string `json:"effort_reason"`
}

// LocalFixes is the fix view of a local project.
type LocalFixes struct {
	// Proposals are the fixes without a decision, or whose branch creation failed.
	Proposals []LocalFixProposal `json:"proposals"`
	// Decisions are all accepted and rejected fixes, most recent first.
	Decisions []dbq.LocalFix `json:"decisions"`
	// GitRepository is false when the directory is not the root of a git repository:
	// fixes can be listed but not applied.
	GitRepository bool `json:"git_repository"`
	// LowRisk counts the proposals GroupLocalFixes would put on GroupBranch.
	LowRisk     int    `json:"low_risk"`
	GroupBranch string `json:"group_branch"`
	// InstallCommand updates the lockfile on a fix branch (Limier only edits package.json).
	InstallCommand string `json:"install_command"`
	// Held are the proposals kept out because their target is younger than MinReleaseAgeDays.
	Held              []LocalFixProposal `json:"held"`
	MinReleaseAgeDays int                `json:"min_release_age_days"`
}

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// newer reports whether version a is strictly newer than b.
func newer(a, b string) bool { return vulndb.VersionsBehind(b, a) != "" }

// LocalFixes computes the proposals of a local project (root and workspaces) from its last scans.
func (a *App) LocalFixes(ctx context.Context, projectID int64) (LocalFixes, error) {
	p, err := a.rootProject(ctx, projectID)
	if err != nil {
		return LocalFixes{}, err
	}
	proposals, err := a.localProposals(ctx, p)
	if err != nil {
		return LocalFixes{}, err
	}
	decisions, err := a.q.ListLocalFixes(ctx, p.ID)
	if err != nil {
		return LocalFixes{}, err
	}
	byKey := map[string]dbq.LocalFix{}
	for _, d := range decisions {
		byKey[fixKey(d.ManifestDir, d.PackageName, d.ToVersion)] = d
	}
	out := LocalFixes{Proposals: []LocalFixProposal{}, Decisions: decisions, Held: []LocalFixProposal{},
		MinReleaseAgeDays: *a.EffectiveRules(ctx, p.ID).MinReleaseAgeDays}
	for _, pr := range proposals {
		d, ok := byKey[fixKey(pr.ManifestDir, pr.PackageName, pr.ToVersion)]
		if ok && d.Status != "failed" {
			continue
		}
		if pr.TooFresh && !securityBeatsCaution(pr) {
			out.Held = append(out.Held, pr)
			continue
		}
		if ok {
			pr.Decision = &d
		}
		out.Proposals = append(out.Proposals, pr)
	}
	_, gitErr := a.localGitDir(p)
	out.GitRepository = gitErr == nil
	out.LowRisk = len(lowRisk(out.Proposals))
	out.GroupBranch = fixbot.GroupBranchName(p.BranchPrefix)
	out.InstallCommand = fixbot.InstallCommand(p.PackageManager)
	return out, nil
}

func fixKey(dir, pkg, version string) string { return dir + "\x00" + pkg + "\x00" + version }

// declaredIn maps each direct dependency to the manifest directories (root "" and workspace subdirs)
// whose package.json declares it, read from the working tree. Unreadable manifests are skipped.
func (a *App) declaredIn(projects []dbq.Project) map[string][]string {
	out := map[string][]string{}
	for _, p := range projects {
		if strings.Contains(path.Clean("/"+p.Subdir), "..") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(a.cfg.LocalReposRoot, p.LocalPath, p.Subdir, "package.json"))
		if err != nil {
			continue
		}
		m, err := scanners.ParseManifest(b)
		if err != nil {
			continue
		}
		for name := range scanners.DirectDeps(m) {
			out[name] = append(out[name], p.Subdir)
		}
	}
	return out
}

// DeclaredIn is declaredIn for a root project and its workspaces.
func (a *App) DeclaredIn(ctx context.Context, root dbq.Project) map[string][]string {
	ws, err := a.q.ListWorkspaces(ctx, &root.ID)
	if err != nil {
		return nil
	}
	return a.declaredIn(append([]dbq.Project{root}, ws...))
}

// localProposals lists CVE fixes first (by priority), then plain version bumps of direct dependencies.
func (a *App) localProposals(ctx context.Context, root dbq.Project) ([]LocalFixProposal, error) {
	projects := []dbq.Project{root}
	ws, err := a.q.ListWorkspaces(ctx, &root.ID)
	if err != nil {
		return nil, err
	}
	projects = append(projects, ws...)
	ids := make([]int64, 0, len(projects))
	dirOf := map[int64]string{}
	for _, p := range projects {
		ids = append(ids, p.ID)
		dirOf[p.ID] = p.Subdir
	}
	findings, err := a.q.ListFixableFindings(ctx, ids)
	if err != nil {
		return nil, err
	}
	pkgsOf := map[int64][]dbq.ListScanPackagesRow{}
	direct := map[int64]map[string]dbq.ListScanPackagesRow{}
	repos := map[string]string{}
	for _, p := range projects {
		if p.LastDepsScanID == nil {
			continue
		}
		pkgs, err := a.q.ListScanPackages(ctx, *p.LastDepsScanID)
		if err != nil {
			return nil, err
		}
		pkgsOf[p.ID] = pkgs
		direct[p.ID] = map[string]dbq.ListScanPackagesRow{}
		for _, pkg := range pkgs {
			if pkg.RepositoryUrl != "" {
				repos[pkg.Name] = pkg.RepositoryUrl
			}
			if pkg.Direct {
				direct[p.ID][pkg.Name] = pkg
			}
		}
	}
	// In a monorepo a dependency is bumped in each manifest that declares it, not in the scanned root.
	declared := a.declaredIn(projects)
	parentBump := func(parent, from, child, fixed string) (string, bool) {
		k := strings.Join([]string{parent, from, child, fixed}, "\x00")
		if v, ok := a.parentBumps.Load(k); ok {
			to := v.(string)
			return to, to != ""
		}
		to, ok, err := a.vuln.ParentBump(ctx, parent, from, child, fixed)
		if err != nil {
			a.log.InfoContext(ctx, "parent bump unavailable, falling back to an override", "parent", parent, "child", child, "error", err)
			return "", false
		}
		if !ok {
			to = ""
		}
		a.parentBumps.Store(k, to)
		return to, ok
	}
	out := securityProposals(findings, dirOf, declared, direct, parentBump)
	bumped := map[string]bool{}
	for _, pr := range out {
		if pr.Kind == "bump" {
			bumped[pr.ManifestDir+"\x00"+pr.PackageName] = true
		}
	}

	var bumps []LocalFixProposal
	for _, p := range projects {
		for _, pkg := range pkgsOf[p.ID] {
			if !pkg.Direct || pkg.LatestVersion == "" || !newer(pkg.LatestVersion, pkg.Version) {
				continue
			}
			for _, dir := range dirsOf(declared, pkg.Name, p.Subdir) {
				if bumped[dir+"\x00"+pkg.Name] {
					continue
				}
				bumped[dir+"\x00"+pkg.Name] = true
				bumps = append(bumps, LocalFixProposal{Kind: "bump", ManifestDir: dir, PackageName: pkg.Name, FromVersion: pkg.Version, ToVersion: pkg.LatestVersion, Dev: pkg.Dev})
			}
		}
	}
	out = append(out, bumps...)
	if days := *a.EffectiveRules(ctx, root.ID).MinReleaseAgeDays; days > 0 {
		releases := a.releaseTimes(ctx, out)
		for i := range out {
			releaseAge(&out[i], releases[out[i].PackageName], time.Duration(days)*24*time.Hour, time.Now())
		}
	}
	usage := a.packageUsage(ctx, root)
	for i := range out {
		pr := &out[i]
		pr.UpdateType = vulndb.VersionsBehind(pr.FromVersion, pr.ToVersion)
		pr.FixEffort = estimateEffort(pr.FromVersion, pr.ToVersion, pr.Dev, usage, pr.PackageName)
		pr.RepositoryURL = repos[pr.PackageName]
		if pr.VulnerabilityIDs == nil {
			pr.VulnerabilityIDs = []string{}
		}
		pr.Branch = fixbot.BumpBranchName(root.BranchPrefix, pr.ManifestDir, pr.PackageName, pr.ToVersion)
		if pr.Kind == "override" {
			pr.FixEffort = overrideEffort(pr.FixEffort)
			pr.Branch = fixbot.OverrideBranchName(root.BranchPrefix, pr.PackageName, pr.ToVersion)
		}
	}
	return out, nil
}

func dirsOf(declared map[string][]string, pkg, fallback string) []string {
	if d := declared[pkg]; len(d) > 0 {
		return d
	}
	return []string{fallback}
}

// securityProposals merges the open findings into fixes, sorted by priority. A direct dependency is
// bumped in each manifest declaring it. A transitive one is fixed by bumping its direct parent when a
// parent version brings the fixed child (parentBump), else by an override in the root package.json
// (overrides only work at the root). direct maps each project to its direct dependencies.
func securityProposals(findings []dbq.ListFixableFindingsRow, dirOf map[int64]string, declared map[string][]string,
	direct map[int64]map[string]dbq.ListScanPackagesRow, parentBump func(parent, from, child, fixed string) (string, bool)) []LocalFixProposal {
	byKey := map[string]*LocalFixProposal{}
	var order []string
	add := func(kind, dir, pkg, from, to string, dev bool, f dbq.ListFixableFindingsRow) *LocalFixProposal {
		k := dir + "\x00" + pkg
		if kind == "override" {
			k = "\x01" + pkg
		}
		pr, ok := byKey[k]
		if !ok {
			pr = &LocalFixProposal{Kind: kind, ManifestDir: dir, PackageName: pkg, FromVersion: from, ToVersion: to, Dev: dev, Priority: f.Priority}
			byKey[k] = pr
			order = append(order, k)
		}
		if newer(to, pr.ToVersion) {
			pr.ToVersion = to
		}
		if newer(pr.FromVersion, from) {
			pr.FromVersion = from
		}
		pr.Dev = pr.Dev && dev
		pr.Priority = max(pr.Priority, f.Priority)
		pr.InKev = pr.InKev || f.InKev
		pr.Malicious = pr.Malicious || f.Malicious
		if severityRank[f.Severity] > severityRank[pr.Severity] {
			pr.Severity = f.Severity
		}
		addUnique(&pr.VulnerabilityIDs, f.VulnerabilityID)
		return pr
	}
	for _, f := range findings {
		if f.Direct {
			for _, dir := range dirsOf(declared, f.PackageName, dirOf[f.ProjectID]) {
				add("bump", dir, f.PackageName, f.PackageVersion, f.FixedVersion, f.Dev, f)
			}
			continue
		}
		// shortcut: only npm lockfiles keep the dependency path, so pnpm and yarn transitive fixes are
		// always overrides; store their paths too (like NpmLockPaths) if the overrides get noisy.
		if len(f.DependencyPath) == 2 {
			if parent, ok := direct[f.ProjectID][f.DependencyPath[0]]; ok {
				if to, ok := parentBump(parent.Name, parent.Version, f.PackageName, f.FixedVersion); ok {
					for _, dir := range dirsOf(declared, parent.Name, dirOf[f.ProjectID]) {
						addUnique(&add("bump", dir, parent.Name, parent.Version, to, parent.Dev, f).Transitive, f.PackageName)
					}
					continue
				}
			}
		}
		// shortcut: a package that is also a direct root dependency gets no override (npm refuses an
		// override that conflicts with a direct dependency); its nested copy waits for a parent bump.
		if slices.Contains(declared[f.PackageName], "") {
			continue
		}
		pr := add("override", "", f.PackageName, f.PackageVersion, f.FixedVersion, f.Dev, f)
		for _, v := range f.Via {
			addUnique(&pr.Via, v)
		}
	}
	out := make([]LocalFixProposal, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority > out[j].Priority })
	return out
}

func addUnique(list *[]string, s string) {
	if !slices.Contains(*list, s) {
		*list = append(*list, s)
	}
}

// overrideEffort: forcing a version under a parent that did not ask for it can break the parent,
// whatever semver says, so an override is never low effort (nor in the low-risk group).
func overrideEffort(e FixEffort) FixEffort {
	if e.Effort != "high" {
		e.Effort = "medium"
	}
	e.EffortReason = "Forcer une version peut casser le parent qui ne l'a pas demandée : lancez les tests du parent et de l'application."
	if e.Breaking {
		e.EffortReason = "Forcer une version peut casser le parent, et celle-ci franchit une frontière semver : relisez le changelog et lancez les tests."
	}
	return e
}

// releaseTimes returns the publish dates of the proposed packages, from the cache filled by deps
// scans, fetching the missing ones (after a restart).
func (a *App) releaseTimes(ctx context.Context, proposals []LocalFixProposal) map[string]map[string]time.Time {
	out := map[string]map[string]time.Time{}
	var missing []string
	for _, pr := range proposals {
		if v, ok := a.releases.Load(pr.PackageName); ok {
			out[pr.PackageName] = v.(map[string]time.Time)
		} else if !slices.Contains(missing, pr.PackageName) {
			missing = append(missing, pr.PackageName)
		}
	}
	if len(missing) == 0 {
		return out
	}
	infos, errs := a.vuln.NPMPackages(ctx, missing)
	if len(errs) > 0 {
		a.log.InfoContext(ctx, "publish dates unavailable for some packages", "count", len(errs))
	}
	for name, info := range infos {
		a.releases.Store(name, info.ReleasedAt)
		out[name] = info.ReleasedAt
	}
	return out
}

// releaseAge applies min_release_age_days to a proposal (like Renovate's minimumReleaseAge): a hijacked
// release is usually unpublished within days, so a too fresh target is replaced by the newest stable
// version above FromVersion that is old enough, or flagged TooFresh when there is none.
// A CVE fix is never retargeted: the OSV ranges are not kept here, and a version published before the
// fix can only be safe if its release line was never affected, which cannot be checked.
// shortcut: an unknown publish date (deps.dev down, cache from an older scan) lets the target through;
// store the dates with the scan packages if this hides fresh releases in practice.
func releaseAge(pr *LocalFixProposal, released map[string]time.Time, minAge time.Duration, now time.Time) {
	at, ok := released[pr.ToVersion]
	if !ok {
		return
	}
	pr.ReleasedAt = &at
	if now.Sub(at) >= minAge {
		return
	}
	if len(pr.VulnerabilityIDs) == 0 {
		best := ""
		for v, t := range released {
			if now.Sub(t) >= minAge && !strings.ContainsAny(v, "-+") && newer(v, pr.FromVersion) &&
				!newer(v, pr.ToVersion) && (best == "" || newer(v, best)) {
				best = v
			}
		}
		if best != "" {
			t := released[best]
			pr.ToVersion, pr.ReleasedAt = best, &t
			return
		}
	}
	pr.TooFresh = true
}

// securityBeatsCaution keeps a too fresh fix in the proposals when waiting is the bigger risk: the
// vulnerability is exploited in the wild (KEV) or the version is malicious (OpenSSF MAL- advisory).
// The Fixes tab says the target is fresh.
func securityBeatsCaution(pr LocalFixProposal) bool {
	return len(pr.VulnerabilityIDs) > 0 && (pr.InKev || pr.Malicious)
}

// packageUsage returns the number of files importing each package, from the last code scan of the
// project, or nil when there is none. Graphs stored before package_usage existed are counted from
// their (possibly truncated) edges.
func (a *App) packageUsage(ctx context.Context, p dbq.Project) map[string]int {
	if p.LastCodeScanID == nil {
		return nil
	}
	raw, err := a.q.GetCodeGraph(ctx, *p.LastCodeScanID)
	if err != nil {
		return nil
	}
	var g struct {
		PackageUsage map[string]int `json:"package_usage"`
		Nodes        []graphNode    `json:"nodes"`
		Edges        []graphEdge    `json:"edges"`
	}
	if json.Unmarshal(raw, &g) != nil {
		return nil
	}
	if g.PackageUsage != nil {
		return g.PackageUsage
	}
	return packageUsage(g.Nodes, g.Edges)
}

// graphNode and graphEdge read graphs stored by older versions.
type graphNode struct {
	ID       string `json:"id"`
	External bool   `json:"external"`
	Package  string `json:"package"`
}

type graphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// packageUsage counts, for each external package, the distinct local modules importing it.
func packageUsage(nodes []graphNode, edges []graphEdge) map[string]int {
	pkgOf := map[string]string{}
	local := map[string]bool{}
	for _, n := range nodes {
		if n.External {
			if n.Package != "" {
				pkgOf[n.ID] = n.Package
			}
		} else {
			local[n.ID] = true
		}
	}
	importers := map[string]map[string]bool{}
	for _, e := range edges {
		pkg, ok := pkgOf[e.To]
		if !ok || !local[e.From] {
			continue
		}
		if importers[pkg] == nil {
			importers[pkg] = map[string]bool{}
		}
		importers[pkg][e.From] = true
	}
	out := make(map[string]int, len(importers))
	for pkg, files := range importers {
		out[pkg] = len(files)
	}
	return out
}

// estimateEffort turns the semver jump and the usage of the package into an effort level.
func estimateEffort(from, to string, dev bool, usage map[string]int, pkg string) FixEffort {
	e := FixEffort{BreakingSteps: vulndb.BreakingSteps(from, to)}
	e.Breaking = e.BreakingSteps > 0
	if usage != nil {
		n := usage[pkg]
		e.UsageFiles = &n
	}
	switch {
	case e.BreakingSteps < 0:
		e.Effort, e.EffortReason = "medium", "Schéma de version non semver : impossible de savoir si la mise à jour est compatible."
	case !e.Breaking:
		e.Effort, e.EffortReason = "low", "Mise à jour compatible (semver) : aucun changement de code attendu."
	case e.UsageFiles == nil:
		e.Effort, e.EffortReason = "medium", "Breaking change possible. Lancez un scan du code pour mesurer l'usage du paquet."
	case *e.UsageFiles == 0:
		what := "aucun fichier ne l'importe : vérifiez la configuration, les scripts npm et la CLI"
		if !dev {
			what = "aucun fichier ne l'importe : paquet inutilisé, ou utilisé par configuration ou CLI"
		}
		e.Effort, e.EffortReason = "medium", "Breaking change possible ; "+what+"."
	case *e.UsageFiles > 10 || e.BreakingSteps >= 3:
		e.Effort = "high"
	case *e.UsageFiles > 3 || e.BreakingSteps == 2:
		e.Effort = "medium"
	default:
		e.Effort = "low"
	}
	if e.EffortReason == "" {
		e.EffortReason = fmt.Sprintf("Breaking change possible (%d version%s majeure%s franchie%s), paquet importé par %d fichier%s : relisez le changelog et adaptez ces fichiers.",
			e.BreakingSteps, plural(e.BreakingSteps), plural(e.BreakingSteps), plural(e.BreakingSteps), *e.UsageFiles, plural(*e.UsageFiles))
	}
	return e
}

func plural(n int) string {
	if n > 1 {
		return "s"
	}
	return ""
}

// DecideLocalFix records the decision on a current proposal and, when accepted, queues the branch creation.
// Only failed and rejected decisions can be taken again.
func (a *App) DecideLocalFix(ctx context.Context, projectID, userID int64, dir, pkg, version string, accept bool) (dbq.LocalFix, error) {
	fixes, err := a.LocalFixes(ctx, projectID)
	if err != nil {
		return dbq.LocalFix{}, err
	}
	var pr *LocalFixProposal
	for i, p := range fixes.Proposals {
		if p.ManifestDir == dir && p.PackageName == pkg && p.ToVersion == version {
			pr = &fixes.Proposals[i]
			break
		}
	}
	if pr == nil {
		return dbq.LocalFix{}, fmt.Errorf("%w: no current proposal for %s %s (already decided, or a new scan changed it)", ErrInvalid, pkg, version)
	}
	if accept && !fixes.GitRepository {
		return dbq.LocalFix{}, fmt.Errorf("%w: the directory is not the root of a git repository", ErrInvalid)
	}
	root, err := a.rootProject(ctx, projectID)
	if err != nil {
		return dbq.LocalFix{}, err
	}
	status := "rejected"
	if accept {
		status = "queued"
	}
	fx, err := a.upsertLocalFix(ctx, root.ID, userID, *pr, status)
	if isNoRows(err) {
		return fx, fmt.Errorf("%w: a decision was already taken on this fix", ErrInvalid)
	}
	if err != nil || !accept {
		return fx, err
	}
	if _, err := a.river.Insert(ctx, LocalFixArgs{FixID: fx.ID, UserID: userID}, nil); err != nil {
		return fx, err
	}
	return fx, nil
}

// GroupLocalFixes accepts every low-risk proposal at once: they share one branch, one commit and one job.
func (a *App) GroupLocalFixes(ctx context.Context, projectID, userID int64) ([]dbq.LocalFix, error) {
	fixes, err := a.LocalFixes(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if !fixes.GitRepository {
		return nil, fmt.Errorf("%w: the directory is not the root of a git repository", ErrInvalid)
	}
	root, err := a.rootProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	gitDir, err := a.localGitDir(root)
	if err != nil {
		return nil, err
	}
	// Also checked by the job; checking here gives the user the reason at once.
	if err := checkBranchFree(filepath.Dir(gitDir), fixes.GroupBranch); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	var out []dbq.LocalFix
	for _, pr := range lowRisk(fixes.Proposals) {
		pr.Branch = fixes.GroupBranch
		fx, err := a.upsertLocalFix(ctx, root.ID, userID, pr, "queued")
		if isNoRows(err) {
			continue // decided meanwhile
		}
		if err != nil {
			return out, err
		}
		out = append(out, fx)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no low-risk bump to group", ErrInvalid)
	}
	if _, err := a.river.Insert(ctx, LocalFixArgs{FixID: out[0].ID, UserID: userID}, nil); err != nil {
		return out, err
	}
	return out, nil
}

// lowRisk keeps the bumps that cross no semver boundary (see estimateEffort), whatever the usage.
func lowRisk(ps []LocalFixProposal) []LocalFixProposal {
	return slices.DeleteFunc(slices.Clone(ps), func(p LocalFixProposal) bool { return p.BreakingSteps != 0 || p.Kind == "override" })
}

func (a *App) upsertLocalFix(ctx context.Context, projectID, userID int64, pr LocalFixProposal, status string) (dbq.LocalFix, error) {
	var uid *int64
	if userID != 0 {
		uid = &userID
	}
	return a.q.UpsertLocalFixDecision(ctx, dbq.UpsertLocalFixDecisionParams{
		ProjectID: projectID, Kind: pr.Kind, ManifestDir: pr.ManifestDir, PackageName: pr.PackageName,
		FromVersion: pr.FromVersion, ToVersion: pr.ToVersion, VulnerabilityIds: pr.VulnerabilityIDs,
		Status: status, Branch: pr.Branch, UserID: uid,
	})
}

// ReopenLocalFix deletes a rejected or failed decision so that the fix is proposed again.
func (a *App) ReopenLocalFix(ctx context.Context, projectID, fixID int64) error {
	root, err := a.rootProject(ctx, projectID)
	if err != nil {
		return err
	}
	n, err := a.q.DeleteLocalFix(ctx, dbq.DeleteLocalFixParams{ID: fixID, ProjectID: root.ID})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: only rejected or failed fixes can be proposed again", ErrInvalid)
	}
	return nil
}

// localGitDir returns the .git directory of a local project; it must sit at the project root
// (a .git file, as in linked worktrees, points outside the mounted directory).
func (a *App) localGitDir(p dbq.Project) (string, error) {
	rel, err := a.resolveLocal(p.LocalPath)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(a.cfg.LocalReposRoot, filepath.FromSlash(rel), ".git")
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("%w: %s is not the root of a git repository", ErrInvalid, rel)
	}
	return dir, nil
}

// workLocalFix commits the queued fixes sharing the job's branch (one fix, or a group) on top of HEAD.
// Failures are recorded on the fixes, never retried: the user can accept the proposals again.
func (a *App) workLocalFix(ctx context.Context, job *river.Job[LocalFixArgs]) error {
	fx, err := a.q.GetLocalFix(ctx, job.Args.FixID)
	if err != nil {
		if isNoRows(err) {
			return nil
		}
		return err
	}
	if fx.Status != "queued" {
		return nil
	}
	all, err := a.q.ListLocalFixes(ctx, fx.ProjectID)
	if err != nil {
		return err
	}
	group := slices.DeleteFunc(all, func(f dbq.LocalFix) bool { return f.Branch != fx.Branch || f.Status != "queued" })
	base, commit, err := a.applyLocalFix(ctx, group)
	status, msg := "created", ""
	if err != nil {
		status, msg = "failed", truncate(err.Error(), 1000)
	}
	for _, f := range group {
		if err := a.q.SetLocalFixResult(ctx, dbq.SetLocalFixResultParams{ID: f.ID, Status: status, BaseCommit: base, CommitSha: commit, Error: msg}); err != nil {
			return err
		}
	}
	a.log.InfoContext(ctx, "local fix "+status, "project_id", fx.ProjectID, "fix_id", fx.ID, "fixes", len(group),
		"branch", fx.Branch, "commit", commit, "error", msg)
	if err != nil {
		return river.JobCancel(err)
	}
	return nil
}

func (a *App) applyLocalFix(ctx context.Context, fixes []dbq.LocalFix) (base, commit string, err error) {
	p, err := a.q.GetProject(ctx, fixes[0].ProjectID)
	if err != nil {
		return "", "", err
	}
	gitDir, err := a.localGitDir(p)
	if err != nil {
		return "", "", err
	}
	for _, fx := range fixes {
		if strings.Contains(path.Clean("/"+fx.ManifestDir), "..") {
			return "", "", fmt.Errorf("invalid manifest directory %q", fx.ManifestDir)
		}
		if err := a.q.SetLocalFixRunning(ctx, fx.ID); err != nil {
			return "", "", err
		}
	}
	return commitFixes(filepath.Dir(gitDir), fixes[0].Branch, p.PackageManager, localFixMessage(fixes, p.PackageManager), fixes)
}

// commitFixes writes the bumps and overrides on top of HEAD as a new commit on a new branch, with
// go-git: the working tree, the index, HEAD and existing branches stay untouched, and no hook runs.
// package.json is read from the HEAD tree, so uncommitted changes are ignored.
func commitFixes(repoDir, branch, packageManager, message string, fixes []dbq.LocalFix) (base, commit string, err error) {
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return "", "", err
	}
	head, err := repo.Head()
	if err != nil {
		return "", "", fmt.Errorf("the repository has no commit to start from: %w", err)
	}
	base = head.Hash().String()
	if err := checkBranchFree(repoDir, branch); err != nil {
		return base, "", err
	}
	headCommit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return base, "", err
	}
	tree, err := headCommit.Tree()
	if err != nil {
		return base, "", err
	}
	files := map[string][]byte{}
	for _, fx := range fixes {
		name := path.Join(fx.ManifestDir, "package.json")
		b, ok := files[name]
		if !ok {
			f, err := tree.File(name)
			if err != nil {
				return base, "", fmt.Errorf("%s at HEAD: %w", name, err)
			}
			s, err := f.Contents()
			if err != nil {
				return base, "", err
			}
			b = []byte(s)
		}
		if fx.Kind == "override" {
			b, err = fixbot.SetOverride(b, packageManager, fx.PackageName, fx.ToVersion)
		} else {
			b, err = fixbot.SetDependency(b, fx.PackageName, fx.ToVersion)
		}
		if err != nil {
			return base, "", fmt.Errorf("%s: %w", name, err)
		}
		files[name] = b
	}
	treeHash, err := writeTree(repo.Storer, tree, files)
	if err != nil {
		return base, "", err
	}
	if treeHash == tree.Hash {
		return base, "", errors.New("the fix changes nothing: it is probably already applied")
	}
	sig := commitSignature(repo)
	h, err := storeObject(repo.Storer, &object.Commit{Author: sig, Committer: sig, Message: message, TreeHash: treeHash, ParentHashes: []plumbing.Hash{head.Hash()}})
	if err != nil {
		return base, "", err
	}
	// shortcut: the check above and this write are not atomic, fine for a single-user app; use a lock if another writer appears.
	if err := repo.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName(branch), h)); err != nil {
		return base, "", err
	}
	return base, h.String(), nil
}

// checkBranchFree fails when branch already exists: Limier never overwrites a branch.
func checkBranchFree(repoDir, branch string) error {
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return err
	}
	_, err = repo.Reference(plumbing.NewBranchReferenceName(branch), false)
	switch {
	case err == nil:
		return fmt.Errorf("branch %s already exists: merge or delete it, then try again", branch)
	case errors.Is(err, plumbing.ErrReferenceNotFound):
		return nil
	}
	return err
}

// writeTree stores a copy of t where files (paths relative to t) have new contents, and returns its hash.
func writeTree(s storer.EncodedObjectStorer, t *object.Tree, files map[string][]byte) (plumbing.Hash, error) {
	entries := slices.Clone(t.Entries)
	find := func(name string) (int, error) {
		i := slices.IndexFunc(entries, func(e object.TreeEntry) bool { return e.Name == name })
		if i < 0 {
			return 0, fmt.Errorf("%s not found at HEAD", name)
		}
		return i, nil
	}
	sub := map[string]map[string][]byte{}
	for name, b := range files {
		if dir, rest, nested := strings.Cut(name, "/"); nested {
			if sub[dir] == nil {
				sub[dir] = map[string][]byte{}
			}
			sub[dir][rest] = b
			continue
		}
		i, err := find(name)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		blob := s.NewEncodedObject()
		blob.SetType(plumbing.BlobObject)
		w, err := blob.Writer()
		if err != nil {
			return plumbing.ZeroHash, err
		}
		if _, err := w.Write(b); err != nil {
			return plumbing.ZeroHash, err
		}
		if err := w.Close(); err != nil {
			return plumbing.ZeroHash, err
		}
		if entries[i].Hash, err = s.SetEncodedObject(blob); err != nil {
			return plumbing.ZeroHash, err
		}
	}
	for dir, fs := range sub {
		i, err := find(dir)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		child, err := object.GetTree(s, entries[i].Hash)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		if entries[i].Hash, err = writeTree(s, child, fs); err != nil {
			return plumbing.ZeroHash, err
		}
	}
	return storeObject(s, &object.Tree{Entries: entries})
}

func storeObject(s storer.EncodedObjectStorer, o interface {
	Encode(plumbing.EncodedObject) error
}) (plumbing.Hash, error) {
	obj := s.NewEncodedObject()
	if err := o.Encode(obj); err != nil {
		return plumbing.ZeroHash, err
	}
	return s.SetEncodedObject(obj)
}

// commitSignature uses the user's git identity (repository, then global config), else Limier's.
func commitSignature(repo *git.Repository) object.Signature {
	sig := object.Signature{Name: "Limier", Email: "limier@localhost", When: time.Now()}
	if cfg, err := repo.ConfigScoped(config.GlobalScope); err == nil && cfg.User.Name != "" && cfg.User.Email != "" {
		sig.Name, sig.Email = cfg.User.Name, cfg.User.Email
	}
	return sig
}

func localFixMessage(fixes []dbq.LocalFix, packageManager string) string {
	var b strings.Builder
	var vulns []string
	for _, fx := range fixes {
		vulns = append(vulns, fx.VulnerabilityIds...)
	}
	slices.Sort(vulns)
	vulns = slices.Compact(vulns)
	typ := "chore"
	if len(vulns) > 0 {
		typ = "fix"
	}
	line := func(fx dbq.LocalFix) {
		fmt.Fprintf(&b, "%s from %s to %s", fx.PackageName, fx.FromVersion, fx.ToVersion)
		if fx.Kind == "override" {
			fmt.Fprintf(&b, " (transitive, pinned with %s in the root package.json)", overrideField(packageManager))
		}
		if fx.ManifestDir != "" {
			fmt.Fprintf(&b, " in %s", fx.ManifestDir)
		}
		b.WriteString("\n")
	}
	if len(fixes) == 1 {
		verb := "bump"
		if fixes[0].Kind == "override" {
			verb = "override"
		}
		fmt.Fprintf(&b, "%s(deps): %s ", typ, verb)
		line(fixes[0])
	} else {
		fmt.Fprintf(&b, "%s(deps): bump %d dependencies (minor and patch)\n\n", typ, len(fixes))
		for _, fx := range fixes {
			b.WriteString("- ")
			line(fx)
		}
	}
	b.WriteString("\n")
	if len(vulns) > 0 {
		fmt.Fprintf(&b, "Fixes: %s\n", strings.Join(vulns, ", "))
	}
	fmt.Fprintf(&b, "Only package.json changes: run `%s` on this branch to update the lockfile. Generated by Limier: review and run the tests before merging.\n", fixbot.InstallCommand(packageManager))
	return b.String()
}

func overrideField(packageManager string) string {
	switch packageManager {
	case "pnpm":
		return "pnpm.overrides"
	case "yarn":
		return "resolutions"
	}
	return "overrides"
}
