package app

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/riverqueue/river"

	"limier/internal/db/dbq"
)

// workRecheckVulns asks OSV again about the packages of each project's current dependency scan and
// adds the vulnerabilities published since, without reading the project again (SPECS F3.8). Then it
// sends one desktop notification for the whole check.
//
// The new findings go into the current scan instead of a new scan row: a scan row stands for a read
// of the lockfile (commit, SBOM, packages), and copying those to record "nothing changed but OSV"
// would only duplicate data. is_new and first_seen_at already tell what the check found.
func (a *App) workRecheckVulns(ctx context.Context, _ *river.Job[RecheckVulnsArgs]) error {
	s, err := a.q.GetAppSettings(ctx)
	if err != nil {
		return err
	}
	if !s.WatchVulns {
		return nil
	}
	projects, err := a.q.ListRootProjects(ctx)
	if err != nil {
		return err
	}
	var news vulnNews
	for _, p := range projects {
		ids, records, err := a.recheckProject(ctx, p)
		if err != nil {
			// One unreachable project must not hide the news of the others.
			a.log.WarnContext(ctx, "recheck vulnerabilities", "project_id", p.ID, "err", err)
			continue
		}
		if len(ids) == 0 {
			continue
		}
		news.Projects = append(news.Projects, filepath.Base(p.Path))
		for _, id := range ids {
			news.add(records[id])
		}
	}
	if news.Findings == 0 || a.notify == nil {
		return nil
	}
	if err := a.notify(news.notice()); err != nil {
		a.log.WarnContext(ctx, "notification", "err", err)
	}
	return nil
}

// recheckProject inserts the findings OSV now reports on the packages of the project's current
// dependency scan and that the scan does not have yet. It returns their vulnerability IDs.
func (a *App) recheckProject(ctx context.Context, p dbq.Project) ([]string, map[string]dbq.UpsertVulnerabilityParams, error) {
	if p.LastDepsScanID == nil {
		return nil, nil, nil
	}
	scanID := *p.LastDepsScanID
	rows, err := a.q.ListScanPackages(ctx, scanID)
	if err != nil {
		return nil, nil, err
	}
	pkgs := map[string]*pkgRef{}
	for _, r := range rows {
		pkgs[pkgKey(r.Name, r.Version)] = &pkgRef{
			ID: r.ID, Ecosystem: r.Ecosystem, Name: r.Name, Version: r.Version, Purl: r.Purl, Direct: r.Direct, Dev: r.Dev, Path: r.DependencyPath,
		}
	}
	known, err := a.prevFindings(ctx, scanID)
	if err != nil {
		return nil, nil, err
	}
	vulns, err := a.osvVulns(ctx, pkgs, known)
	if err != nil || len(vulns) == 0 {
		return nil, nil, err
	}
	records, err := a.vulnRecords(ctx, vulns)
	if err != nil {
		return nil, nil, err
	}
	var ids []string
	// Computed before the transaction: SQLite holds its write lock from BEGIN.
	rules, reach := a.EffectiveRules(ctx, p.ID), a.reachability(ctx, p)
	err = a.inTx(ctx, func(q *dbq.Queries, _ *sql.Tx) error {
		// known holds the current findings, so every inserted one is new (F3.8).
		ids, _, _, err = insertFindings(ctx, q, p, scanID, rules, reach, pkgs, vulns, records, known, true)
		return err
	})
	if err != nil || len(ids) == 0 {
		return nil, nil, err
	}
	// Risk score and today's snapshot now include the new findings.
	return ids, records, a.recomputeProject(ctx, p)
}

// vulnNews counts the new findings of one check. Each finding counts in its most urgent class only.
type vulnNews struct {
	Findings, Malicious, KEV, Critical int
	Projects                           []string
}

func (n *vulnNews) add(v dbq.UpsertVulnerabilityParams) {
	n.Findings++
	switch {
	case v.Malicious:
		n.Malicious++
	case v.InKev:
		n.KEV++
	case v.Severity == "critical":
		n.Critical++
	}
}

// notice builds the notification title and body, the most urgent classes first.
// shortcut: French only, since the UI language lives in the webview's localStorage; store it in
// app_settings if English users ask.
func (n vulnNews) notice() (title, body string) {
	plural := func(c int, one, many string) string {
		if c > 1 {
			return fmt.Sprintf("%d %s", c, many)
		}
		return fmt.Sprintf("%d %s", c, one)
	}
	title = fmt.Sprintf("Le détective a du nouveau : %s dans %s",
		plural(n.Findings, "nouvelle faille", "nouvelles failles"), plural(len(n.Projects), "projet", "projets"))
	var urgent []string
	if n.Malicious > 0 {
		urgent = append(urgent, plural(n.Malicious, "paquet malveillant", "paquets malveillants"))
	}
	if n.KEV > 0 {
		urgent = append(urgent, plural(n.KEV, "faille déjà exploitée", "failles déjà exploitées"))
	}
	if n.Critical > 0 {
		urgent = append(urgent, plural(n.Critical, "critique", "critiques"))
	}
	if len(urgent) > 0 {
		body = "À regarder d'abord : " + strings.Join(urgent, ", ") + ". "
	}
	names := n.Projects
	if len(names) > 3 {
		names = append(names[:3:3], fmt.Sprintf("%d autres", len(n.Projects)-3))
	}
	body += "Projets : " + strings.Join(names, ", ") + "."
	return title, body
}
