package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"limier/internal/db/dbq"
	"limier/internal/policy"
	"limier/internal/scanners"
)

// enrichment holds EPSS and KEV data for a set of CVEs.
type enrichment struct {
	epss map[string]float64
	kev  map[string]bool
}

func (a *App) loadEnrichment(ctx context.Context, vulns map[string]scanners.OSVVuln) (enrichment, error) {
	e := enrichment{epss: map[string]float64{}, kev: map[string]bool{}}
	var cves []string
	for _, v := range vulns {
		cves = append(cves, v.CVEs()...)
	}
	if len(cves) == 0 {
		return e, nil
	}
	scores, err := a.q.EPSSForCVEs(ctx, cves)
	if err != nil {
		return e, err
	}
	for _, s := range scores {
		e.epss[s.CveID] = s.Score
	}
	kev, err := a.q.KEVForCVEs(ctx, cves)
	if err != nil {
		return e, err
	}
	for _, c := range kev {
		e.kev[c] = true
	}
	return e, nil
}

// vulnRecord converts an OSV record to its database row.
func vulnRecord(v scanners.OSVVuln, e enrichment) dbq.UpsertVulnerabilityParams {
	score, vector, ok := v.CVSS()
	severity := "unknown"
	var cvss *float64
	if ok {
		cvss = &score
		severity = scanners.SeverityFromScore(score)
	}
	malicious := v.Malicious()
	if malicious {
		severity = "critical"
	}
	var epss *float64
	inKEV := false
	for _, c := range v.CVEs() {
		if s, ok := e.epss[c]; ok && (epss == nil || s > *epss) {
			epss = &s
		}
		inKEV = inKEV || e.kev[c]
	}
	refs, _ := json.Marshal(v.References)
	if v.References == nil {
		refs = []byte("[]")
	}
	aliases := v.Aliases
	if aliases == nil {
		aliases = []string{}
	}
	summary := v.Summary
	if summary == "" {
		summary = truncate(v.Details, 300)
	}
	return dbq.UpsertVulnerabilityParams{
		ID: v.ID, Aliases: aliases, Summary: summary, Severity: severity, CvssScore: cvss, CvssVector: vector,
		EpssScore: epss, InKev: inKEV, Malicious: malicious, PublishedAt: nonZero(v.Published), ModifiedAt: nonZero(v.Modified), Refs: refs,
	}
}

func nonZero(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// reachability tells whether a dependency is imported by the code (F3.4), from the latest code scan graph.
// nil means unknown: no code scan yet, or a transitive dependency without known path.
type reachability map[string]bool

func (a *App) reachability(ctx context.Context, p dbq.Project) reachability {
	if p.LastCodeScanID == nil {
		return nil
	}
	raw, err := a.q.GetCodeGraph(ctx, *p.LastCodeScanID)
	if err != nil {
		return nil
	}
	var g struct {
		ImportedPackages []string `json:"imported_packages"`
	}
	if json.Unmarshal(raw, &g) != nil || g.ImportedPackages == nil {
		return nil
	}
	r := reachability{}
	for _, n := range g.ImportedPackages {
		r[n] = true
	}
	return r
}

func (r reachability) of(name string, direct bool, path []string) *bool {
	if r == nil {
		return nil
	}
	var root string
	switch {
	case direct:
		root = name
	case len(path) > 0:
		root = path[0]
	default:
		return nil
	}
	v := r[root]
	if v {
		// Imported: the vulnerable code may still be unused, but we cannot tell.
		return nil
	}
	return &v
}

// prevFinding is a finding of an earlier scan (or of the current one, for a recheck), keyed by
// vulnerability ID + "|" + package name.
type prevFinding struct {
	id          int64
	status      string
	firstSeenAt time.Time
}

func (a *App) prevFindings(ctx context.Context, scanID int64) (map[string]prevFinding, error) {
	rows, err := a.q.ListScanFindingKeys(ctx, scanID)
	if err != nil {
		return nil, err
	}
	prev := map[string]prevFinding{}
	for _, r := range rows {
		prev[r.VulnerabilityID+"|"+r.PackageName] = prevFinding{r.ID, r.Status, r.FirstSeenAt}
	}
	return prev, nil
}

// vulnRecords enriches the distinct OSV records with EPSS and KEV.
func (a *App) vulnRecords(ctx context.Context, vulns map[string][]scanners.OSVVuln) (map[string]dbq.UpsertVulnerabilityParams, error) {
	uniq := map[string]scanners.OSVVuln{}
	for _, vs := range vulns {
		for _, v := range vs {
			uniq[v.ID] = v
		}
	}
	enr, err := a.loadEnrichment(ctx, uniq)
	if err != nil {
		return nil, err
	}
	records := map[string]dbq.UpsertVulnerabilityParams{}
	for id, v := range uniq {
		records[id] = vulnRecord(v, enr)
	}
	return records, nil
}

// insertFindings upserts the vulnerabilities and inserts one finding per vulnerable package version
// into scan. A finding is new when hadPrev and prev has no finding for its vulnerability and package.
// It returns the vulnerability ID and priority of each finding, and the keys seen (see prevFinding).
func insertFindings(ctx context.Context, q *dbq.Queries, p dbq.Project, scanID int64, rules policy.Rules, reach reachability,
	pkgs map[string]*pkgRef, vulns map[string][]scanners.OSVVuln, records map[string]dbq.UpsertVulnerabilityParams,
	prev map[string]prevFinding, hadPrev bool) (ids []string, priorities []float64, seen map[string]bool, err error) {
	for _, rec := range records {
		if err := q.UpsertVulnerability(ctx, rec); err != nil {
			return nil, nil, nil, err
		}
	}
	seen = map[string]bool{}
	for key, vs := range vulns {
		pk, ok := pkgs[key]
		if !ok || pk.ID == 0 {
			continue
		}
		for _, v := range vs {
			fk := v.ID + "|" + pk.Name
			if seen[fk+"|"+pk.Version] {
				continue
			}
			seen[fk+"|"+pk.Version] = true
			seen[fk] = true
			rec := records[v.ID]
			reachable := reach.of(pk.Name, pk.Direct, pk.Path)
			prio := policy.Priority(*rules.Weights, policy.PriorityInput{
				CVSS: deref(rec.CvssScore), EPSS: deref(rec.EpssScore), InKEV: rec.InKev, Reachable: reachable, Direct: pk.Direct, Malicious: rec.Malicious,
			})
			firstSeen := time.Now()
			pf, existed := prev[fk]
			if existed {
				firstSeen = pf.firstSeenAt
			}
			if _, err := q.InsertFinding(ctx, dbq.InsertFindingParams{
				ScanID: scanID, ProjectID: p.ID, VulnerabilityID: v.ID, PackageID: pk.ID,
				FixedVersion: v.MinFixedVersion("npm", pk.Name, pk.Version), Priority: prio, Reachable: reachable,
				Direct: pk.Direct, Status: "open", FirstSeenAt: firstSeen, IsNew: hadPrev && !existed,
			}); err != nil {
				return nil, nil, nil, err
			}
			ids = append(ids, v.ID)
			priorities = append(priorities, prio)
		}
	}
	return ids, priorities, seen, nil
}

// processDeps stores packages, vulnerabilities and findings of a dependency scan, carries ignores over,
// marks disappeared findings fixed and switches the project to this scan.
func (a *App) processDeps(ctx context.Context, p dbq.Project, scan dbq.Scan, pkgs map[string]*pkgRef, vulns map[string][]scanners.OSVVuln) error {
	rules := a.EffectiveRules(ctx, p.ID)
	reach := a.reachability(ctx, p)
	records, err := a.vulnRecords(ctx, vulns)
	if err != nil {
		return err
	}

	prev := map[string]prevFinding{}
	// On the first scan nothing is "new": everything is.
	hadPrev := p.LastDepsScanID != nil && *p.LastDepsScanID != scan.ID
	if hadPrev {
		if prev, err = a.prevFindings(ctx, *p.LastDepsScanID); err != nil {
			return err
		}
	}

	err = a.inTx(ctx, func(q *dbq.Queries, _ *sql.Tx) error {
		for _, pk := range pkgs {
			row, err := q.UpsertPackage(ctx, dbq.UpsertPackageParams{Ecosystem: pk.Ecosystem, Name: pk.Name, Version: pk.Version, Purl: pk.Purl})
			if err != nil {
				return err
			}
			pk.ID = row.ID
			path := pk.Path
			if path == nil {
				path = []string{}
			}
			via := pk.Via
			if via == nil {
				via = []string{}
			}
			risks := pk.Risks
			if risks == nil {
				risks = []string{}
			}
			if err := q.InsertScanPackage(ctx, dbq.InsertScanPackageParams{
				ScanID: scan.ID, PackageID: pk.ID, Direct: pk.Direct, Dev: pk.Dev, DependencyPath: path, Via: via,
				LatestVersion: pk.Latest, Deprecated: pk.Deprecated, ReleasedAt: pk.ReleasedAt,
				LatestPublishedAt: pk.LatestPublishedAt, Maintainers: pk.Maintainers, Scorecard: pk.Scorecard, RepositoryUrl: pk.RepositoryURL,
				Risks: risks,
			}); err != nil {
				return err
			}
		}
		_, priorities, seen, err := insertFindings(ctx, q, p, scan.ID, rules, reach, pkgs, vulns, records, prev, hadPrev)
		if err != nil {
			return err
		}

		var fixed []int64
		for k, pf := range prev {
			if !seen[k] && pf.status != "fixed" {
				fixed = append(fixed, pf.id)
			}
		}
		if len(fixed) > 0 {
			if err := q.MarkFindingsFixed(ctx, fixed); err != nil {
				return err
			}
		}
		if err := q.SetProjectLastDepsScan(ctx, dbq.SetProjectLastDepsScanParams{ID: p.ID, LastDepsScanID: &scan.ID, RiskScore: policy.RiskScore(priorities)}); err != nil {
			return err
		}
		return a.refreshSnapshot(ctx, q, p.ID)
	})
	return err
}

func deref(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}

// refreshSnapshot writes today's aggregated metrics for trends (2-year retention).
func (a *App) refreshSnapshot(ctx context.Context, q *dbq.Queries, projectID int64) error {
	p, err := q.GetProject(ctx, projectID)
	if err != nil {
		return err
	}
	sev, err := q.ProjectSeverityCounts(ctx, projectID)
	if err != nil {
		return err
	}
	params := dbq.UpsertSnapshotParams{
		ProjectID: projectID, VulnsCritical: sev.Critical, VulnsHigh: sev.High, VulnsMedium: sev.Medium, VulnsLow: sev.Low,
		RiskScore: p.RiskScore,
	}
	if p.LastCodeScanID != nil {
		if m, err := q.GetCodeMetrics(ctx, *p.LastCodeScanID); err == nil {
			params.Loc, params.UnusedDeps, params.Cycles = &m.Loc, &m.UnusedDeps, &m.Cycles
		}
	}
	return q.UpsertSnapshot(ctx, params)
}

// recomputeProject re-scores the current findings of a project (policy change, new EPSS/KEV data, new code graph).
func (a *App) recomputeProject(ctx context.Context, p dbq.Project) error {
	// Reload: a concurrent dependency scan may have switched the current scan.
	p, err := a.q.GetProject(ctx, p.ID)
	if err != nil {
		return err
	}
	if p.LastDepsScanID == nil {
		return nil
	}
	rules := a.EffectiveRules(ctx, p.ID)
	reach := a.reachability(ctx, p)
	rows, err := a.q.ListCurrentFindingsForScoring(ctx, *p.LastDepsScanID)
	if err != nil {
		return err
	}
	return a.inTx(ctx, func(q *dbq.Queries, _ *sql.Tx) error {
		var priorities []float64
		for _, r := range rows {
			reachable := reach.of(r.PackageName, r.Direct, r.DependencyPath)
			prio := policy.Priority(*rules.Weights, policy.PriorityInput{CVSS: r.CvssScore, EPSS: r.EpssScore, InKEV: r.InKev, Reachable: reachable, Direct: r.Direct, Malicious: r.Malicious})
			if err := q.UpdateFindingScore(ctx, dbq.UpdateFindingScoreParams{ID: r.ID, Priority: prio, Reachable: reachable}); err != nil {
				return err
			}
			if r.Status == "open" {
				priorities = append(priorities, prio)
			}
		}
		if err := q.SetProjectRisk(ctx, dbq.SetProjectRiskParams{ID: p.ID, RiskScore: policy.RiskScore(priorities)}); err != nil {
			return err
		}
		return a.refreshSnapshot(ctx, q, p.ID)
	})
}
