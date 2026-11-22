package app

import (
	"context"
	"database/sql"
	"strconv"
	"sync"
	"testing"
	"time"

	"limier/internal/db/dbq"
	"limier/internal/db/sqltypes"
)

// Checks for the PostgreSQL → SQLite translation: text times, ids, rewritten queries.

type seed struct {
	t   *testing.T
	ctx context.Context
	q   *dbq.Queries
}

func (s seed) project(path, subdir string, parent *int64) dbq.Project {
	s.t.Helper()
	p, err := s.q.UpsertLocalProject(s.ctx, dbq.UpsertLocalProjectParams{LocalPath: path, ParentID: parent, Path: path + subdir, Subdir: subdir, PackageManager: "npm"})
	if err != nil {
		s.t.Fatal(err)
	}
	return p
}

func (s seed) scan(projectID int64, kind string) dbq.Scan {
	s.t.Helper()
	sc, err := s.q.CreateScan(s.ctx, dbq.CreateScanParams{ProjectID: projectID, Kind: kind, Trigger: "manual"})
	if err != nil {
		s.t.Fatal(err)
	}
	return sc
}

func (s seed) current(p dbq.Project, scanID int64, risk float64) {
	s.t.Helper()
	if err := s.q.SetProjectLastDepsScan(s.ctx, dbq.SetProjectLastDepsScanParams{ID: p.ID, LastDepsScanID: &scanID, RiskScore: risk}); err != nil {
		s.t.Fatal(err)
	}
}

func (s seed) pkg(scanID int64, name, version string) int64 {
	s.t.Helper()
	row, err := s.q.UpsertPackage(s.ctx, dbq.UpsertPackageParams{Ecosystem: "npm", Name: name, Version: version})
	if err != nil {
		s.t.Fatal(err)
	}
	if err := s.q.InsertScanPackage(s.ctx, dbq.InsertScanPackageParams{ScanID: scanID, PackageID: row.ID, Direct: true}); err != nil {
		s.t.Fatal(err)
	}
	return row.ID
}

func (s seed) finding(p dbq.Project, scanID, pkgID int64, vulnID, severity, status string, prio float64, aliases ...string) dbq.Finding {
	s.t.Helper()
	if err := s.q.UpsertVulnerability(s.ctx, dbq.UpsertVulnerabilityParams{ID: vulnID, Aliases: aliases, Severity: severity, Refs: sqltypes.JSON("[]")}); err != nil {
		s.t.Fatal(err)
	}
	f, err := s.q.InsertFinding(s.ctx, dbq.InsertFindingParams{ScanID: scanID, ProjectID: p.ID, VulnerabilityID: vulnID, PackageID: pkgID,
		Priority: prio, Status: status, FirstSeenAt: time.Now()})
	if err != nil {
		s.t.Fatal(err)
	}
	return f
}

func newSeed(t *testing.T) (seed, *App, *sql.DB) {
	a, pool := dbApp(t)
	return seed{t: t, ctx: context.Background(), q: a.q}, a, pool
}

// Text order of stored times must be time order, for Go-written (nanoseconds, no fraction when zero)
// and SQL-written (strftime, always 3 digits) values alike.
func TestDBTimeTextOrder(t *testing.T) {
	_, _, pool := newSeed(t)
	base := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	times := []time.Time{base, base.Add(120 * time.Millisecond), base.Add(123456789), base.Add(500 * time.Millisecond), base.Add(time.Second)}
	for i, ti := range times {
		for j, tj := range times {
			var less bool
			// A non-UTC time must be written in UTC too, or the offset breaks text order.
			if err := pool.QueryRow(`SELECT ? < ?`, ti.In(time.FixedZone("x", 3600)), tj).Scan(&less); err != nil {
				t.Fatal(err)
			}
			if less != (i < j) {
				t.Errorf("%v < %v: got %v", ti, tj, less)
			}
		}
	}
	// SQL-written millisecond text against Go-written text.
	var ok bool
	if err := pool.QueryRow(`SELECT ? < '2026-11-22 10:00:00.001+00:00' AND '2026-11-22 10:00:00.999+00:00' < ?`, base, base.Add(time.Second)).Scan(&ok); err != nil || !ok {
		t.Errorf("mixed SQL/Go text order: %v %v", ok, err)
	}
	// A stored default reads back as a UTC time.
	var created time.Time
	if err := pool.QueryRow(`SELECT updated_at FROM policies LIMIT 1`).Scan(&created); err != nil || time.Since(created) > time.Minute || created.Location() != time.UTC {
		t.Errorf("default created_at: %v %v", created, err)
	}
}

// foreign_keys is a per-connection pragma: every pooled connection must enforce cascades.
func TestDBForeignKeysOnEveryConnection(t *testing.T) {
	s, _, pool := newSeed(t)
	var conns []*sql.Conn
	for range 8 {
		c, err := pool.Conn(s.ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		var on int
		if err := c.QueryRowContext(s.ctx, `PRAGMA foreign_keys`).Scan(&on); err != nil || on != 1 {
			t.Errorf("connection %d: foreign_keys=%d %v", len(conns), on, err)
		}
	}
	for _, c := range conns {
		c.Close()
	}

	p := s.project("fk/app", "", nil)
	ws := s.project("fk/app", "ws", &p.ID)
	sc := s.scan(p.ID, "deps")
	s.finding(p, sc.ID, s.pkg(sc.ID, "x", "1.0.0"), "GHSA-fk", "high", "open", 1)
	if _, err := s.q.DeleteProject(s.ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(`SELECT (SELECT count(*) FROM projects) + (SELECT count(*) FROM scans) + (SELECT count(*) FROM findings) + (SELECT count(*) FROM scan_packages)`).Scan(&n); err != nil || n != 0 {
		t.Errorf("cascade left %d rows (workspace %d) %v", n, ws.ID, err)
	}
	if _, err := pool.Exec(`INSERT INTO scans (project_id, kind, trigger) VALUES (999, 'deps', 'manual')`); err == nil {
		t.Error("insert with a missing project must fail")
	}
}

// Ids must never come back after a delete: River jobs and the UI hold scan, project and fix ids
// (PostgreSQL sequences never reused them; a plain SQLite rowid reuses the largest one).
func TestDBIDsNotReused(t *testing.T) {
	s, _, _ := newSeed(t)
	p := s.project("ids/a", "", nil)
	sc := s.scan(p.ID, "deps")
	if _, err := s.q.DeleteProject(s.ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	p2 := s.project("ids/b", "", nil)
	sc2 := s.scan(p2.ID, "deps")
	if p2.ID <= p.ID || sc2.ID <= sc.ID {
		t.Errorf("ids reused: project %d→%d, scan %d→%d", p.ID, p2.ID, sc.ID, sc2.ID)
	}
}

func TestDBScanOrdering(t *testing.T) {
	s, _, pool := newSeed(t)
	p := s.project("order/app", "", nil)
	d1, c1, d2 := s.scan(p.ID, "deps"), s.scan(p.ID, "code"), s.scan(p.ID, "deps")
	// Same millisecond: the later id wins.
	if _, err := pool.Exec(`UPDATE scans SET created_at = '2026-11-22 10:00:00.000+00:00'`); err != nil {
		t.Fatal(err)
	}
	latest, err := s.q.LatestScanPerKind(s.ctx, p.ID)
	if err != nil || len(latest) != 2 || latest[0].ID != c1.ID || latest[1].ID != d2.ID {
		t.Errorf("latest per kind: %+v %v", latest, err)
	}
	page1, _ := s.q.ListProjectScans(s.ctx, dbq.ListProjectScansParams{ProjectID: p.ID, Limit: 2})
	page2, _ := s.q.ListProjectScans(s.ctx, dbq.ListProjectScansParams{ProjectID: p.ID, Limit: 2, Offset: 2})
	if len(page1) != 2 || len(page2) != 1 || page1[0].ID != d2.ID || page1[1].ID != c1.ID || page2[0].ID != d1.ID {
		t.Errorf("scan pages: %v %v", page1, page2)
	}
	for _, sc := range []dbq.Scan{d1, d2} {
		if err := s.q.FinishScan(s.ctx, dbq.FinishScanParams{ID: sc.ID, Status: "succeeded"}); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.q.LatestSucceededScan(s.ctx, dbq.LatestSucceededScanParams{ProjectID: p.ID, Kind: "deps"}); err != nil || got.ID != d2.ID {
		t.Errorf("latest succeeded: %d %v", got.ID, err)
	}
	kind := "code"
	if only, _ := s.q.ListProjectScans(s.ctx, dbq.ListProjectScansParams{ProjectID: p.ID, Kind: &kind, Limit: 10}); len(only) != 1 {
		t.Errorf("kind filter: %v", only)
	}
}

// GlobalTrend carries each project's last snapshot forward, day by day, in the local calendar.
func TestDBGlobalTrend(t *testing.T) {
	s, _, pool := newSeed(t)
	a, b := s.project("trend/a", "", nil), s.project("trend/b", "", nil)
	for _, r := range []struct {
		id             int64
		ago, crit, hig int
	}{{a.ID, 5, 2, 0}, {a.ID, 2, 1, 0}, {b.ID, 3, 0, 4}, {b.ID, 30, 7, 7}} {
		if _, err := pool.Exec(`INSERT INTO metric_snapshots (project_id, day, vulns_critical, vulns_high) VALUES (?, date('now', 'localtime', ?), ?, ?)`,
			r.id, "-"+strconv.Itoa(r.ago)+" days", r.crit, r.hig); err != nil {
			t.Fatal(err)
		}
	}
	tr, err := s.q.GlobalTrend(s.ctx, time.Now().AddDate(0, 0, -6))
	if err != nil || len(tr) != 7 {
		t.Fatalf("trend: %d rows %v", len(tr), err)
	}
	// Day -6..0. b's 30-day-old snapshot (7/7) holds until day -3.
	wantCrit := []int32{7, 9, 9, 2, 1, 1, 1}
	wantHigh := []int32{7, 7, 7, 4, 4, 4, 4}
	today := time.Now().Format(time.DateOnly)
	for i, r := range tr {
		if r.VulnsCritical != wantCrit[i] || r.VulnsHigh != wantHigh[i] {
			t.Errorf("day %d: critical %d high %d, want %d %d", i-6, r.VulnsCritical, r.VulnsHigh, wantCrit[i], wantHigh[i])
		}
	}
	if d, ok := tr[6].Day.(time.Time); !ok || d.Format(time.DateOnly) != today {
		t.Errorf("last day %v (%T), want %s", tr[6].Day, tr[6].Day, today)
	}
	rows, err := s.q.ProjectTrend(s.ctx, dbq.ProjectTrendParams{ProjectID: a.ID, Day: time.Now().AddDate(0, 0, -5)})
	if err != nil || len(rows) != 2 {
		t.Errorf("project trend: %v %v", rows, err)
	}
	if n, err := s.q.DeleteOldSnapshots(s.ctx, time.Now().AddDate(0, 0, -5)); err != nil || n != 1 {
		t.Errorf("delete old snapshots: %d %v", n, err)
	}
}

func TestDBListProjects(t *testing.T) {
	s, _, _ := newSeed(t)
	a, b, c := s.project("b-app", "", nil), s.project("a-app", "", nil), s.project("c-App", "", nil)
	s.project("b-app", "/ws", &a.ID)
	sc := s.scan(a.ID, "deps")
	pk := s.pkg(sc.ID, "x", "1.0.0")
	s.finding(a, sc.ID, pk, "GHSA-crit", "critical", "open", 9)
	s.finding(a, sc.ID, pk, "GHSA-high", "high", "fixed", 5)
	old := s.scan(a.ID, "deps") // findings of an older scan don't count
	s.finding(a, old.ID, s.pkg(old.ID, "x", "1.0.0"), "GHSA-low", "low", "open", 1)
	s.current(a, sc.ID, 10)
	s.current(b, s.scan(b.ID, "deps").ID, 50)

	roots := true
	ids := func(sort string, search *string, limit int32) ([]int64, int64) {
		t.Helper()
		rows, err := s.q.ListProjects(s.ctx, dbq.ListProjectsParams{Sort: sort, Search: search, RootsOnly: &roots, Limit: limit})
		if err != nil {
			t.Fatal(err)
		}
		var out []int64
		var total int64
		for _, r := range rows {
			out = append(out, r.ID)
			total = r.Total
			if r.ID == a.ID && (r.VulnsCritical != 1 || r.VulnsHigh != 0 || r.VulnsLow != 0) {
				t.Errorf("counts of a: %+v", r)
			}
		}
		return out, total
	}
	if got, _ := ids("risk", nil, 10); !equal(got, []int64{b.ID, a.ID, c.ID}) {
		t.Errorf("risk sort: %v", got)
	}
	if got, _ := ids("path", nil, 10); !equal(got, []int64{b.ID, a.ID, c.ID}) {
		t.Errorf("path sort: %v", got)
	}
	search := "APP"
	if got, total := ids("path", &search, 1); !equal(got, []int64{b.ID}) || total != 3 {
		t.Errorf("search + limit: %v total %d", got, total)
	}
	all, _ := s.q.ListProjects(s.ctx, dbq.ListProjectsParams{Limit: 10})
	ws, _ := s.q.ListProjects(s.ctx, dbq.ListProjectsParams{ParentID: &a.ID, Limit: 10})
	if len(all) != 4 || len(ws) != 1 {
		t.Errorf("all %d, workspaces %d", len(all), len(ws))
	}
}

func equal(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDBSearchPackagesWorstSeverity(t *testing.T) {
	s, a, _ := newSeed(t)
	p := s.project("pkgs/app", "", nil)
	sc := s.scan(p.ID, "deps")
	ab := s.pkg(sc.ID, "a_b", "1.0.0")
	s.pkg(sc.ID, "axb", "1.0.0")
	s.finding(p, sc.ID, ab, "GHSA-1", "high", "open", 5)
	s.finding(p, sc.ID, ab, "GHSA-2", "critical", "open", 9)
	s.finding(p, sc.ID, ab, "GHSA-3", "low", "fixed", 1)
	s.current(p, sc.ID, 1)

	res, err := a.SearchPackages(s.ctx, "A_B") // "_" is literal, case is ignored
	if err != nil || len(res.Items) != 1 {
		t.Fatalf("search: %+v %v", res, err)
	}
	if h := res.Items[0]; h.Name != "a_b" || h.OpenVulns != 2 || h.WorstSeverity != "critical" {
		t.Errorf("hit: %+v", h)
	}
	if res, _ := a.SearchPackages(s.ctx, "axb@1.0.0"); len(res.Items) != 1 || res.Items[0].OpenVulns != 0 || res.Items[0].WorstSeverity != "" {
		t.Errorf("exact search: %+v", res)
	}
	if res, _ := a.SearchPackages(s.ctx, "axb@2.0.0"); len(res.Items) != 0 {
		t.Errorf("version filter: %+v", res)
	}
}

func TestDBListFindingsFilters(t *testing.T) {
	s, _, _ := newSeed(t)
	p := s.project("find/app", "", nil)
	sc := s.scan(p.ID, "deps")
	express := s.pkg(sc.ID, "Express", "4.0.0")
	qs := s.pkg(sc.ID, "qs", "6.0.0")
	f1 := s.finding(p, sc.ID, express, "GHSA-aaaa", "critical", "open", 5, "CVE-2099-0001")
	f2 := s.finding(p, sc.ID, qs, "GHSA-bbbb", "high", "open", 5)
	old := s.scan(p.ID, "deps") // fixed findings live in older scans
	s.finding(p, old.ID, s.pkg(old.ID, "qs", "6.0.0"), "GHSA-cccc", "low", "fixed", 5)
	s.current(p, sc.ID, 1)

	list := func(f dbq.ListFindingsParams) []int64 {
		t.Helper()
		f.ProjectID = &p.ID
		if f.Limit == 0 {
			f.Limit = 10
		}
		rows, err := s.q.ListFindings(s.ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []int64
		for _, r := range rows {
			out = append(out, r.ID)
		}
		return out
	}
	if got := list(dbq.ListFindingsParams{}); !equal(got, []int64{f1.ID, f2.ID}) {
		t.Errorf("no filter: %v", got)
	}
	if got := list(dbq.ListFindingsParams{Severities: sqltypes.Strings{}}); len(got) != 2 {
		t.Errorf("empty severities filter nothing: %v", got)
	}
	if got := list(dbq.ListFindingsParams{Severities: sqltypes.Strings{"high", "low"}}); !equal(got, []int64{f2.ID}) {
		t.Errorf("severities: %v", got)
	}
	for search, want := range map[string][]int64{"CVE-2099-0001": {f1.ID}, "xPRe": {f1.ID}, "bbbb": {f2.ID}, "CVE-2099": nil} {
		if got := list(dbq.ListFindingsParams{Search: &search}); !equal(got, want) {
			t.Errorf("search %q: %v", search, got)
		}
	}
	yes := true
	if got := list(dbq.ListFindingsParams{Direct: &yes}); len(got) != 0 {
		t.Errorf("direct filter: %v", got)
	}
	fixed := "fixed"
	if got := list(dbq.ListFindingsParams{Status: &fixed}); len(got) != 1 {
		t.Errorf("fixed: %v", got)
	}
	// Equal priorities: pages follow the id.
	if a, b := list(dbq.ListFindingsParams{Limit: 1}), list(dbq.ListFindingsParams{Limit: 1, Offset: 1}); !equal(a, []int64{f1.ID}) || !equal(b, []int64{f2.ID}) {
		t.Errorf("pages: %v %v", a, b)
	}
	if fx, err := s.q.ListFixableFindings(s.ctx, nil); err != nil || len(fx) != 0 {
		t.Errorf("fixable with no project: %v %v", fx, err)
	}
	if err := s.q.MarkFindingsFixed(s.ctx, nil); err != nil {
		t.Errorf("mark none fixed: %v", err)
	}
}

// The policies conflict target is an expression index: COALESCE(project_id, 0).
func TestDBUpsertPolicy(t *testing.T) {
	s, _, pool := newSeed(t)
	p := s.project("pol/app", "", nil)
	for range 2 {
		if _, err := s.q.UpsertPolicy(s.ctx, dbq.UpsertPolicyParams{Scope: "global", Rules: sqltypes.JSON(`{"a":1}`)}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.q.UpsertPolicy(s.ctx, dbq.UpsertPolicyParams{Scope: "project", ProjectID: &p.ID, Rules: sqltypes.JSON(`{"b":2}`)}); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := pool.QueryRow(`SELECT count(*) FROM policies`).Scan(&n); err != nil || n != 2 {
		t.Errorf("policies: %d %v", n, err)
	}
	if pol, err := s.q.GetPolicy(s.ctx, dbq.GetPolicyParams{Scope: "global"}); err != nil || string(pol.Rules) != `{"a":1}` {
		t.Errorf("global policy: %s %v", pol.Rules, err)
	}
	if pol, err := s.q.GetPolicy(s.ctx, dbq.GetPolicyParams{Scope: "project", ProjectID: &p.ID}); err != nil || string(pol.Rules) != `{"b":2}` {
		t.Errorf("project policy: %s %v", pol.Rules, err)
	}
}

// Writers share one SQLite lock: concurrent enqueues must wait (busy_timeout), not fail, and
// only one active scan per kind may exist. River's unique jobs must hold on SQLite too.
func TestDBConcurrentEnqueue(t *testing.T) {
	s, a, pool := newSeed(t)
	p := s.project("conc/app", "", nil)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 16 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := a.EnqueueScan(s.ctx, p.ID, "deps", "manual")
			errs <- err
		}()
		go func() {
			defer wg.Done()
			_, err := a.river.Insert(s.ctx, RecomputeArgs{ProjectID: p.ID}, nil)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && err != ErrScanInProgress {
			t.Errorf("enqueue: %v", err)
		}
	}
	var scans, jobs int
	if err := pool.QueryRow(`SELECT (SELECT count(*) FROM scans), (SELECT count(*) FROM river_job WHERE kind = 'recompute_priorities')`).Scan(&scans, &jobs); err != nil {
		t.Fatal(err)
	}
	if scans != 1 || jobs != 1 {
		t.Errorf("scans %d, recompute jobs %d: want 1 and 1", scans, jobs)
	}
}

// Cutoffs are Go times compared with SQL-written created_at text.
func TestDBRetentionCutoffs(t *testing.T) {
	s, a, pool := newSeed(t)
	p := s.project("ret/app", "", nil)
	old, cur, fresh := s.scan(p.ID, "deps"), s.scan(p.ID, "deps"), s.scan(p.ID, "code")
	s.current(p, cur.ID, 0)
	if _, err := pool.Exec(`UPDATE scans SET created_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now', '-200 days') WHERE id IN (?, ?)`, old.ID, cur.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := s.q.MarkStaleScansFailed(s.ctx, time.Now().Add(-staleScanAfter)); err != nil || n != 2 {
		t.Errorf("stale scans: %d %v", n, err)
	}
	if got, _ := s.q.GetScan(s.ctx, fresh.ID); got.Status != "queued" {
		t.Errorf("fresh scan: %s", got.Status)
	}
	if err := a.retention(s.ctx); err != nil {
		t.Fatal(err)
	}
	var ids []int64
	rows, _ := pool.Query(`SELECT id FROM scans ORDER BY id`)
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	if !equal(ids, []int64{cur.ID, fresh.ID}) {
		t.Errorf("scans after retention: %v", ids)
	}
}
