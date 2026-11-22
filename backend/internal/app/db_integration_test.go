package app

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"limier/internal/config"
	"limier/internal/db"
	"limier/internal/db/dbq"
	"limier/internal/scanners"
)

// Exercises findings processing against a real SQLite database in a temporary file.
func dbApp(t *testing.T) (*App, *sql.DB) {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, filepath.Join(t.TempDir(), "limier.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	a, err := New(ctx, cfg, pool, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return a, pool
}

func osvRecord(t *testing.T, raw string) scanners.OSVVuln {
	t.Helper()
	v, err := scanners.ParseOSVVuln([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

const qsVuln = `{"id":"GHSA-hrpp-h998-j3pp","aliases":["CVE-2022-24999"],"summary":"qs prototype pollution",
 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
 "affected":[{"package":{"ecosystem":"npm","name":"qs"},"ranges":[{"type":"SEMVER","events":[{"introduced":"6.7.0"},{"fixed":"6.7.3"}]}]}]}`

const expressVuln = `{"id":"GHSA-test-crit-0001","aliases":["CVE-2099-0001"],"summary":"express critical",
 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
 "affected":[{"package":{"ecosystem":"npm","name":"express"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.20.0"}]}]}]}`

func TestDBFindingsLifecycle(t *testing.T) {
	a, pool := dbApp(t)
	ctx := context.Background()
	q := a.q

	p, err := q.UpsertLocalProject(ctx, dbq.UpsertLocalProjectParams{LocalPath: "grp/app", Path: "grp/app", PackageManager: "npm"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO kev_entries (cve_id) VALUES ('CVE-2099-0001')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO epss_scores (cve_id, score, percentile) VALUES ('CVE-2022-24999', 0.5, 0.9)`); err != nil {
		t.Fatal(err)
	}

	pkgs := func() map[string]*pkgRef {
		return map[string]*pkgRef{
			"express@4.17.1": {Ecosystem: "npm", Name: "express", Version: "4.17.1", Direct: true, Path: []string{"express"}},
			"qs@6.7.0":       {Ecosystem: "npm", Name: "qs", Version: "6.7.0", Path: []string{"express", "qs"}},
		}
	}
	scan := func(vulns map[string][]scanners.OSVVuln) dbq.Scan {
		t.Helper()
		s, err := q.CreateScan(ctx, dbq.CreateScanParams{ProjectID: p.ID, Kind: "deps", Trigger: "manual"})
		if err != nil {
			t.Fatal(err)
		}
		p, _ = q.GetProject(ctx, p.ID)
		if err := a.processDeps(ctx, p, s, pkgs(), vulns); err != nil {
			t.Fatal(err)
		}
		p, _ = q.GetProject(ctx, p.ID)
		return s
	}
	current := func() map[string]dbq.ListFindingsRow {
		rows, err := q.ListFindings(ctx, dbq.ListFindingsParams{ProjectID: &p.ID, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]dbq.ListFindingsRow{}
		for _, r := range rows {
			out[r.PackageName] = r
		}
		return out
	}

	both := map[string][]scanners.OSVVuln{
		"express@4.17.1": {osvRecord(t, expressVuln)},
		"qs@6.7.0":       {osvRecord(t, qsVuln)},
	}

	// Scan 1: two open findings, enriched and scored.
	s1 := scan(both)
	f := current()
	if len(f) != 2 {
		t.Fatalf("want 2 findings, got %d", len(f))
	}
	ex, qs := f["express"], f["qs"]
	if !ex.InKev || ex.Severity != "critical" || ex.Priority != 73.8 || ex.FixedVersion != "4.20.0" || !ex.Direct {
		t.Errorf("express finding: kev=%v sev=%s prio=%v fixed=%s", ex.InKev, ex.Severity, ex.Priority, ex.FixedVersion)
	}
	// cvss 5.9*6 + 0.5*25 = 47.9, transitive *0.8 = 38.3
	if qs.Priority != 38.3 || qs.FixedVersion != "6.7.3" || qs.Direct || qs.EpssScore == nil {
		t.Errorf("qs finding: prio=%v fixed=%s direct=%v", qs.Priority, qs.FixedVersion, qs.Direct)
	}
	if p.RiskScore <= 0 || p.LastDepsScanID == nil || *p.LastDepsScanID != s1.ID {
		t.Errorf("project not updated: risk=%v last=%v", p.RiskScore, p.LastDepsScanID)
	}
	if snap, err := q.LatestSnapshot(ctx, p.ID); err != nil || snap.VulnsCritical != 1 || snap.VulnsMedium != 1 {
		t.Errorf("snapshot: %+v %v", snap, err)
	}
	// Rescan: first_seen is preserved.
	scan(both)
	f = current()
	if f["qs"].Status != "open" || !f["qs"].FirstSeenAt.Equal(qs.FirstSeenAt) {
		t.Errorf("first_seen not preserved: %+v", f["qs"])
	}
	if f["express"].ID == ex.ID {
		t.Error("expected a new finding row for the new scan")
	}

	// Scan 3: express vulnerability gone => previous finding fixed.
	prevExpress := f["express"].ID
	scan(map[string][]scanners.OSVVuln{"qs@6.7.0": {osvRecord(t, qsVuln)}})
	f = current()
	if _, ok := f["express"]; ok || len(f) != 1 {
		t.Errorf("express should be gone from current findings: %v", f)
	}
	fixed := "fixed"
	rows, _ := q.ListFindings(ctx, dbq.ListFindingsParams{ProjectID: &p.ID, Status: &fixed, Limit: 10})
	found := false
	for _, r := range rows {
		found = found || r.ID == prevExpress
	}
	if !found {
		t.Error("previous express finding not marked fixed")
	}

	// Dashboard queries run.
	if c, err := q.DashboardCounts(ctx); err != nil || c != 1 {
		t.Errorf("dashboard counts: %+v %v", c, err)
	}
	if tr, err := q.GlobalTrend(ctx, time.Now().AddDate(0, 0, -90)); err != nil || len(tr) != 91 {
		t.Errorf("global trend: %d rows %v", len(tr), err)
	}
	if err := a.retention(ctx); err != nil {
		t.Errorf("retention: %v", err)
	}
}
