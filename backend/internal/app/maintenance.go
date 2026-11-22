package app

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"limier/internal/db/dbq"
	"limier/internal/vulndb"
)

// Retention periods (SPECS §9).
const (
	scanRetention     = 180 * 24 * time.Hour
	snapshotRetention = 2 * 365 * 24 * time.Hour
	// Scans still queued or running after this are considered lost (worker crash).
	staleScanAfter = 2 * time.Hour
)

func (a *App) workMaintenance(ctx context.Context, job *river.Job[MaintenanceArgs]) error {
	switch job.Args.Task {
	case "stale_scans":
		return a.failStaleScans(ctx)
	case "retention":
		return a.retention(ctx)
	}
	return river.JobCancel(fmt.Errorf("unknown maintenance task %q", job.Args.Task))
}

// failStaleScans marks scans stuck in queued or running as failed.
func (a *App) failStaleScans(ctx context.Context) error {
	if n, err := a.q.MarkStaleScansFailed(ctx, time.Now().Add(-staleScanAfter)); err == nil && n > 0 {
		a.log.WarnContext(ctx, "stale scans marked failed", "count", n)
	}
	return nil
}

func (a *App) retention(ctx context.Context) error {
	now := time.Now()
	scans, err := a.q.DeleteOldScans(ctx, now.Add(-scanRetention))
	if err != nil {
		return err
	}
	blobs, err := a.q.DeleteOrphanSBOMBlobs(ctx)
	if err != nil {
		return err
	}
	snaps, err := a.q.DeleteOldSnapshots(ctx, now.Add(-snapshotRetention))
	if err != nil {
		return err
	}
	a.log.InfoContext(ctx, "retention applied", "scans", scans, "sbom_blobs", blobs, "snapshots", snaps)
	return nil
}

func (a *App) workRecompute(ctx context.Context, job *river.Job[RecomputeArgs]) error {
	if job.Args.ProjectID != 0 {
		p, err := a.q.GetProject(ctx, job.Args.ProjectID)
		if isNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return a.recomputeProject(ctx, p)
	}
	projects, err := a.q.ListRootProjects(ctx)
	if err != nil {
		return err
	}
	for _, p := range projects {
		if err := a.recomputeProject(ctx, p); err != nil {
			return fmt.Errorf("project %d: %w", p.ID, err)
		}
	}
	return nil
}

// workRefreshVulnDB refreshes CISA KEV and EPSS, propagates them to known vulnerabilities and re-scores findings.
func (a *App) workRefreshVulnDB(ctx context.Context, _ *river.Job[RefreshVulnDBArgs]) error {
	kev, err := a.vuln.FetchKEV(ctx)
	if err != nil {
		return fmt.Errorf("kev: %w", err)
	}
	err = a.inTx(ctx, func(q *dbq.Queries, _ *sql.Tx) error {
		for _, e := range kev {
			d := e.DateAdded
			if err := q.UpsertKEV(ctx, dbq.UpsertKEVParams{CveID: e.CVE, DateAdded: &d, Ransomware: e.Ransomware}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := a.loadEPSS(ctx); err != nil {
		return fmt.Errorf("epss: %w", err)
	}
	n, err := a.q.RefreshVulnEnrichment(ctx)
	if err != nil {
		return err
	}
	a.log.InfoContext(ctx, "vulnerability data refreshed", "kev", len(kev), "vulnerabilities", n)
	if _, err := a.river.Insert(ctx, RecomputeArgs{}, nil); err != nil {
		return err
	}
	// Every 6 h, and at each start: new advisories are priced with fresh KEV and EPSS data.
	_, err = a.river.Insert(ctx, RecheckVulnsArgs{}, nil)
	return err
}

// loadEPSS reads the EPSS feed (~300k rows, ~20 MB in memory) then upserts it in one transaction.
// Reading first keeps the SQLite write lock for the inserts only, not for the download.
func (a *App) loadEPSS(ctx context.Context) error {
	var scores []vulndb.EPSSScore
	if err := a.vuln.FetchEPSS(ctx, func(s vulndb.EPSSScore) error {
		scores = append(scores, s)
		return nil
	}); err != nil {
		return err
	}
	return a.inTx(ctx, func(_ *dbq.Queries, tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO epss_scores (cve_id, score, percentile, updated_at)
			VALUES (?, ?, ?, strftime('%Y-%m-%d %H:%M:%f+00:00', 'now'))
			ON CONFLICT (cve_id) DO UPDATE SET score = excluded.score, percentile = excluded.percentile, updated_at = excluded.updated_at`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, s := range scores {
			if _, err := stmt.ExecContext(ctx, s.CVE, s.Score, s.Percentile); err != nil {
				return err
			}
		}
		return nil
	})
}
