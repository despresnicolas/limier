package app

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/riverqueue/river"

	"limier/internal/db/dbq"
	"limier/internal/policy"
)

// EnqueueScan creates a queued scan and its job. For workspaces of a monorepo, the parent repository is scanned.
func (a *App) EnqueueScan(ctx context.Context, projectID int64, kind, trigger string) (*dbq.Scan, error) {
	p, err := a.rootProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if kind != "code" && kind != "deps" {
		return nil, fmt.Errorf("%w: unknown scan kind %q", ErrInvalid, kind)
	}

	var scan dbq.Scan
	// Checked in the transaction: it holds the SQLite write lock, so two clicks can't both create a scan.
	err = a.inTx(ctx, func(q *dbq.Queries, tx *sql.Tx) error {
		active, err := q.HasActiveScan(ctx, dbq.HasActiveScanParams{ProjectID: p.ID, Kind: kind})
		if err != nil {
			return err
		}
		if active {
			return ErrScanInProgress
		}
		scan, err = q.CreateScan(ctx, dbq.CreateScanParams{ProjectID: p.ID, Kind: kind, Trigger: trigger})
		if err != nil {
			return err
		}
		_, err = a.river.InsertTx(ctx, tx, scanArgs(scan), nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

func scanArgs(s dbq.Scan) river.JobArgs {
	if s.Kind == "code" {
		return ScanCodeArgs{ScanID: s.ID}
	}
	return ScanDepsArgs{ScanID: s.ID}
}

// enqueueQuiet enqueues scans triggered by events, ignoring "already in progress".
func (a *App) enqueueQuiet(ctx context.Context, projectID int64, kind, trigger string) {
	if _, err := a.EnqueueScan(ctx, projectID, kind, trigger); err != nil && err != ErrScanInProgress {
		a.log.WarnContext(ctx, "enqueue scan", "project_id", projectID, "kind", kind, "err", err)
	}
}

func (a *App) EnqueueRecompute(ctx context.Context, projectID int64) error {
	_, err := a.river.Insert(ctx, RecomputeArgs{ProjectID: projectID}, nil)
	return err
}

// EffectiveRules merges global and project policies.
func (a *App) EffectiveRules(ctx context.Context, projectID int64) policy.Rules {
	var g, p policy.Rules
	if pol, err := a.q.GetPolicy(ctx, dbq.GetPolicyParams{Scope: "global"}); err == nil {
		g, _ = policy.ParseRules(pol.Rules)
	}
	if projectID != 0 {
		if pol, err := a.q.GetPolicy(ctx, dbq.GetPolicyParams{Scope: "project", ProjectID: &projectID}); err == nil {
			p, _ = policy.ParseRules(pol.Rules)
		}
	}
	return policy.Effective(g, p)
}
