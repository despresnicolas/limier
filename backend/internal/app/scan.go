package app

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/riverqueue/river"

	"limier/internal/db/dbq"
	"limier/internal/runner"
)

// runScan wraps a scan job: status transitions and retry bookkeeping.
// The scan is marked failed only on the last attempt; earlier failures leave it queued for the retry.
func runScan[T river.JobArgs](ctx context.Context, a *App, job *river.Job[T], scanID int64, fn func(context.Context, dbq.Scan) error) error {
	scan, err := a.q.GetScan(ctx, scanID)
	if isNoRows(err) {
		return river.JobCancel(fmt.Errorf("scan %d no longer exists", scanID))
	}
	if err != nil {
		return err
	}
	if scan.Status == "succeeded" {
		return nil
	}
	if err := a.q.StartScan(ctx, scan.ID); err != nil {
		return err
	}
	err = fn(ctx, scan)

	status, msg := "succeeded", ""
	if err != nil {
		msg = truncate(err.Error(), 2000)
		status = "failed"
		if job.Attempt < job.MaxAttempts && !isPermanent(err) {
			status = "queued"
		}
	}
	// Use a fresh context: the job context may be cancelled on timeout.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if ferr := a.q.FinishScan(fctx, dbq.FinishScanParams{ID: scan.ID, Status: status, Error: msg}); ferr != nil {
		a.log.ErrorContext(ctx, "finish scan", "scan_id", scan.ID, "err", ferr)
	}
	if err != nil {
		a.log.WarnContext(ctx, "scan failed", "scan_id", scan.ID, "kind", scan.Kind, "attempt", job.Attempt, "err", err)
		if isPermanent(err) {
			return river.JobCancel(err)
		}
	}
	return err
}

// errPermanent marks failures that retrying cannot fix.
var errPermanent = errors.New("permanent failure")

// isPermanent also covers an unreachable Docker socket: retries would only keep the scan queued for minutes.
// shortcut: Docker-specific, drop the syscall checks when PLAN steps 1–4 remove the runner.
func isPermanent(err error) bool {
	return errors.Is(err, errPermanent) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT)
}

func permanent(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errPermanent, fmt.Sprintf(format, args...))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func pipelineID(kind string, scanID int64) string {
	return "limier-" + kind + "-" + strconv.FormatInt(scanID, 10) + "-" + strconv.FormatInt(time.Now().Unix()%100000, 10)
}

// runPipeline runs p and reports step failures with their stderr tail.
func (a *App) runPipeline(ctx context.Context, p runner.Pipeline) (*runner.Result, error) {
	res, err := a.runner.Run(ctx, p)
	if res != nil {
		for _, s := range res.Steps {
			if s.ExitCode != 0 {
				a.log.InfoContext(ctx, "pipeline step exited non-zero", "pipeline", p.ID, "step", s.Name,
					"exit_code", s.ExitCode, "stderr", truncate(strings.TrimSpace(string(s.Stderr)), 500))
			}
		}
	}
	return res, err
}
