// Package app holds Limier business logic: job enqueueing, scan pipelines, findings processing,
// local fixes and maintenance. HTTP handlers and River workers both call it.
package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riversqlite"
	"github.com/robfig/cron/v3"

	"limier/internal/config"
	"limier/internal/db/dbq"
	"limier/internal/runner"
	"limier/internal/storage"
	"limier/internal/vulndb"
)

type App struct {
	cfg    config.Config
	pool   *sql.DB
	q      *dbq.Queries
	river  *river.Client[*sql.Tx]
	runner runner.Runner
	vuln   *vulndb.Client
	store  storage.Store
	log    *slog.Logger
	// openURL hands a URL to the desktop (editor links); nil outside the app.
	openURL func(string) error
	// notify shows a desktop notification; nil outside the app.
	notify func(title, body string) error
	// releases caches vulndb.PackageInfo.ReleasedAt per package name (filled by deps scans and
	// local fix proposals) for the minimum release age of fix targets.
	releases sync.Map
	// parentBumps caches vulndb.ParentBump answers ("" when no parent version fixes the child).
	// shortcut: kept until restart, so a parent release that fixes the child later is seen after a
	// restart; key it by day if users miss such bumps.
	parentBumps sync.Map
}

type Options struct {
	// Worker enables job processing and periodic jobs. The API process only inserts jobs.
	Worker bool
	// OpenURL opens a URL with the desktop (editor links).
	OpenURL func(string) error
	// Notify shows a desktop notification (new vulnerabilities found by recheck_vulns).
	Notify func(title, body string) error
}

func New(ctx context.Context, cfg config.Config, pool *sql.DB, opts Options) (*App, error) {
	q := dbq.New(pool)
	a := &App{
		cfg:     cfg,
		pool:    pool,
		q:       q,
		vuln:    vulndb.New(vulndb.Endpoints{}, nil),
		store:   storage.New(q),
		log:     slog.Default(),
		openURL: opts.OpenURL,
		notify:  opts.Notify,
	}

	var err error
	rcfg := &river.Config{Workers: a.workers(), Logger: slog.Default()}
	if opts.Worker {
		if a.runner, err = runner.NewDocker(runner.DockerConfig{Host: cfg.DockerHost}); err != nil {
			return nil, err
		}
		rcfg.Queues = map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: cfg.WorkerConcurrency}}
		rcfg.PeriodicJobs = periodicJobs()
		rcfg.JobTimeout = 30 * time.Minute
	}
	if a.river, err = river.NewClient(riversqlite.New(pool), rcfg); err != nil {
		return nil, fmt.Errorf("river client: %w", err)
	}
	return a, nil
}

// Start begins job processing (worker mode only).
func (a *App) Start(ctx context.Context) error { return a.river.Start(ctx) }

func (a *App) Stop(ctx context.Context) error { return a.river.Stop(ctx) }

func (a *App) Queries() *dbq.Queries { return a.q }

func (a *App) Config() config.Config { return a.cfg }

func (a *App) Store() storage.Store { return a.store }

// cronSchedule adapts a cron expression to River's PeriodicSchedule.
func cronSchedule(expr string) river.PeriodicSchedule {
	s, err := cron.ParseStandard(expr)
	if err != nil {
		panic(err)
	}
	return s
}

func periodicJobs() []*river.PeriodicJob {
	job := func(sched river.PeriodicSchedule, args river.JobArgs, runOnStart bool) *river.PeriodicJob {
		return river.NewPeriodicJob(sched, func() (river.JobArgs, *river.InsertOpts) { return args, nil },
			&river.PeriodicJobOpts{RunOnStart: runOnStart})
	}
	return []*river.PeriodicJob{
		job(river.PeriodicInterval(6*time.Hour), RefreshVulnDBArgs{}, true),
		job(river.PeriodicInterval(time.Hour), MaintenanceArgs{Task: "stale_scans"}, true),
		job(cronSchedule("30 4 * * *"), MaintenanceArgs{Task: "retention"}, false),
	}
}

// worker adapts a function to river.Worker with a per-kind timeout.
type worker[T river.JobArgs] struct {
	river.WorkerDefaults[T]
	timeout time.Duration
	fn      func(context.Context, *river.Job[T]) error
}

func (w *worker[T]) Work(ctx context.Context, job *river.Job[T]) error { return w.fn(ctx, job) }
func (w *worker[T]) Timeout(*river.Job[T]) time.Duration               { return w.timeout }

func addWorker[T river.JobArgs](ws *river.Workers, timeout time.Duration, fn func(context.Context, *river.Job[T]) error) {
	river.AddWorker(ws, &worker[T]{timeout: timeout, fn: fn})
}

func (a *App) workers() *river.Workers {
	ws := river.NewWorkers()
	addWorker(ws, 15*time.Minute, a.workScanCode)
	addWorker(ws, 10*time.Minute, a.workScanDeps)
	addWorker(ws, 10*time.Minute, a.workLocalFix)
	addWorker(ws, 30*time.Minute, a.workRefreshVulnDB)
	addWorker(ws, 10*time.Minute, a.workMaintenance)
	addWorker(ws, 10*time.Minute, a.workRecompute)
	addWorker(ws, 30*time.Minute, a.workRecheckVulns)
	return ws
}

// inTx runs fn in a transaction with queries bound to it.
func (a *App) inTx(ctx context.Context, fn func(q *dbq.Queries, tx *sql.Tx) error) error {
	tx, err := a.pool.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after Commit
	if err := fn(a.q.WithTx(tx), tx); err != nil {
		return err
	}
	return tx.Commit()
}

// rootProject returns the monorepo parent of a workspace, or the project itself.
func (a *App) rootProject(ctx context.Context, id int64) (dbq.Project, error) {
	p, err := a.q.GetProject(ctx, id)
	if err != nil {
		return p, err
	}
	if p.ParentID != nil {
		return a.q.GetProject(ctx, *p.ParentID)
	}
	return p, nil
}

var (
	ErrScanInProgress = errors.New("a scan of this kind is already queued or running")
	ErrNotFound       = errors.New("not found")
	ErrInvalid        = errors.New("invalid request")
)

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
