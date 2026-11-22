package app

import (
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// Job kinds, timeouts and retries follow SPECS §8. MaxAttempts = retries + 1.

// pendingStates dedupes a job while an identical one waits or runs; completed jobs never block a new run.
var pendingStates = []rivertype.JobState{
	rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
	rivertype.JobStateRunning, rivertype.JobStateScheduled,
}

func uniqueOpts(attempts int) river.InsertOpts {
	return river.InsertOpts{MaxAttempts: attempts, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: pendingStates}}
}

type ScanCodeArgs struct {
	ScanID int64 `json:"scan_id"`
}

func (ScanCodeArgs) Kind() string                 { return "scan_code" }
func (ScanCodeArgs) InsertOpts() river.InsertOpts { return river.InsertOpts{MaxAttempts: 3} }

type ScanDepsArgs struct {
	ScanID int64 `json:"scan_id"`
}

func (ScanDepsArgs) Kind() string                 { return "scan_deps" }
func (ScanDepsArgs) InsertOpts() river.InsertOpts { return river.InsertOpts{MaxAttempts: 4} }

// LocalFixArgs applies an accepted fix to a local repository as a new branch.
type LocalFixArgs struct {
	FixID  int64 `json:"fix_id"`
	UserID int64 `json:"user_id,omitempty"`
}

func (LocalFixArgs) Kind() string                 { return "local_fix" }
func (LocalFixArgs) InsertOpts() river.InsertOpts { return uniqueOpts(1) }

type RefreshVulnDBArgs struct{}

func (RefreshVulnDBArgs) Kind() string                 { return "refresh_vuln_db" }
func (RefreshVulnDBArgs) InsertOpts() river.InsertOpts { return uniqueOpts(4) }

// RecheckVulnsArgs looks for vulnerabilities published since the last dependency scans (SPECS F3.8).
type RecheckVulnsArgs struct{}

func (RecheckVulnsArgs) Kind() string                 { return "recheck_vulns" }
func (RecheckVulnsArgs) InsertOpts() river.InsertOpts { return uniqueOpts(3) }

// MaintenanceArgs fails stale scans and applies retention.
type MaintenanceArgs struct {
	Task string `json:"task"` // "stale_scans" | "retention"
}

func (MaintenanceArgs) Kind() string                 { return "maintenance" }
func (MaintenanceArgs) InsertOpts() river.InsertOpts { return uniqueOpts(3) }

// RecomputeArgs recomputes priorities and risk scores after a policy or enrichment change.
type RecomputeArgs struct {
	ProjectID int64 `json:"project_id,omitempty"` // 0 => all projects
}

func (RecomputeArgs) Kind() string                 { return "recompute_priorities" }
func (RecomputeArgs) InsertOpts() river.InsertOpts { return uniqueOpts(3) }
