-- name: UpsertSnapshot :exec
-- day is the local calendar day, like CURRENT_DATE on the old PostgreSQL.
INSERT INTO metric_snapshots (project_id, day, vulns_critical, vulns_high, vulns_medium, vulns_low,
                              loc, unused_deps, cycles, risk_score)
VALUES (@project_id, date('now', 'localtime'), @vulns_critical, @vulns_high, @vulns_medium, @vulns_low,
        @loc, @unused_deps, @cycles, @risk_score)
ON CONFLICT (project_id, day) DO UPDATE SET
    vulns_critical = excluded.vulns_critical, vulns_high = excluded.vulns_high,
    vulns_medium = excluded.vulns_medium, vulns_low = excluded.vulns_low,
    loc = COALESCE(excluded.loc, metric_snapshots.loc),
    unused_deps = COALESCE(excluded.unused_deps, metric_snapshots.unused_deps), cycles = COALESCE(excluded.cycles, metric_snapshots.cycles),
    risk_score = excluded.risk_score;

-- name: LatestSnapshot :one
SELECT * FROM metric_snapshots WHERE project_id = ? ORDER BY day DESC LIMIT 1;

-- name: ProjectTrend :many
-- @day is a time: its local calendar day is the first one returned.
SELECT * FROM metric_snapshots WHERE project_id = @project_id AND day >= date(@day, 'localtime') ORDER BY day;

-- name: GlobalTrend :many
-- Daily totals from the local day of @since to today; each project carries its last known snapshot forward.
WITH RECURSIVE days AS (
    SELECT date(@since, 'localtime') AS day
    UNION ALL
    SELECT date(day, '+1 day') FROM days WHERE day < date('now', 'localtime')
),
spans AS (
    SELECT ms.day, lead(ms.day) OVER (PARTITION BY ms.project_id ORDER BY ms.day) AS next_day,
           ms.vulns_critical, ms.vulns_high, ms.vulns_medium, ms.vulns_low
    FROM metric_snapshots ms
)
SELECT d.day,
       CAST(COALESCE(sum(s.vulns_critical), 0) AS INT) AS vulns_critical,
       CAST(COALESCE(sum(s.vulns_high), 0) AS INT) AS vulns_high,
       CAST(COALESCE(sum(s.vulns_medium), 0) AS INT) AS vulns_medium,
       CAST(COALESCE(sum(s.vulns_low), 0) AS INT) AS vulns_low
FROM days d
LEFT JOIN spans s ON s.day <= d.day AND (s.next_day IS NULL OR d.day < s.next_day)
GROUP BY d.day ORDER BY d.day;

-- name: DashboardCounts :one
SELECT CAST(count(*) AS INT) AS projects FROM projects WHERE parent_id IS NULL;

-- name: DashboardSeverityCounts :many
SELECT v.severity, CAST(count(*) AS INT) AS count, CAST(count(*) FILTER (WHERE v.in_kev) AS INT) AS in_kev,
       CAST(count(*) FILTER (WHERE v.malicious) AS INT) AS malicious
FROM findings f
JOIN projects p ON p.id = f.project_id AND f.scan_id = p.last_deps_scan_id
JOIN vulnerabilities v ON v.id = f.vulnerability_id
WHERE f.status = 'open'
GROUP BY v.severity;

-- name: TopRiskProjects :many
SELECT p.id, p.path, p.risk_score,
       EXISTS (SELECT 1 FROM scans sc WHERE sc.project_id IN (p.id, COALESCE(p.parent_id, p.id)) AND sc.status IN ('queued', 'running')) AS scanning
FROM projects p
WHERE p.parent_id IS NULL AND p.risk_score > 0 ORDER BY p.risk_score DESC LIMIT CAST(@limit AS INT);
