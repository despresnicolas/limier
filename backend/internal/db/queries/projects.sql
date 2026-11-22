-- name: DeleteStaleWorkspaces :exec
DELETE FROM projects WHERE parent_id = @parent_id
  AND subdir NOT IN (SELECT value FROM json_each(CAST(@keep AS TEXT_LIST)));

-- name: GetProject :one
SELECT * FROM projects WHERE id = ?;

-- name: ListRootProjects :many
SELECT * FROM projects WHERE parent_id IS NULL ORDER BY id;

-- name: ListProjects :many
-- LIKE is case-insensitive for ASCII letters only.
SELECT p.*,
       count(*) OVER () AS total,
       CAST(COALESCE(s.critical, 0) AS INT) AS vulns_critical,
       CAST(COALESCE(s.high, 0) AS INT) AS vulns_high,
       CAST(COALESCE(s.medium, 0) AS INT) AS vulns_medium,
       CAST(COALESCE(s.low, 0) AS INT) AS vulns_low,
       EXISTS (SELECT 1 FROM scans sc WHERE sc.project_id IN (p.id, COALESCE(p.parent_id, p.id)) AND sc.status IN ('queued', 'running')) AS scanning
FROM projects p
LEFT JOIN (
    SELECT f.scan_id,
           count(*) FILTER (WHERE v.severity = 'critical') AS critical,
           count(*) FILTER (WHERE v.severity = 'high') AS high,
           count(*) FILTER (WHERE v.severity = 'medium') AS medium,
           count(*) FILTER (WHERE v.severity = 'low') AS low
    FROM findings f JOIN vulnerabilities v ON v.id = f.vulnerability_id
    WHERE f.status = 'open' AND f.scan_id IN (SELECT last_deps_scan_id FROM projects)
    GROUP BY f.scan_id
) s ON s.scan_id = p.last_deps_scan_id
-- sqlc leaves parameters in ORDER BY unbound: @sort comes in through this one-row join.
CROSS JOIN (SELECT CAST(@sort AS TEXT) AS sort) o
WHERE (CAST(sqlc.narg(search) AS TEXT) IS NULL OR p.path LIKE '%' || sqlc.narg(search) || '%')
  AND (CAST(sqlc.narg(parent_id) AS INTEGER) IS NULL OR p.parent_id = sqlc.narg(parent_id))
  AND (CAST(sqlc.narg(roots_only) AS BOOLEAN) IS NULL OR NOT sqlc.narg(roots_only) OR p.parent_id IS NULL)
ORDER BY
  CASE WHEN o.sort = 'risk' THEN p.risk_score END DESC,
  p.path
LIMIT CAST(sqlc.arg(limit) AS INT) OFFSET CAST(sqlc.arg(offset) AS INT);

-- name: SetProjectLastDepsScan :exec
UPDATE projects SET last_deps_scan_id = @last_deps_scan_id, risk_score = @risk_score,
    updated_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now') WHERE id = @id;

-- name: SetProjectLastCodeScan :exec
UPDATE projects SET last_code_scan_id = @last_code_scan_id, updated_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now') WHERE id = @id;

-- name: ListWorkspaces :many
SELECT * FROM projects WHERE parent_id = ? ORDER BY subdir;

-- name: GetPolicy :one
SELECT * FROM policies WHERE scope = @scope AND project_id IS sqlc.narg(project_id);

-- name: UpsertPolicy :one
INSERT INTO policies (scope, project_id, rules) VALUES (?, ?, ?)
ON CONFLICT (scope, COALESCE(project_id, 0)) DO UPDATE SET rules = excluded.rules, updated_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')
RETURNING *;

-- name: SetProjectRisk :exec
UPDATE projects SET risk_score = @risk_score, updated_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now') WHERE id = @id;

-- name: UpsertLocalProject :one
INSERT INTO projects (local_path, parent_id, path, subdir, package_manager)
VALUES (@local_path, sqlc.narg(parent_id), @path, @subdir, @package_manager)
ON CONFLICT (local_path, subdir) DO UPDATE
SET parent_id = excluded.parent_id, path = excluded.path, package_manager = excluded.package_manager,
    updated_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')
RETURNING *;

-- name: DeleteProject :execrows
DELETE FROM projects WHERE id = ?;

-- name: ListLocalPaths :many
SELECT local_path FROM projects WHERE parent_id IS NULL;

-- name: SetProjectBranchPrefix :exec
UPDATE projects SET branch_prefix = @branch_prefix, updated_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now') WHERE id = @id;
