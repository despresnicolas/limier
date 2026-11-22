-- name: UpsertLocalFixDecision :one
INSERT INTO local_fixes (project_id, kind, manifest_dir, package_name, from_version, to_version, vulnerability_ids, status, branch, user_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (project_id, manifest_dir, package_name, to_version) DO UPDATE
SET kind = excluded.kind, from_version = excluded.from_version, vulnerability_ids = excluded.vulnerability_ids,
    status = excluded.status, branch = excluded.branch, user_id = excluded.user_id,
    base_commit = '', commit_sha = '', error = '', updated_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')
WHERE local_fixes.status IN ('failed', 'rejected')
RETURNING *;

-- name: GetLocalFix :one
SELECT * FROM local_fixes WHERE id = ?;

-- name: ListLocalFixes :many
SELECT * FROM local_fixes WHERE project_id = ? ORDER BY updated_at DESC, id DESC;

-- name: SetLocalFixRunning :exec
UPDATE local_fixes SET status = 'running', error = '', updated_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now') WHERE id = ?;

-- name: SetLocalFixResult :exec
UPDATE local_fixes SET status = @status, base_commit = @base_commit, commit_sha = @commit_sha, error = @error,
    updated_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now') WHERE id = @id;

-- name: DeleteLocalFix :execrows
DELETE FROM local_fixes WHERE id = ? AND project_id = ? AND status IN ('rejected', 'failed');

-- name: ListFixableFindings :many
SELECT f.project_id, f.direct, f.fixed_version, f.vulnerability_id, f.priority,
       v.severity, v.in_kev, v.malicious, p.name AS package_name, p.version AS package_version,
       CAST(COALESCE(sp.dev, 0) AS BOOLEAN) AS dev,
       CAST(COALESCE(sp.dependency_path, '[]') AS TEXT_LIST) AS dependency_path,
       CAST(COALESCE(sp.via, '[]') AS TEXT_LIST) AS via
FROM findings f
JOIN projects pr ON pr.id = f.project_id AND f.scan_id = pr.last_deps_scan_id
JOIN vulnerabilities v ON v.id = f.vulnerability_id
JOIN packages p ON p.id = f.package_id
LEFT JOIN scan_packages sp ON sp.scan_id = f.scan_id AND sp.package_id = f.package_id
WHERE f.project_id IN (sqlc.slice(project_ids)) AND f.status = 'open' AND f.fixed_version <> ''
ORDER BY f.priority DESC;
