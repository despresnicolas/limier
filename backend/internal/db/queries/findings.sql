-- name: InsertFinding :one
INSERT INTO findings (scan_id, project_id, vulnerability_id, package_id, fixed_version, priority, reachable, direct, status, first_seen_at, is_new)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (scan_id, vulnerability_id, package_id) DO UPDATE SET fixed_version = excluded.fixed_version
RETURNING *;

-- name: ListScanFindingKeys :many
-- Findings of a scan with the package identity, used to diff consecutive scans.
SELECT f.id, f.vulnerability_id, f.status, f.first_seen_at, p.name AS package_name, p.version AS package_version
FROM findings f JOIN packages p ON p.id = f.package_id
WHERE f.scan_id = ?;

-- name: MarkFindingsFixed :exec
UPDATE findings SET status = 'fixed' WHERE id IN (sqlc.slice(ids));

-- name: GetFinding :one
SELECT f.*, v.aliases, v.summary, v.severity, v.cvss_score, v.cvss_vector, v.epss_score, v.in_kev, v.malicious, v.published_at, v.refs,
       p.ecosystem, p.name AS package_name, p.version AS package_version, p.purl,
       sp.dependency_path, sp.via, sp.dev
FROM findings f
JOIN vulnerabilities v ON v.id = f.vulnerability_id
JOIN packages p ON p.id = f.package_id
LEFT JOIN scan_packages sp ON sp.scan_id = f.scan_id AND sp.package_id = f.package_id
WHERE f.id = ?;

-- name: ListFindings :many
-- An empty @severities filters nothing. LIKE is case-insensitive for ASCII letters only.
SELECT f.*, v.aliases, v.summary, v.severity, v.cvss_score, v.epss_score, v.in_kev, v.malicious,
       p.ecosystem, p.name AS package_name, p.version AS package_version,
       sp.dependency_path, sp.via, pr.path AS project_path,
       count(*) OVER () AS total
FROM findings f
JOIN projects pr ON pr.id = f.project_id
JOIN vulnerabilities v ON v.id = f.vulnerability_id
JOIN packages p ON p.id = f.package_id
LEFT JOIN scan_packages sp ON sp.scan_id = f.scan_id AND sp.package_id = f.package_id
WHERE (CAST(sqlc.narg(project_id) AS INTEGER) IS NULL OR f.project_id = sqlc.narg(project_id))
  AND (
    (CAST(sqlc.narg(status) AS TEXT) = 'fixed' AND f.status = 'fixed')
    OR (COALESCE(sqlc.narg(status), '') <> 'fixed' AND f.scan_id = pr.last_deps_scan_id
        AND (sqlc.narg(status) IS NULL OR f.status = sqlc.narg(status)))
  )
  AND (json_array_length(CAST(sqlc.narg(severities) AS TEXT_LIST)) = 0
       OR v.severity IN (SELECT value FROM json_each(sqlc.narg(severities))))
  AND (CAST(sqlc.narg(min_priority) AS REAL) IS NULL OR f.priority >= sqlc.narg(min_priority))
  AND (CAST(sqlc.narg(direct) AS BOOLEAN) IS NULL OR f.direct = sqlc.narg(direct))
  AND (CAST(sqlc.narg(in_kev) AS BOOLEAN) IS NULL OR v.in_kev = sqlc.narg(in_kev))
  AND (CAST(sqlc.narg(malicious) AS BOOLEAN) IS NULL OR v.malicious = sqlc.narg(malicious))
  AND (CAST(sqlc.narg(is_new) AS BOOLEAN) IS NULL OR f.is_new = sqlc.narg(is_new))
  AND (CAST(sqlc.narg(search) AS TEXT) IS NULL OR p.name LIKE '%' || sqlc.narg(search) || '%'
       OR f.vulnerability_id LIKE '%' || sqlc.narg(search) || '%'
       OR EXISTS (SELECT 1 FROM json_each(v.aliases) a WHERE a.value = sqlc.narg(search)))
ORDER BY f.priority DESC, f.id
LIMIT CAST(sqlc.arg(limit) AS INT) OFFSET CAST(sqlc.arg(offset) AS INT);

-- name: ProjectFindingPriorities :many
SELECT f.priority FROM findings f WHERE f.scan_id = ? AND f.status = 'open';

-- name: ProjectSeverityCounts :one
SELECT CAST(count(*) FILTER (WHERE v.severity = 'critical') AS INT) AS critical,
       CAST(count(*) FILTER (WHERE v.severity = 'high') AS INT) AS high,
       CAST(count(*) FILTER (WHERE v.severity = 'medium') AS INT) AS medium,
       CAST(count(*) FILTER (WHERE v.severity = 'low') AS INT) AS low
FROM projects p
JOIN findings f ON f.scan_id = p.last_deps_scan_id AND f.status = 'open'
JOIN vulnerabilities v ON v.id = f.vulnerability_id
WHERE p.id = ?;

-- name: ListCurrentFindingsForScoring :many
SELECT f.id, f.direct, f.reachable, f.package_id, f.status, sp.dependency_path, p.name AS package_name,
       CAST(COALESCE(v.cvss_score, 0) AS REAL) AS cvss_score, CAST(COALESCE(v.epss_score, 0) AS REAL) AS epss_score, v.in_kev, v.malicious
FROM findings f
JOIN vulnerabilities v ON v.id = f.vulnerability_id
JOIN packages p ON p.id = f.package_id
LEFT JOIN scan_packages sp ON sp.scan_id = f.scan_id AND sp.package_id = f.package_id
WHERE f.scan_id = ?;

-- name: UpdateFindingScore :exec
UPDATE findings SET priority = @priority, reachable = @reachable WHERE id = @id;
