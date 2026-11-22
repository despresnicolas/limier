-- name: CreateScan :one
INSERT INTO scans (project_id, kind, trigger, commit_sha, from_sbom)
VALUES (?, ?, ?, ?, ?) RETURNING *;

-- name: GetScan :one
SELECT * FROM scans WHERE id = ?;

-- name: StartScan :exec
UPDATE scans SET status = 'running', started_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now'), error = '' WHERE id = ?;

-- name: SetScanCommit :exec
UPDATE scans SET commit_sha = @commit_sha WHERE id = @id;

-- name: FinishScan :exec
UPDATE scans SET status = @status, finished_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now'), error = @error WHERE id = @id;

-- name: ListProjectScans :many
SELECT * FROM scans
WHERE project_id = @project_id AND (CAST(sqlc.narg(kind) AS TEXT) IS NULL OR kind = sqlc.narg(kind))
ORDER BY created_at DESC, id DESC LIMIT CAST(sqlc.arg(limit) AS INT) OFFSET CAST(sqlc.arg(offset) AS INT);

-- name: HasActiveScan :one
SELECT EXISTS (
    SELECT 1 FROM scans WHERE project_id = ? AND kind = ? AND status IN ('queued', 'running')
);

-- name: LatestSucceededScan :one
SELECT * FROM scans WHERE project_id = ? AND kind = ? AND status = 'succeeded'
ORDER BY created_at DESC, id DESC LIMIT 1;

-- name: LatestScanPerKind :many
SELECT s.* FROM scans s
WHERE s.project_id = ? AND s.id = (
    SELECT l.id FROM scans l WHERE l.project_id = s.project_id AND l.kind = s.kind ORDER BY l.created_at DESC, l.id DESC LIMIT 1
)
ORDER BY s.kind;

-- name: CreateSBOM :one
INSERT INTO sboms (scan_id, format, storage_uri) VALUES (?, ?, ?)
ON CONFLICT (scan_id) DO UPDATE SET storage_uri = excluded.storage_uri
RETURNING *;

-- name: GetSBOMByScan :one
SELECT * FROM sboms WHERE scan_id = ?;

-- name: InsertSBOMBlob :one
INSERT INTO sbom_blobs (content) VALUES (?) RETURNING id;

-- name: GetSBOMBlob :one
SELECT content FROM sbom_blobs WHERE id = ?;

-- name: DeleteSBOMBlob :exec
DELETE FROM sbom_blobs WHERE id = ?;

-- name: UpsertPackage :one
INSERT INTO packages (ecosystem, name, version, purl) VALUES (?, ?, ?, ?)
ON CONFLICT (ecosystem, name, version) DO UPDATE
SET purl = CASE WHEN excluded.purl <> '' THEN excluded.purl ELSE packages.purl END
RETURNING *;

-- name: InsertScanPackage :exec
INSERT INTO scan_packages (scan_id, package_id, direct, dev, dependency_path, latest_version, deprecated, released_at, via,
    latest_published_at, maintainers, scorecard, risks, repository_url)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (scan_id, package_id) DO UPDATE
SET direct = scan_packages.direct OR excluded.direct, dev = scan_packages.dev AND excluded.dev;

-- name: ListScanPackages :many
SELECT p.*, sp.direct, sp.dev, sp.dependency_path, sp.via, sp.latest_version, sp.deprecated, sp.released_at,
    sp.latest_published_at, sp.maintainers, sp.scorecard, sp.risks, sp.repository_url
FROM scan_packages sp JOIN packages p ON p.id = sp.package_id
WHERE sp.scan_id = ?
ORDER BY sp.direct DESC, p.name;

-- name: UpsertVulnerability :exec
INSERT INTO vulnerabilities (id, aliases, summary, severity, cvss_score, cvss_vector, epss_score, in_kev, published_at, modified_at, refs, malicious, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%f+00:00', 'now'))
ON CONFLICT (id) DO UPDATE
SET aliases = excluded.aliases, summary = excluded.summary, severity = excluded.severity,
    cvss_score = excluded.cvss_score, cvss_vector = excluded.cvss_vector, epss_score = excluded.epss_score,
    in_kev = excluded.in_kev, published_at = excluded.published_at, modified_at = excluded.modified_at,
    refs = excluded.refs, malicious = excluded.malicious, updated_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now');

-- name: GetVulnerability :one
SELECT * FROM vulnerabilities WHERE id = ?;

-- name: GetVulnerabilities :many
SELECT * FROM vulnerabilities WHERE id IN (SELECT value FROM json_each(CAST(@ids AS TEXT_LIST)));

-- name: KnownVulnerabilities :many
-- Vulnerabilities already in base whose record is fresh enough to skip a refetch.
SELECT id FROM vulnerabilities WHERE id IN (SELECT value FROM json_each(CAST(@ids AS TEXT_LIST)))
  AND updated_at > strftime('%Y-%m-%d %H:%M:%f+00:00', 'now', '-24 hours');

-- name: EPSSForCVEs :many
SELECT cve_id, score FROM epss_scores WHERE cve_id IN (SELECT value FROM json_each(CAST(@cves AS TEXT_LIST)));

-- name: KEVForCVEs :many
SELECT cve_id FROM kev_entries WHERE cve_id IN (SELECT value FROM json_each(CAST(@cves AS TEXT_LIST)));

-- name: UpsertKEV :exec
INSERT INTO kev_entries (cve_id, date_added, ransomware) VALUES (?, ?, ?)
ON CONFLICT (cve_id) DO UPDATE SET date_added = excluded.date_added, ransomware = excluded.ransomware;

-- name: RefreshVulnEnrichment :execrows
-- Propagate fresh KEV/EPSS data to vulnerabilities.
-- IN (id + aliases) keeps primary key lookups; an OR would scan epss_scores for each vulnerability.
UPDATE vulnerabilities SET
    in_kev = EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id IN (
        SELECT vulnerabilities.id UNION ALL SELECT value FROM json_each(vulnerabilities.aliases))),
    epss_score = (SELECT max(e.score) FROM epss_scores e WHERE e.cve_id IN (
        SELECT vulnerabilities.id UNION ALL SELECT value FROM json_each(vulnerabilities.aliases)));

-- name: InsertCodeMetrics :exec
INSERT INTO code_metrics (scan_id, loc, unused_deps, cycles, languages, details,
    secrets, sast_findings, complex_functions, duplicated_lines, dead_files,
    debt_minutes, security_rating, reliability_rating, maintainability_rating)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (scan_id) DO UPDATE SET loc = excluded.loc, unused_deps = excluded.unused_deps, cycles = excluded.cycles,
    languages = excluded.languages, details = excluded.details, secrets = excluded.secrets,
    sast_findings = excluded.sast_findings, complex_functions = excluded.complex_functions,
    duplicated_lines = excluded.duplicated_lines, dead_files = excluded.dead_files,
    debt_minutes = excluded.debt_minutes, security_rating = excluded.security_rating,
    reliability_rating = excluded.reliability_rating, maintainability_rating = excluded.maintainability_rating;

-- name: GetCodeMetrics :one
SELECT * FROM code_metrics WHERE scan_id = ?;

-- name: ListCodeMetricsHistory :many
SELECT s.created_at, s.commit_sha, m.*
FROM code_metrics m JOIN scans s ON s.id = m.scan_id
WHERE s.project_id = @project_id AND s.status = 'succeeded'
ORDER BY s.created_at DESC, s.id DESC LIMIT CAST(@limit AS INT);

-- name: UpsertCodeGraph :exec
INSERT INTO code_graphs (scan_id, graph) VALUES (?, ?)
ON CONFLICT (scan_id) DO UPDATE SET graph = excluded.graph;

-- name: GetCodeGraph :one
SELECT graph FROM code_graphs WHERE scan_id = ?;

-- name: DeleteOldScans :execrows
-- Retention: detailed scans older than the cutoff, keeping the latest scan of each kind per project.
DELETE FROM scans
WHERE scans.created_at < ?
  AND scans.id NOT IN (SELECT last_deps_scan_id FROM projects WHERE last_deps_scan_id IS NOT NULL)
  AND scans.id NOT IN (SELECT last_code_scan_id FROM projects WHERE last_code_scan_id IS NOT NULL);

-- name: DeleteOrphanSBOMBlobs :execrows
DELETE FROM sbom_blobs WHERE NOT EXISTS (SELECT 1 FROM sboms s WHERE s.storage_uri = 'pg://' || sbom_blobs.id);

-- name: DeleteOldSnapshots :execrows
-- @day is a time: snapshots before its local calendar day go.
DELETE FROM metric_snapshots WHERE day < date(@day, 'localtime');

-- name: MarkStaleScansFailed :execrows
-- Scans stuck in running state (worker crash) are failed after the given cutoff.
UPDATE scans SET status = 'failed', finished_at = strftime('%Y-%m-%d %H:%M:%f+00:00', 'now'), error = 'scan timed out'
WHERE status IN ('queued', 'running') AND created_at < ?;
