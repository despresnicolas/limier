-- name: VersionDriftRows :many
-- One row per (root project, package version) from each project's last deps scan, kept only for
-- packages seen at two or more versions. Workspaces share their root's scan.
WITH used AS (
    SELECT pr.id AS project_id, pr.path AS project_path, pk.name, pk.version, sp.latest_version,
           CAST((SELECT count(DISTINCT f.vulnerability_id) FROM findings f
                 WHERE f.scan_id = sp.scan_id AND f.package_id = sp.package_id AND f.status = 'open') AS INT) AS open_vulns
    FROM projects pr
    JOIN scan_packages sp ON sp.scan_id = pr.last_deps_scan_id
    JOIN packages pk ON pk.id = sp.package_id
    WHERE pr.parent_id IS NULL AND (sp.direct OR CAST(@include_indirect AS BOOLEAN))
)
SELECT u.project_id, u.project_path, u.name, u.version, u.latest_version, u.open_vulns
FROM used u
WHERE u.name IN (SELECT name FROM used GROUP BY name HAVING count(DISTINCT version) > 1)
ORDER BY u.name, u.version, u.project_path;

-- name: SearchPackages :many
-- "Where is this package?" (F5.x): packages of each root project's last deps scan, by name
-- (exact, or LIKE @pattern with \, % and _ escaped by the caller) and optional exact version.
-- LIKE is case-insensitive for ASCII letters only.
SELECT pr.id AS project_id, pr.path AS project_path, pk.name, pk.version,
       sp.direct, sp.dev, sp.via, sp.dependency_path,
       CAST((SELECT count(DISTINCT f.vulnerability_id) FROM findings f
             WHERE f.scan_id = sp.scan_id AND f.package_id = sp.package_id AND f.status = 'open') AS INT) AS open_vulns,
       CAST(COALESCE((
           SELECT CASE max(CASE vu.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END)
                  WHEN 5 THEN 'critical' WHEN 4 THEN 'high' WHEN 3 THEN 'medium' WHEN 2 THEN 'low' WHEN 1 THEN 'unknown' END
           FROM findings f JOIN vulnerabilities vu ON vu.id = f.vulnerability_id
           WHERE f.scan_id = sp.scan_id AND f.package_id = sp.package_id AND f.status = 'open'
       ), '') AS TEXT) AS worst_severity
FROM projects pr
JOIN scan_packages sp ON sp.scan_id = pr.last_deps_scan_id
JOIN packages pk ON pk.id = sp.package_id
WHERE pr.parent_id IS NULL
  AND (CASE WHEN CAST(@exact AS BOOLEAN) THEN pk.name = CAST(@pattern AS TEXT)
       ELSE pk.name LIKE '%' || @pattern || '%' ESCAPE '\' END)
  AND (CAST(sqlc.narg(version) AS TEXT) IS NULL OR pk.version = sqlc.narg(version))
ORDER BY pk.name, pk.version, pr.path
LIMIT CAST(@max_rows AS INT);
