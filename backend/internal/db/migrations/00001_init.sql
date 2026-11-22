-- +goose Up
-- SQLite baseline: the final PostgreSQL schema (migrations 00001-00019, in git history), translated.
-- Times are TEXT "YYYY-MM-DD HH:MM:SS[.fff…]+00:00" in UTC: the format the Go driver writes
-- (_time_format=sqlite, _timezone=UTC), so text order is time order; the strftime defaults write it too.
-- Days are TEXT "YYYY-MM-DD" (local calendar day). Lists are JSON arrays of strings (TEXT_LIST),
-- JSON documents are JSON_TEXT, booleans are 0/1. The declared types drive the sqlc overrides.
-- AUTOINCREMENT: ids are never reused after a delete, like PostgreSQL sequences (River jobs and the UI hold ids).

CREATE TABLE users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now'))
);

CREATE TABLE projects (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id          INTEGER REFERENCES projects (id) ON DELETE CASCADE,
    path               TEXT NOT NULL,
    subdir             TEXT NOT NULL DEFAULT '',
    package_manager    TEXT NOT NULL DEFAULT '' CHECK (package_manager IN ('', 'npm', 'pnpm', 'yarn')),
    risk_score         REAL NOT NULL DEFAULT 0,
    last_deps_scan_id  INTEGER REFERENCES scans (id) ON DELETE SET NULL,
    last_code_scan_id  INTEGER REFERENCES scans (id) ON DELETE SET NULL,
    created_at         TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')),
    updated_at         TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')),
    local_path         TEXT NOT NULL,
    branch_prefix      TEXT NOT NULL DEFAULT 'fix'
);
CREATE INDEX projects_parent_idx ON projects (parent_id);
CREATE UNIQUE INDEX projects_local_path_uniq ON projects (local_path, subdir);

CREATE TABLE scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('code', 'deps')),
    trigger      TEXT NOT NULL CHECK (trigger IN ('push', 'cron', 'manual', 'webhook')),
    commit_sha   TEXT NOT NULL DEFAULT '',
    from_sbom    BOOLEAN NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    created_at   TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')),
    started_at   TIMESTAMP,
    finished_at  TIMESTAMP,
    error        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX scans_project_idx ON scans (project_id, created_at DESC);
CREATE INDEX scans_created_idx ON scans (created_at);

CREATE TABLE sboms (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL UNIQUE REFERENCES scans (id) ON DELETE CASCADE,
    format       TEXT NOT NULL DEFAULT 'cyclonedx-json',
    storage_uri  TEXT NOT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now'))
);

-- Used by the "pg://" SBOM storage backend (the name stays for stored URIs). Content is gzip-compressed.
CREATE TABLE sbom_blobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    content     BLOB NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now'))
);

CREATE TABLE packages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem  TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    purl       TEXT NOT NULL DEFAULT '',
    UNIQUE (ecosystem, name, version)
);

CREATE TABLE scan_packages (
    scan_id              INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    package_id           INTEGER NOT NULL REFERENCES packages (id),
    direct               BOOLEAN NOT NULL DEFAULT 0,
    dev                  BOOLEAN NOT NULL DEFAULT 0,
    dependency_path      TEXT_LIST NOT NULL DEFAULT '[]',
    latest_version       TEXT NOT NULL DEFAULT '',
    deprecated           BOOLEAN NOT NULL DEFAULT 0,
    released_at          TIMESTAMP,
    -- Direct dependencies that pull in each transitive package, from the lockfile graph.
    via                  TEXT_LIST NOT NULL DEFAULT '[]',
    -- Health at scan time; NULL means unknown.
    latest_published_at  TIMESTAMP,
    maintainers          INT,
    scorecard            REAL,
    -- Supply-chain signals as "kind" or "kind:detail" (install-script, git:<url>, typosquat:<popular>…).
    risks                TEXT_LIST NOT NULL DEFAULT '[]',
    -- Source repository of a direct dependency, normalised https URL ('' when unknown).
    repository_url       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, package_id)
);
CREATE INDEX scan_packages_package_idx ON scan_packages (package_id);

CREATE TABLE vulnerabilities (
    id            TEXT PRIMARY KEY,
    aliases       TEXT_LIST NOT NULL DEFAULT '[]',
    summary       TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'unknown',
    cvss_score    REAL,
    cvss_vector   TEXT NOT NULL DEFAULT '',
    epss_score    REAL,
    in_kev        BOOLEAN NOT NULL DEFAULT 0,
    published_at  TIMESTAMP,
    modified_at   TIMESTAMP,
    refs          JSON_TEXT NOT NULL DEFAULT '[]',
    updated_at    TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')),
    -- OpenSSF malicious-package advisory (MAL- id or alias): critical, its findings score 100.
    malicious     BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    project_id        INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    vulnerability_id  TEXT NOT NULL REFERENCES vulnerabilities (id),
    package_id        INTEGER NOT NULL REFERENCES packages (id),
    fixed_version     TEXT NOT NULL DEFAULT '',
    priority          REAL NOT NULL DEFAULT 0,
    reachable         BOOLEAN,
    direct            BOOLEAN NOT NULL DEFAULT 0,
    status            TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed')),
    first_seen_at     TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')),
    created_at        TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')),
    -- Absent from the previous dependency scan of the project.
    is_new            BOOLEAN NOT NULL DEFAULT 0,
    UNIQUE (scan_id, vulnerability_id, package_id)
);
CREATE INDEX findings_project_idx ON findings (project_id, status);
CREATE INDEX findings_vuln_idx ON findings (vulnerability_id);

CREATE TABLE code_metrics (
    scan_id                 INTEGER PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
    loc                     INTEGER NOT NULL DEFAULT 0,
    unused_deps             INT NOT NULL DEFAULT 0,
    cycles                  INT NOT NULL DEFAULT 0,
    languages               JSON_TEXT NOT NULL DEFAULT '[]',
    details                 JSON_TEXT NOT NULL DEFAULT '{}',
    secrets                 INT NOT NULL DEFAULT 0,
    sast_findings           INT NOT NULL DEFAULT 0,
    complex_functions       INT NOT NULL DEFAULT 0,
    duplicated_lines        INT NOT NULL DEFAULT 0,
    dead_files              INT NOT NULL DEFAULT 0,
    -- SonarQube-style ratings (SPECS F3): debt in minutes and A..E letters.
    debt_minutes            INT NOT NULL DEFAULT 0,
    security_rating         TEXT NOT NULL DEFAULT '',
    reliability_rating      TEXT NOT NULL DEFAULT '',
    maintainability_rating  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE code_graphs (
    scan_id  INTEGER PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
    graph    JSON_TEXT NOT NULL
);

CREATE TABLE policies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL CHECK (scope IN ('global', 'project')),
    project_id  INTEGER REFERENCES projects (id) ON DELETE CASCADE,
    rules       JSON_TEXT NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')),
    CHECK ((scope = 'global') = (project_id IS NULL))
);
CREATE UNIQUE INDEX policies_scope_uniq ON policies (scope, COALESCE(project_id, 0));
INSERT INTO policies (scope, rules) VALUES ('global', '{}');

-- Daily aggregates kept 2 years for trend charts.
CREATE TABLE metric_snapshots (
    project_id      INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    day             DATE NOT NULL,
    vulns_critical  INT NOT NULL DEFAULT 0,
    vulns_high      INT NOT NULL DEFAULT 0,
    vulns_medium    INT NOT NULL DEFAULT 0,
    vulns_low       INT NOT NULL DEFAULT 0,
    loc             INTEGER,
    unused_deps     INT,
    cycles          INT,
    risk_score      REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, day)
);

CREATE TABLE kev_entries (
    cve_id      TEXT PRIMARY KEY,
    date_added  DATE,
    ransomware  BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE epss_scores (
    cve_id      TEXT PRIMARY KEY,
    score       REAL NOT NULL,
    percentile  REAL NOT NULL,
    updated_at  TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now'))
);

-- Fixes proposed for local projects: each one is accepted or rejected by the user.
-- An accepted fix becomes a branch committed into the local repository; nothing is merged automatically.
CREATE TABLE local_fixes (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id         INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    kind               TEXT NOT NULL CHECK (kind IN ('bump', 'override')),
    manifest_dir       TEXT NOT NULL DEFAULT '',
    package_name       TEXT NOT NULL,
    from_version       TEXT NOT NULL,
    to_version         TEXT NOT NULL,
    vulnerability_ids  TEXT_LIST NOT NULL DEFAULT '[]',
    status             TEXT NOT NULL CHECK (status IN ('queued', 'running', 'created', 'failed', 'rejected')),
    branch             TEXT NOT NULL DEFAULT '',
    base_commit        TEXT NOT NULL DEFAULT '',
    commit_sha         TEXT NOT NULL DEFAULT '',
    error              TEXT NOT NULL DEFAULT '',
    user_id            INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at         TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')),
    updated_at         TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')),
    UNIQUE (project_id, manifest_dir, package_name, to_version)
);

-- App settings read by background jobs (SPECS F3.8). A single row; the CHECK keeps it single.
CREATE TABLE app_settings (
    id           BOOLEAN PRIMARY KEY DEFAULT 1 CHECK (id),
    watch_vulns  BOOLEAN NOT NULL DEFAULT 1
);
INSERT INTO app_settings DEFAULT VALUES;

-- +goose Down
SELECT 'down migration not supported: this is the baseline';
