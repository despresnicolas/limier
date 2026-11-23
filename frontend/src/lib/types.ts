// Types mirroring the Limier API (backend/internal/httpapi, JSON from sqlc rows).

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'
export type FindingStatus = 'open' | 'fixed'
export type ScanKind = 'code' | 'deps'
export type ScanStatus = 'queued' | 'running' | 'succeeded' | 'failed'

export interface Page<T> {
  items: T[]
  total: number
}

export interface Project {
  id: number
  /** Folder under LOCAL_REPOS_ROOT. */
  local_path: string
  parent_id: number | null
  path: string
  subdir: string
  package_manager: '' | 'npm' | 'pnpm' | 'yarn'
  /** First segment of fix branches, e.g. "fix" in fix/bump-lodash-4.17.21. */
  branch_prefix: string
  risk_score: number
  last_deps_scan_id: number | null
  last_code_scan_id: number | null
  created_at: string
  updated_at: string
}

export interface ProjectListItem extends Project {
  total: number
  vulns_critical: number
  vulns_high: number
  vulns_medium: number
  vulns_low: number
  scanning: boolean
}

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
}

export interface Scan {
  id: number
  project_id: number
  kind: ScanKind
  trigger: 'cron' | 'manual'
  commit_sha: string
  from_sbom: boolean
  status: ScanStatus
  created_at: string
  started_at: string | null
  finished_at: string | null
  error: string
}

export interface Language {
  name: string
  files: number
  code: number
  comments: number
  blanks: number
}

export type IssueSeverity = 'high' | 'medium' | 'low' | 'info'

/** One code finding, shown as file:line. `detail` never holds a secret in clear. */
/** A finding hidden by a limier-ignore comment in the code. */
export interface CodeIgnored {
  rule: string
  file: string
  line?: number
  reason?: string
  /** Marked as a false positive in the app (else hidden by a limier-ignore comment). */
  detail?: string
  false_positive?: boolean
}

export interface CodeIssue {
  rule: string
  severity: IssueSeverity
  file: string
  line?: number
  end_line?: number
  detail?: string
  /** Absent from the previous code scan. */
  new?: boolean
}

export interface CodeFunction {
  file: string
  name: string
  line: number
  end_line: number
  complexity: number
  lines: number
  params: number
  max_nesting: number
  churn?: number // commits in 12 months, absent before hotspots v2
  score?: number
}

/** A file both complex and often changed (churn × max complexity). */
export interface HotFile {
  file: string
  churn: number
  complexity: number
  lines: number
  score: number
}

export interface CodeClone {
  lines: number
  tokens: number
  locations: { file: string; line: number; end_line: number }[]
}

export interface CoverageMetric {
  covered: number
  total: number
  pct: number
}

/** Test coverage: the report the project's tools left on disk, and the import-graph estimate. */
export interface CodeCoverage {
  measured?: {
    format: 'istanbul-summary' | 'lcov' | 'istanbul'
    reports: string[]
    date: string
    lines: CoverageMetric
    statements?: CoverageMetric
    functions: CoverageMetric
    branches: CoverageMetric
    files: { file: string; lines: CoverageMetric }[]
  }
  estimate: { test_files: number; source_files: number; reached: number; pct: number; untested: string[] }
}

/** Lists of a code scan. Scans made before v4 only have unused_dependencies and tool_errors. */
export interface CodeMetricDetails {
  secrets?: CodeIssue[]
  flaws?: CodeIssue[]
  smells?: CodeIssue[]
  quick_wins?: string[]
  hotspots?: CodeFunction[]
  hot_files?: HotFile[]
  functions?: number
  avg_complexity?: number
  duplication?: { clones: CodeClone[] | null; duplicated_lines: number; total_lines: number; ratio: number }
  cycles?: string[][] | null
  dead_files?: string[] | null
  unused_exports?: CodeIssue[] | null
  unused_dependencies?: string[] | null
  coverage?: CodeCoverage
  ignored?: CodeIgnored[] | null
  truncated?: boolean
  tool_errors?: string[]
}

export interface CodeMetrics {
  scan_id: number
  loc: number
  unused_deps: number
  cycles: number
  secrets: number
  sast_findings: number
  complex_functions: number
  duplicated_lines: number
  dead_files: number
  /** SonarQube-style ratings; '' on scans made before they existed. */
  debt_minutes: number
  security_rating: string
  reliability_rating: string
  maintainability_rating: string
  languages: Language[]
  details: CodeMetricDetails
}

export interface CodeMetricsHistoryItem extends CodeMetrics {
  created_at: string
  commit_sha: string
}

export interface ProjectDetail {
  project: Project
  root_project_id: number
  latest_scans: Scan[]
  vulnerabilities: SeverityCounts
  security_grade: 'A' | 'B' | 'C' | 'D' | 'E'
  code_metrics: CodeMetrics | null
  workspaces: Project[]
}

export interface Finding {
  id: number
  scan_id: number
  project_id: number
  vulnerability_id: string
  package_id: number
  fixed_version: string
  priority: number
  reachable: boolean | null
  direct: boolean
  status: FindingStatus
  first_seen_at: string
  /** Absent from the previous dependency scan. */
  is_new: boolean
  created_at: string
  aliases: string[]
  summary: string
  severity: Severity
  cvss_score: number | null
  epss_score: number | null
  in_kev: boolean
  /** OpenSSF malicious-package advisory (MAL- id or alias). */
  malicious: boolean
  ecosystem: string
  package_name: string
  package_version: string
  dependency_path: string[] | null
  /** Direct dependencies pulling in this transitive package (empty on older scans). */
  via?: string[] | null
  project_path: string
  total: number
}

export interface OSVReference {
  Type?: string
  URL?: string
  type?: string
  url?: string
}

export interface FindingDetail extends Omit<Finding, 'project_path' | 'total'> {
  cvss_vector: string
  published_at: string | null
  refs: OSVReference[]
  purl: string
  dev: boolean | null
}

export interface FindingFilters {
  severity?: Severity[]
  status?: FindingStatus
  min_priority?: number
  direct?: boolean
  kev?: boolean
  malicious?: boolean
  new?: boolean
  group?: string
  search?: string
  limit?: number
  offset?: number
}

export interface Dependency {
  id: number
  ecosystem: string
  name: string
  version: string
  purl: string
  direct: boolean
  dev: boolean
  dependency_path: string[]
  /** Direct dependencies pulling in this transitive package (empty on older scans). */
  via?: string[] | null
  latest_version: string
  deprecated: boolean
  released_at: string | null
  outdated?: '' | 'major' | 'minor' | 'patch'
  /** Manifest directories declaring a direct dependency ("" is the root). */
  declared_in?: string[]
  too_old: boolean
  /** Health, null when unknown: publish date of the latest version, then (direct dependencies only) npm maintainers and OpenSSF Scorecard score (0–10). */
  latest_published_at?: string | null
  maintainers?: number | null
  scorecard?: number | null
  /** Supply-chain signals from the lockfile, "kind" or "kind:detail": install-script, git:<url>, http:<url>, file:<path>, registry:<host>, typosquat:<popular>. */
  risks?: string[] | null
}

export interface Snapshot {
  project_id: number
  day: string
  vulns_critical: number
  vulns_high: number
  vulns_medium: number
  vulns_low: number
  loc: number | null
  unused_deps: number | null
  cycles: number | null
  risk_score: number
}

export interface PriorityWeights {
  cvss: number
  epss: number
  kev: number
  unreachable: number
  transitive: number
}

export interface PolicyRules {
  max_dependency_age_days?: number
  /** Fix targets published less than N days ago are held back; 0 disables. */
  min_release_age_days?: number
  priority_weights?: PriorityWeights
}

export interface PolicyRow {
  id: number
  scope: 'global' | 'project'
  project_id: number | null
  rules: PolicyRules
  updated_at: string
}

export type EffectiveRules = Required<PolicyRules>

export interface ProjectPolicyResponse {
  rules: PolicyRules
  effective: EffectiveRules
}

export interface GlobalPolicyResponse {
  policy: PolicyRow
  effective: EffectiveRules
}

/** App settings that background jobs read (SPECS F3.8). */
export interface AppSettings {
  /** Recheck known packages against OSV every 6 h and notify new vulnerabilities. */
  watch_vulns: boolean
}

export interface DashboardSummary {
  counts: { projects: number }
  vulnerabilities_by_severity: Record<Severity, number>
  vulnerabilities_in_kev: number
  vulnerabilities_malicious: number
  top_risk_projects: { id: number; path: string; risk_score: number; scanning: boolean }[]
  trend: { day: string; vulns_critical: number; vulns_high: number; vulns_medium: number; vulns_low: number }[]
}

export interface Features {
  local_projects: boolean
}

/** A fix proposed for a local project; an accepted fix becomes a branch in the local repository. */
export interface LocalFix {
  id: number
  project_id: number
  kind: 'bump' | 'override'
  manifest_dir: string
  package_name: string
  from_version: string
  to_version: string
  vulnerability_ids: string[]
  status: 'queued' | 'running' | 'created' | 'failed' | 'rejected'
  branch: string
  base_commit: string
  commit_sha: string
  error: string
  user_id: number | null
  created_at: string
  updated_at: string
}

export interface LocalFixProposal {
  kind: LocalFix['kind']
  manifest_dir: string
  package_name: string
  from_version: string
  to_version: string
  update_type: '' | 'patch' | 'minor' | 'major'
  dev: boolean
  vulnerability_ids: string[]
  severity: Severity | ''
  in_kev: boolean
  priority: number
  branch: string
  /** Set when a previous attempt failed. */
  decision: LocalFix | null
  /** Semver allows breaking changes (major, or minor in 0.x). */
  breaking: boolean
  /** Breaking boundaries crossed; -1 when the versions are not semver. */
  breaking_steps: number
  /** Project files importing the package; null without a code scan. */
  usage_files: number | null
  /** Estimated work to adapt the code. */
  effort: FixEffort
  effort_reason: string
  /** Publish date of to_version, when known. */
  released_at: string | null
  /** to_version is younger than min_release_age_days: held, or proposed anyway for a KEV or malicious fix. */
  too_fresh: boolean
  /** https URL of the package's source repository, '' when unknown. */
  repository_url: string
  /** For a bump: the vulnerable transitive packages it fixes through this direct parent. */
  transitive?: string[]
  /** For an override: the direct dependencies that pull the package in. */
  via?: string[]
}

export type FixEffort = 'low' | 'medium' | 'high'

export interface LocalFixes {
  proposals: LocalFixProposal[]
  decisions: LocalFix[]
  /** False when the directory is not the root of a git repository: fixes cannot be applied. */
  git_repository: boolean
  /** Proposals that cross no semver boundary: they can share group_branch. */
  low_risk: number
  group_branch: string
  /** Updates the lockfile on a fix branch: Limier only edits package.json. */
  install_command: string
  /** Proposals kept out because their target is younger than min_release_age_days. */
  held: LocalFixProposal[]
  min_release_age_days: number
}

export interface LocalDir {
  name: string
  /** Relative to the server's LOCAL_REPOS_ROOT. */
  path: string
  /** Holds a package.json: can be analysed. */
  node: boolean
  /** Holds a .git directory: accepted fixes can become branches. */
  git: boolean
  registered: boolean
}

export interface LocalBrowse {
  root: string
  path: string
  node: boolean
  git: boolean
  registered: boolean
  dirs: LocalDir[]
  truncated: boolean
}

export interface DriftVersion {
  version: string
  open_vulns: number
  projects: { id: number; path: string }[]
}

export interface DriftPackage {
  name: string
  projects: number
  latest_version: string
  /** Majors between the lowest and highest version in use. */
  spread: number
  vulnerable: boolean
  versions: DriftVersion[]
}

/** One package found by "Where is this package?", from the last deps scan of a project. */
export interface PackageHit {
  project_id: number
  project_path: string
  name: string
  version: string
  direct: boolean
  dev: boolean
  via: string[]
  dependency_path: string[]
  open_vulns: number
  /** Worst severity of the open vulnerabilities, "" when there is none. */
  worst_severity: Severity | ''
  /** Manifest directories declaring a direct dependency ("" is the root). */
  declared_in?: string[]
}

export interface PackageSearch {
  items: PackageHit[]
  truncated: boolean
}

/** Updater status. `enabled` is false outside a bundled app (wails3 dev). */
export interface UpdateStatus {
  current: string
  enabled: boolean
  state: 'unconfigured' | 'idle' | 'checking' | 'up-to-date' | 'available' | 'downloading' | 'verifying' | 'installing' | 'ready' | 'error'
  available?: string
  notes?: string
  error?: string
}
