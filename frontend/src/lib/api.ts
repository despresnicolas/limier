// Thin fetch client for /api/v1, served in-process by the desktop app to its webview only (no sign-in).
import type {
  AppSettings, DashboardSummary, Dependency, DriftPackage, Features, Finding, FindingDetail, FindingFilters, GlobalPolicyResponse, LocalBrowse, LocalFix, LocalFixes,
  CodeMetricsHistoryItem, Page, PolicyRow, PolicyRules, Project, ProjectDetail, ProjectListItem, ProjectPolicyResponse, Scan,
  ScanKind, Snapshot, PackageSearch, UpdateStatus,
} from './types';

export const API_BASE = '/api/v1';

export class ApiError extends Error {
  status: number;
  /** Set while the embedded backend is still starting. */
  starting: boolean;
  constructor(status: number, message: string, starting = false) {
    super(message);
    this.status = status;
    this.starting = starting;
  }
}

type Query = Record<string, string | number | boolean | string[] | undefined | null>;

export function buildQuery(q?: Query): string {
  if (!q) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) {
      if (v.length) p.set(k, v.join(','));
    } else p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

async function request<T>(method: string, path: string, body?: unknown, query?: Query): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${API_BASE}${path}${buildQuery(query)}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let msg = res.statusText;
    let starting = false;
    try {
      const j = await res.json();
      if (j?.error) msg = j.error;
      starting = j?.starting === 'true';
    } catch {
      // non-JSON error body
    }
    throw new ApiError(res.status, msg, starting);
  }
  if (res.status === 204) return undefined as T;
  const type = res.headers.get('Content-Type') ?? '';
  return (type.includes('json') ? res.json() : res.text()) as Promise<T>;
}

const get = <T>(path: string, query?: Query) => request<T>('GET', path, undefined, query);
const post = <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {});
const put = <T>(path: string, body: unknown) => request<T>('PUT', path, body);
const del = <T>(path: string) => request<T>('DELETE', path);

/** Saves an API response as a file. */
export async function download(path: string, filename: string, query?: Query) {
  const res = await fetch(`${API_BASE}${path}${buildQuery(query)}`);
  if (!res.ok) throw new ApiError(res.status, res.statusText);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(await res.blob());
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

export const api = {
  features: () => get<Features>('/features'),
  dashboard: () => get<DashboardSummary>('/dashboard/summary'),
  versionDrift: (all = false) => get<DriftPackage[]>('/packages/drift', { all: all || undefined }),

  projects: (p: { search?: string; sort?: 'path' | 'risk'; limit?: number; offset?: number } = {}) => get<Page<ProjectListItem>>('/projects', { ...p }),
  project: (id: number) => get<ProjectDetail>(`/projects/${id}`),
  deleteProject: (id: number) => del<void>(`/projects/${id}`),
  browseLocal: (path: string) => get<LocalBrowse>('/local-projects/browse', { path }),
  createLocalProject: (path: string) => post<Project>('/local-projects', { path }),
  projectPolicy: (id: number) => get<ProjectPolicyResponse>(`/projects/${id}/policy`),
  putProjectPolicy: (id: number, rules: PolicyRules) => put<PolicyRow>(`/projects/${id}/policy`, rules),
  putBranchPrefix: (id: number, branch_prefix: string) => put<{ branch_prefix: string }>(`/projects/${id}/branch-prefix`, { branch_prefix }),
  scans: (id: number, limit = 50) => get<Scan[]>(`/projects/${id}/scans`, { limit }),
  createScan: (id: number, kind: ScanKind) => post<Scan>(`/projects/${id}/scans`, { kind }),
  projectFindings: (id: number, f: FindingFilters = {}) => get<Page<Finding>>(`/projects/${id}/findings`, { ...f }),
  dependencies: (id: number) => get<Dependency[]>(`/projects/${id}/dependencies`),
  codeMetrics: (id: number, limit = 200) => get<CodeMetricsHistoryItem[]>(`/projects/${id}/code-metrics`, { limit }),
  trends: (id: number, days = 90) => get<Snapshot[]>(`/projects/${id}/trends`, { days }),
  localFixes: (id: number) => get<LocalFixes>(`/projects/${id}/local-fixes`),
  decideLocalFix: (id: number, fix: { manifest_dir: string; package_name: string; to_version: string; decision: 'accept' | 'reject' }) =>
    post<LocalFix>(`/projects/${id}/local-fixes`, fix),
  groupLocalFixes: (id: number) => post<LocalFix[]>(`/projects/${id}/local-fixes/group`, {}),
  reopenLocalFix: (id: number, fixId: number) => del<void>(`/projects/${id}/local-fixes/${fixId}`),
  openInEditor: (id: number, body: { editor: string; file: string; line: number }) => post<void>(`/projects/${id}/open-in-editor`, body),
  /** Quits the app, then deletes its data and moves it to the Trash (handled by the root module). */
  uninstall: () => post<void>('/uninstall'),
  /** Updater (root module): status, manual check, then install + restart in the background. */
  updateStatus: () => request<UpdateStatus>('GET', '/update'),
  checkUpdate: () => post<UpdateStatus>('/update/check'),
  installUpdate: () => post<UpdateStatus>('/update/install'),

  findings: (f: FindingFilters = {}) => get<Page<Finding>>('/findings', { ...f }),
  finding: (id: number) => get<FindingDetail>(`/findings/${id}`),

  searchPackages: (q: string) => get<PackageSearch>('/packages/search', { q }),

  globalPolicy: () => get<GlobalPolicyResponse>('/policies/global'),
  putGlobalPolicy: (rules: PolicyRules) => put<PolicyRow>('/policies/global', rules),

  settings: () => get<AppSettings>('/settings'),
  putSettings: (s: AppSettings) => put<AppSettings>('/settings', s),
};
