<script lang="ts">
  import DepType from '$lib/components/DepType.svelte';
  import { goto } from '$app/navigation';
  import { route } from '$lib/route.svelte';
  import { api, download } from '$lib/api';
  import { fmtPercent } from '$lib/format';
  import { t } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import { toast } from '$lib/toast.svelte';
  import type { FindingFilters, FindingStatus, Severity } from '$lib/types';
  import Pager from './Pager.svelte';
  import Sev, { SEVERITIES } from './Sev.svelte';

  // Filters live in the URL, next to any other parameter of the page (e.g. the project tab).
  let { projectId }: { projectId?: number } = $props();
  const LIMIT = 50;
  const FILTER_KEYS = ['severity', 'status', 'min_priority', 'direct', 'kev', 'malicious', 'new', 'search', 'offset'];

  const sp = $derived(route().searchParams);
  const severity = $derived((sp.get('severity')?.split(',') ?? []) as Severity[]);
  const status = $derived((sp.get('status') ?? 'open') as FindingStatus);
  const offset = $derived(Number(sp.get('offset')) || 0);
  const filters = $derived<FindingFilters>({
    severity: severity.length ? severity : undefined,
    status,
    min_priority: sp.get('min_priority') ? Number(sp.get('min_priority')) : undefined,
    direct: sp.get('direct') === null ? undefined : sp.get('direct') === 'true',
    kev: sp.get('kev') === 'true' || undefined,
    malicious: sp.get('malicious') === 'true' || undefined,
    new: sp.get('new') === 'true' || undefined,
    search: sp.get('search') ?? undefined,
  });
  const hasFilters = $derived(FILTER_KEYS.some((k) => sp.has(k)));

  const q = resource(() => {
    const f = { ...filters, limit: LIMIT, offset };
    return projectId === undefined ? api.findings(f) : api.projectFindings(projectId, f);
  });
  // All projects: group the page by project, in priority order of each project's first finding.
  // shortcut: groups only the current page (50 rows), a project can span two pages.
  const groups = $derived.by(() => {
    const m = new Map<number, NonNullable<typeof q.data>['items']>();
    for (const f of q.data?.items ?? []) m.set(f.project_id, [...(m.get(f.project_id) ?? []), f]);
    return [...m.values()];
  });

  function update(patch: Record<string, string | undefined>, keepOffset = false) {
    const p = new URLSearchParams(sp);
    if (!keepOffset) p.delete('offset');
    for (const [k, v] of Object.entries(patch)) {
      if (v === undefined || v === '') p.delete(k);
      else p.set(k, v);
    }
    const s = p.toString();
    goto(`#${route().pathname}${s ? `?${s}` : ''}`, { keepFocus: true, noScroll: true });
  }
  function reset() {
    update(Object.fromEntries(FILTER_KEYS.map((k) => [k, undefined])));
  }
  function toggleSeverity(s: Severity) {
    const next = severity.includes(s) ? severity.filter((x) => x !== s) : [...severity, s];
    update({ severity: next.join(',') || undefined });
  }

  let searchTimer: ReturnType<typeof setTimeout>;
  function onSearch(v: string) {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => update({ search: v || undefined }), 300);
  }

  let exporting = $state(false);
  async function exportCsv() {
    exporting = true;
    try {
      await download(projectId === undefined ? '/findings' : `/projects/${projectId}/findings`, 'limier-findings.csv', { ...filters, format: 'csv' });
    } catch (err) {
      toast(`${t('findings.exportFailed')} : ${(err as Error).message}`, 'err');
    } finally {
      exporting = false;
    }
  }
</script>

<section class="card filters" aria-label={t('findings.filters')}>
  <div class="sev" role="group" aria-label={t('findings.bySeverity')}>
    <span class="lbl">{t('findings.severity')}</span>
    {#each SEVERITIES as s (s)}
      <button class:on={severity.includes(s)} aria-pressed={severity.includes(s)} onclick={() => toggleSeverity(s)}>{t(`sev.${s}`)}</button>
    {/each}
  </div>
  <div class="grid">
    <label>
      {t('findings.search')}
      <input type="search" value={sp.get('search') ?? ''} oninput={(e) => onSearch(e.currentTarget.value)} placeholder={t('findings.searchPh')} />
    </label>
    <label>
      {t('findings.status')}
      <select value={status} onchange={(e) => update({ status: e.currentTarget.value === 'open' ? undefined : e.currentTarget.value })}>
        <option value="open">{t('status.open')}</option>
        <option value="fixed">{t('status.fixed')}</option>
      </select>
    </label>
    <label>
      {t('findings.dependency')}
      <select value={sp.get('direct') ?? 'all'} onchange={(e) => update({ direct: e.currentTarget.value === 'all' ? undefined : e.currentTarget.value })}>
        <option value="all">{t('findings.all')}</option>
        <option value="true">{t('dep.direct')}</option>
        <option value="false">{t('dep.transitive')}</option>
      </select>
    </label>
    <label>
      {t('findings.minPriority')}
      <input type="number" min="0" max="100" placeholder="0–100" value={sp.get('min_priority') ?? ''}
        onchange={(e) => {
          const n = Number(e.currentTarget.value);
          update({ min_priority: e.currentTarget.value === '' || !Number.isFinite(n) ? undefined : String(Math.min(100, Math.max(0, n))) });
        }} />
    </label>
  </div>
  <div class="checks">
    <label class="check">
      <input type="checkbox" checked={sp.get('kev') === 'true'} onchange={(e) => update({ kev: e.currentTarget.checked ? 'true' : undefined })} />
      {t('findings.kevOnly')}
    </label>
    <label class="check">
      <input type="checkbox" checked={sp.get('malicious') === 'true'} onchange={(e) => update({ malicious: e.currentTarget.checked ? 'true' : undefined })} />
      {t('findings.maliciousOnly')}
    </label>
    <label class="check">
      <input type="checkbox" checked={sp.get('new') === 'true'} onchange={(e) => update({ new: e.currentTarget.checked ? 'true' : undefined })} />
      {t('findings.newOnly')}
    </label>
  </div>
  {#if hasFilters}<button class="ghost reset" onclick={reset}>{t('findings.reset')}</button>{/if}
</section>

<div class="bar">
  <p class="muted" aria-live="polite">{q.data ? t('findings.count', { n: q.data.total }) : ''}</p>
  <button onclick={exportCsv} disabled={exporting}>{t('findings.export')}</button>
</div>

{#if q.error}
  <p class="sev-error" role="alert">{q.error.message} <button onclick={q.reload}>{t('action.retry')}</button></p>
{:else if !q.data}
  <p class="muted">{t('load.loading')}</p>
{:else if q.data.items.length === 0}
  <p class="card muted">{t('findings.none')}</p>
{:else}
  <div class="scroll-x fit">
    <table>
      <thead>
        <tr>
          <th class="num">{t('findings.priority')}</th><th>{t('findings.vuln')}</th><th>{t('findings.severity')}</th><th>{t('findings.package')}</th>
          <th>{t('findings.type')}</th><th class="num">EPSS</th><th>{t('findings.status')}</th>
        </tr>
      </thead>
      {#each groups as items (items[0].project_id)}
      <tbody>
        {#if projectId === undefined}
          <tr class="group"><th colspan="7"><a href="#/projects/{items[0].project_id}">{items[0].project_path}</a> <span class="muted">{items.length}</span></th></tr>
        {/if}
        {#each items as f (f.id)}
          <tr>
            <td class="num">{f.priority.toFixed(1)}</td>
            <td class="vuln">
              <a href="#/findings/{f.id}">{f.vulnerability_id}</a>
              {#if f.is_new && f.status === 'open'}<span class="pill new" title={t('findings.newTitle')}>{t('findings.new')}</span>{/if}
              {#if f.malicious}<span class="pill kev" title={t('findings.maliciousTitle')}>{t('findings.malicious')}</span>{/if}
              {#if f.in_kev}<span class="pill kev" title={t('findings.kevTitle')}>KEV</span>{/if}
              {#if f.reachable === false}<span class="pill">{t('findings.unreachable')}</span>{/if}
              {#if f.summary}<div class="muted sum" title={f.summary}>{f.summary}</div>{/if}
            </td>
            <td><Sev severity={f.severity} /></td>
            <td class="pkg">
              <code>{f.package_name}<wbr />@{f.package_version}</code>
              {#if f.fixed_version}<div class="muted small">{t('findings.fixedIn')} <code>{f.fixed_version}</code></div>{/if}
            </td>
            <td><DepType direct={f.direct} via={f.via} path={f.dependency_path} /></td>
            <td class="num nowrap">{fmtPercent(f.epss_score)}</td>
            <td class="nowrap">
              {t(`status.${f.status}One`)}
              {#if f.status === 'open'}<div class="small"><a href="#/projects/{f.project_id}?tab=fixes">{t('findings.fixes')}</a></div>{/if}
            </td>
          </tr>
        {/each}
      </tbody>
      {/each}
    </table>
  </div>
  <Pager total={q.data.total} limit={LIMIT} {offset} onchange={(o) => update({ offset: o ? String(o) : undefined }, true)} />
{/if}

<style>
  .nowrap { white-space: nowrap; }
  .filters { display: grid; gap: 12px; margin-bottom: 12px; }
  .sev { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
  .sev button { padding: 2px 10px; border-radius: 99px; font-size: 12px; }
  .sev button.on { background: var(--accent-soft); border-color: var(--accent); color: var(--accent); }
  .lbl { font-size: 12px; color: var(--muted); margin-right: 4px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; align-items: end; }
  .checks { display: flex; flex-wrap: wrap; gap: 6px 20px; }
  .check { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text); }
  .check input { width: auto; }
  .reset { justify-self: start; padding: 2px 6px; font-size: 12px; }
  .bar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; font-size: 13px; }
  /* No horizontal scroll: cells wrap at sensible points instead. */
  .fit { overflow-x: visible; }
  .sum { font-size: 12px; display: -webkit-box; -webkit-line-clamp: 2; line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
  .pkg code, .small code { overflow-wrap: normal; }
  .small { font-size: 12px; margin-top: 2px; }
  .kev { color: var(--err); }
  .new { color: var(--accent); border-color: var(--accent); }
  .group th { background: var(--surface-2); color: var(--text); font-size: 13px; }
</style>
