<script lang="ts">
  import { goto } from '$app/navigation';
  import { route } from '$lib/route.svelte';
  import { api } from '$lib/api';
  import { fmtDateTime, fmtRelative } from '$lib/format';
  import { t } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import AddProject from '$lib/components/AddProject.svelte';
  import DeleteProject from '$lib/components/DeleteProject.svelte';
  import NoProjects from '$lib/components/NoProjects.svelte';
  import Grade, { gradeFromRisk } from '$lib/components/Grade.svelte';
  import Load from '$lib/components/Load.svelte';
  import Pager from '$lib/components/Pager.svelte';
  import SevCounts from '$lib/components/SevCounts.svelte';

  const LIMIT = 50;
  const sp = $derived(route().searchParams);
  const search = $derived(sp.get('search') ?? '');
  const sort = $derived(sp.get('sort') === 'risk' ? 'risk' : 'path');
  const offset = $derived(Number(sp.get('offset')) || 0);
  // Refresh while a scan runs, so pending grades turn into letters.
  const q = resource(() => api.projects({ search, sort, limit: LIMIT, offset }), { poll: (d) => (d?.items.some((p) => p.scanning) ? 5000 : false) });

  function update(patch: Record<string, string | undefined>) {
    const p = new URLSearchParams(sp);
    if (!('offset' in patch)) p.delete('offset');
    for (const [k, v] of Object.entries(patch)) v ? p.set(k, v) : p.delete(k);
    const s = p.toString();
    goto(`#/projects${s ? `?${s}` : ''}`, { keepFocus: true, noScroll: true });
  }
  let timer: ReturnType<typeof setTimeout>;
  // No project at all: the empty state alone, without search, sort or a second add button.
  const empty = $derived(!search && q.data?.total === 0);
</script>

<div class="head">
  <h1>{t('nav.projects')}</h1>
  {#if !empty}<AddProject onadded={q.reload} />{/if}
</div>

{#if !empty}
<div class="filters">
  <label>
    {t('findings.search')}
    <input type="search" value={search} placeholder={t('findings.searchPh')}
      oninput={(e) => { const v = e.currentTarget.value; clearTimeout(timer); timer = setTimeout(() => update({ search: v || undefined }), 300); }} />
  </label>
  <label>
    {t('projects.sort')}
    <select value={sort} onchange={(e) => update({ sort: e.currentTarget.value === 'risk' ? 'risk' : undefined })}>
      <option value="path">{t('projects.sortPath')}</option>
      <option value="risk">{t('projects.sortRisk')}</option>
    </select>
  </label>
</div>
{/if}

<Load r={q}>
  {#snippet children(d)}
    {#if d.items.length === 0 && !search}
      <NoProjects onadded={q.reload} />
    {:else if d.items.length === 0}
      <p class="card muted">{t('projects.noMatch')}</p>
    {:else}
      <div class="scroll-x">
        <table>
          <thead>
            <tr><th>{t('projects.project')}</th><th>{t('projects.pm')}</th><th>{t('projects.grade')}</th><th>{t('projects.open')}</th><th>{t('projects.updated')}</th><th></th></tr>
          </thead>
          <tbody>
            {#each d.items as p (p.id)}
              <tr>
                <td>
                  <a href="#/projects/{p.id}"><strong>{p.path}</strong>{#if p.subdir}<span class="muted"> / {p.subdir}</span>{/if}</a>
                  {#if p.local_path}<div class="muted path"><code>{p.local_path}</code></div>{/if}
                </td>
                <td>{p.package_manager || '—'}</td>
                <td><span class="grade"><Grade grade={gradeFromRisk(p.risk_score)} size={22} pending={p.scanning || p.last_deps_scan_id === null} /> <span class="muted" title={t('risk.title')}>{p.risk_score.toFixed(0)}</span></span></td>
                <td><SevCounts counts={{ critical: p.vulns_critical, high: p.vulns_high, medium: p.vulns_medium, low: p.vulns_low }} /></td>
                <td title={fmtDateTime(p.updated_at)}>{fmtRelative(p.updated_at)}</td>
                <td class="end">{#if !p.parent_id}<DeleteProject id={p.id} path={p.path} ondeleted={q.reload} />{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <Pager total={d.total} limit={LIMIT} {offset} onchange={(o) => update({ offset: o ? String(o) : undefined })} />
    {/if}
  {/snippet}
</Load>

<style>
  .head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
  .filters { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); gap: 12px; max-width: 560px; margin-bottom: 16px; }
  .path { font-size: 12px; }
  .grade { display: inline-flex; align-items: center; gap: 6px; }
  .end { text-align: right; }
</style>
