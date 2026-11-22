<script lang="ts">
  import { api } from '$lib/api';
  import { fmtDate, fmtNumber, fmtRelative } from '$lib/format';
  import { t, type Key } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import type { Dependency } from '$lib/types';
  import Load from '$lib/components/Load.svelte';

  let { projectId }: { projectId: number } = $props();
  const PAGE = 100;
  const q = resource(() => api.dependencies(projectId));
  let outdatedOnly = $state(false);
  let riskyOnly = $state(false);
  let text = $state('');
  let shown = $state(PAGE);
  let open = $state(new Set<string>()); // expanded direct dependencies (by id), plus "others"

  // Direct dependencies pulling in an indirect one; older scans only know the first step of one path.
  const parents = (d: Dependency) => (d.via?.length ? d.via : d.dependency_path && d.dependency_path.length > 1 ? [d.dependency_path[0]] : []);

  type Group = { dep: Dependency | null; kids: Dependency[] };

  // Each direct dependency with the indirect ones it pulls in; indirect ones without a known parent go last.
  function groups(deps: Dependency[]): Group[] {
    const kidsOf = new Map<string, Dependency[]>();
    const others: Dependency[] = [];
    for (const d of deps) {
      if (d.direct) continue;
      const ps = parents(d);
      if (!ps.length) others.push(d);
      for (const p of ps) kidsOf.set(p, [...(kidsOf.get(p) ?? []), d]);
    }
    const byName = (a: Dependency, b: Dependency) => a.name.localeCompare(b.name);
    const out: Group[] = deps.filter((d) => d.direct).sort(byName).map((d) => ({ dep: d, kids: (kidsOf.get(d.name) ?? []).sort(byName) }));
    if (others.length) out.push({ dep: null, kids: others.sort(byName) });
    return out;
  }

  // While filtering, a group stays when its direct dependency or one of its indirect ones matches,
  // and opens on the matching indirect ones.
  function filtered(all: Group[]) {
    const s = text.trim().toLowerCase();
    const active = !!s || outdatedOnly || riskyOnly;
    const match = (d: Dependency) =>
      (!outdatedOnly || !!d.outdated) && (!riskyOnly || risksOf(d).length > 0) && (!s || d.name.toLowerCase().includes(s));
    const out: (Group & { auto: boolean })[] = [];
    for (const g of all) {
      if (!active) {
        out.push({ ...g, auto: false });
        continue;
      }
      const kids = g.kids.filter(match);
      if ((g.dep && match(g.dep)) || kids.length) out.push({ dep: g.dep, kids: kids.length ? kids : g.kids, auto: kids.length > 0 });
    }
    return out;
  }

  const keyOf = (g: Group) => (g.dep ? String(g.dep.id) : 'others');
  function toggle(k: string) {
    const next = new Set(open);
    if (!next.delete(k)) next.add(k);
    open = next;
  }
  const TWO_YEARS = 2 * 365 * 86400 * 1000;
  const stale = (d: Dependency) => !!d.latest_published_at && Date.now() - new Date(d.latest_published_at).getTime() > TWO_YEARS;
  const count = (deps: Dependency[], f: (d: Dependency) => boolean) => fmtNumber(deps.filter(f).length);
  // A risk is "kind" or "kind:detail"; the detail (URL, host, popular name) may hold colons itself.
  // Unknown kinds (from a newer scan) are skipped rather than shown untranslated.
  const RISK_KINDS = ['install-script', 'git', 'http', 'file', 'registry', 'typosquat'];
  const risksOf = (d: Dependency) =>
    (d.risks ?? []).flatMap((r) => {
      const i = r.indexOf(':');
      const kind = i < 0 ? r : r.slice(0, i);
      if (!RISK_KINDS.includes(kind)) return [];
      return [{ r, detail: i < 0 ? '' : r.slice(i + 1), label: `deps.risk.${kind}` as Key, tip: `deps.risk.${kind}.tip` as Key, red: kind === 'http' }];
    });
</script>

{#snippet cells(d: Dependency)}
  <td><code>{d.version}</code></td>
  <td><code>{d.latest_version || '—'}</code> {#if d.outdated}<span class="pill" class:sev-warning={d.outdated === 'major'}>{d.outdated}</span>{/if}</td>
  <td class="nowrap">{fmtDate(d.released_at)} {#if d.too_old}<span class="pill sev-warning">{t('deps.tooOldOne')}</span>{/if}</td>
  <td><div class="health">
    {#if d.scorecard != null}<span class="pill" class:sev-error={d.scorecard < 4} title={t('deps.scorecardTip')}>Scorecard {fmtNumber(Math.round(d.scorecard * 10) / 10)}/10</span>{/if}
    {#if d.latest_published_at}<span class="pill" class:sev-warning={stale(d)} title={t('deps.lastPublishTip')}>{t('deps.lastPublish', { when: fmtRelative(d.latest_published_at) })}</span>{/if}
    {#if d.maintainers != null}<span class="pill" class:sev-warning={d.maintainers === 1} title={t('deps.maintainersTip')}>{t('deps.maintainers', { n: d.maintainers })}</span>{/if}
  </div></td>
{/snippet}

{#snippet badges(d: Dependency)}
  {#if d.dev}<span class="pill">dev</span>{/if}
  {#if d.deprecated}<span class="pill sev-error">{t('deps.deprecatedOne')}</span>{/if}
  {#each risksOf(d) as x (x.r)}
    <span class="pill" class:sev-error={x.red} class:sev-warning={!x.red} title={t(x.tip, { detail: x.detail })}>{t(x.label, { detail: x.detail })}</span>
  {/each}
{/snippet}

<Load r={q}>
  {#snippet children(deps)}
    {#if deps.length === 0}
      <p class="card muted">{t('deps.none')}</p>
    {:else}
      {@const rows = filtered(groups(deps))}
      <section class="stats">
        <div class="card"><span class="lbl">{t('deps.total')}</span><span class="v">{fmtNumber(deps.length)}</span></div>
        <div class="card"><span class="lbl">{t('deps.direct')}</span><span class="v">{count(deps, (d) => d.direct)}</span></div>
        <div class="card"><span class="lbl">{t('deps.outdated')}</span><span class="v">{count(deps, (d) => !!d.outdated)}</span>
          <span class="lbl">{t('deps.major', { n: count(deps, (d) => d.outdated === 'major') })}</span></div>
        <div class="card"><span class="lbl">{t('deps.deprecated')}</span><span class="v">{count(deps, (d) => d.deprecated)}</span></div>
        <div class="card"><span class="lbl">{t('deps.tooOld')}</span><span class="v">{count(deps, (d) => d.too_old)}</span></div>
      </section>
      <div class="filters">
        <input type="search" bind:value={text} oninput={() => (shown = PAGE)} placeholder={t('deps.searchPh')} aria-label={t('deps.searchPh')} />
        <label class="check"><input type="checkbox" bind:checked={outdatedOnly} /> {t('deps.outdatedOnly')}</label>
        <label class="check"><input type="checkbox" bind:checked={riskyOnly} onchange={() => (shown = PAGE)} /> {t('deps.riskyOnly')}</label>
        <span class="muted">{t('deps.results', { n: rows.length })}</span>
      </div>
      <div class="scroll-x">
        <table>
          <thead><tr><th>{t('findings.package')}</th><th>{t('deps.version')}</th><th>{t('deps.latest')}</th><th>{t('deps.released')}</th><th>{t('deps.health')}</th></tr></thead>
          <tbody>
            {#each rows.slice(0, shown) as g (keyOf(g))}
              {@const k = keyOf(g)}
              {@const expanded = g.auto || open.has(k)}
              <tr class="parent">
                <td>
                  {#if g.kids.length}
                    <button type="button" class="ghost toggle" aria-expanded={expanded} onclick={() => toggle(k)}>
                      <span class="chev" class:open={expanded} aria-hidden="true">▸</span>
                      {#if g.dep}<strong class="name">{g.dep.name}</strong>{:else}<strong>{t('deps.otherIndirect')}</strong>{/if}
                    </button>
                  {:else if g.dep}
                    <span class="chev spacer" aria-hidden="true">▸</span><strong class="name">{g.dep.name}</strong>
                  {/if}
                  {#if g.dep}{@render badges(g.dep)}{/if}
                  {#if g.kids.length}<span class="muted kids">{t('deps.indirectCount', { n: g.kids.length })}</span>{/if}
                  {#if g.dep?.declared_in?.some((dir) => dir)}<div class="muted where">{g.dep.declared_in.map((dir) => dir || t('deps.root')).join(', ')}</div>{/if}
                </td>
                {#if g.dep}{@render cells(g.dep)}{:else}<td></td><td></td><td></td><td></td>{/if}
              </tr>
              {#if expanded}
                {#each g.kids as d (d.id)}
                  <tr class="child">
                    <td><span class="name">{d.name}</span> {@render badges(d)}</td>
                    {@render cells(d)}
                  </tr>
                {/each}
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
      {#if shown < rows.length}
        <p class="more"><button onclick={() => (shown += PAGE)}>{t('deps.more', { n: rows.length - shown })}</button></p>
      {/if}
    {/if}
  {/snippet}
</Load>

<style>
  .where { font-size: 12px; padding-left: 22px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-bottom: 12px; }
  .stats .card { display: grid; padding: 10px 12px; }
  .lbl { font-size: 12px; color: var(--muted); }
  .v { font-size: 20px; font-weight: 600; font-variant-numeric: tabular-nums; }
  .filters { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; margin-bottom: 8px; font-size: 13px; }
  .filters input[type='search'] { width: 280px; }
  .check { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text); }
  .check input { width: auto; }
  .name { overflow-wrap: anywhere; }
  .nowrap { white-space: nowrap; }
  .health { display: flex; flex-wrap: wrap; gap: 4px; min-width: 180px; }
  .more { text-align: center; margin-top: 12px; }
  .toggle { border: 0; padding: 0; display: inline-flex; align-items: center; gap: 0; text-align: left; }
  .chev { display: inline-block; width: 22px; color: var(--muted); transition: transform 0.15s; }
  .chev.open { transform: rotate(90deg); }
  .spacer { visibility: hidden; }
  .kids { font-size: 12px; margin-left: 6px; }
  .child td { background: var(--surface-2); font-size: 13px; }
  .child td:first-child { padding-left: 44px; }
</style>
