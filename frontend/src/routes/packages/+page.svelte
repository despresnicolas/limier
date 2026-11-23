<script lang="ts">
  import { goto } from '$app/navigation';
  import { api, ApiError } from '$lib/api';
  import { t } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import { route } from '$lib/route.svelte';
  import type { PackageSearch } from '$lib/types';
  import DepType from '$lib/components/DepType.svelte';
  import Load from '$lib/components/Load.svelte';
  import Sev from '$lib/components/Sev.svelte';
  import VersionDrift from '$lib/components/VersionDrift.svelte';

  // The search lives in the URL (#/packages?q=…), so a search can be linked.
  const q = $derived(route().searchParams.get('q')?.trim() ?? '');
  const empty: PackageSearch = { items: [], truncated: false };
  const res = resource(() => (q ? api.searchPackages(q) : Promise.resolve(empty)));
  const invalid = $derived(res.error instanceof ApiError && res.error.status === 400);

  const EXAMPLES = ['axios', 'axios@1.6.0', 'axios@<1.7.0'];

  let timer: ReturnType<typeof setTimeout>;
  const search = (v: string) => goto(`#/packages${v.trim() ? `?q=${encodeURIComponent(v.trim())}` : ''}`, { keepFocus: true, noScroll: true, replaceState: true });
  function onInput(v: string) {
    clearTimeout(timer);
    timer = setTimeout(() => search(v), 300);
  }
</script>

<h1>{t('nav.packages')}</h1>
<p class="muted intro">{t('packages.intro')}</p>

<div class="search">
  <div class="field">
    <svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="5" /><path d="m11 11 3.5 3.5" /></svg>
    <input type="search" value={q} oninput={(e) => onInput(e.currentTarget.value)} aria-label={t('packages.search')} placeholder={t('packages.searchPh')} spellcheck="false" autocomplete="off" />
  </div>
  <p class="examples">
    <span class="muted">{t('packages.examples')}</span>
    {#each EXAMPLES as ex (ex)}<button type="button" class="ex" onclick={() => { clearTimeout(timer); search(ex); }}><code>{ex}</code></button>{/each}
  </p>
  <p class="muted hint">{t('packages.searchHint')}</p>
</div>

{#if !q}
  <VersionDrift />
{:else if invalid}
  <p class="card sev-warning" role="alert">{t('packages.invalid')}</p>
{:else}
  <Load r={res}>
    {#snippet children(d)}
      {#if d.items.length === 0}
        <p class="card muted">{t('packages.none', { q })}</p>
      {:else}
        <p class="muted count" role="status">
          {t('packages.count', { n: d.items.length })} {t('packages.inProjects', { n: new Set(d.items.map((h) => h.project_id)).size })}
          {#if d.truncated}{t('packages.truncated')}{/if}
        </p>
        <div class="scroll-x">
          <table>
            <thead>
              <tr>
                <th>{t('packages.project')}</th>
                <th>{t('packages.package')}</th>
                <th>{t('packages.version')}</th>
                <th>{t('packages.type')}</th>
                <th>{t('packages.vulns')}</th>
              </tr>
            </thead>
            <tbody>
              {#each d.items as h (`${h.project_id}/${h.name}@${h.version}`)}
                <tr>
                  <td>
                    <a href="#/projects/{h.project_id}?tab=dependencies">{h.project_path}</a>
                    {#if h.declared_in?.length}
                      <div class="sub muted">{t('packages.declaredIn')} {#each h.declared_in as dir, i (dir)}{#if i}, {/if}<code>{dir || t('packages.root')}</code>{/each}</div>
                    {/if}
                  </td>
                  <td><code>{h.name}</code></td>
                  <td><code>{h.version}</code></td>
                  <td>
                    <DepType direct={h.direct} via={h.via} path={h.dependency_path} />
                    {#if h.dev}<div class="sub muted">{t('packages.dev')}</div>{/if}
                  </td>
                  <td>
                    {#if h.open_vulns > 0}
                      <a href="#/projects/{h.project_id}?search={encodeURIComponent(h.name)}">{t('packages.vulnCount', { n: h.open_vulns })}</a>
                      · <Sev severity={h.worst_severity} />
                    {:else}<span class="muted">{t('packages.clean')}</span>{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {/snippet}
  </Load>
{/if}

<style>
  .intro { margin: -8px 0 16px; font-size: 13px; }
  .search { display: grid; gap: 8px; margin-bottom: 28px; }
  .field { position: relative; }
  .field svg { position: absolute; left: 12px; top: 50%; translate: 0 -50%; width: 16px; height: 16px; fill: none; stroke: var(--muted); stroke-width: 1.6; stroke-linecap: round; pointer-events: none; }
  .field input { font-family: var(--mono); font-size: 15px; padding: 10px 12px 10px 36px; border-radius: var(--radius); }
  .examples { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 0; font-size: 12px; }
  .ex { padding: 1px 8px; border-radius: 99px; font-size: 12px; background: var(--surface-2); border-color: transparent; }
  .ex:hover { border-color: var(--accent); }
  .hint { margin: 0; }
  .hint, .sub, .count { font-size: 12px; }
</style>
