<script lang="ts">
  import Help from '$lib/components/Help.svelte';
  import Load from '$lib/components/Load.svelte';
  import { api } from '$lib/api';
  import { t } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';

  let all = $state(false);
  const drift = resource(() => api.versionDrift(all));
</script>

<section class="drift">
  <div class="head">
    <h2>{t('drift.title')}</h2>
    <label class="check"><input type="checkbox" bind:checked={all} /> {t('drift.indirect')}</label>
  </div>
  <p class="muted hint">{t('drift.hint')}</p>
  <Load r={drift}>
    {#snippet children(list)}
      {#if !list.length}<p class="muted">{t('drift.none')}</p>{:else}
        <div class="scroll-x">
          <table>
            <thead><tr><th>{t('drift.package')}</th><th>{t('drift.versions')}</th><th class="num">{t('drift.spread')} <Help text={t('drift.spreadHelp')} /></th></tr></thead>
            <tbody>
              {#each list as p (p.name)}
                <tr>
                  <td><code>{p.name}</code><div class="muted">{p.projects} {t('drift.projects').toLowerCase()}</div></td>
                  <td>
                    {#each p.versions as v (v.version)}
                      <details>
                        <summary>
                          <span class="pill" class:vuln={v.open_vulns > 0} class:latest={v.version === p.latest_version}
                            title={v.open_vulns > 0 ? t('drift.vulns', { n: v.open_vulns }) : v.version === p.latest_version ? t('drift.latest') : undefined}>{v.version}</span>
                          <span class="muted">× {v.projects.length}</span>
                        </summary>
                        <ul>{#each v.projects as pr (pr.id)}<li><a href="#/projects/{pr.id}?tab=dependencies">{pr.path}</a></li>{/each}</ul>
                      </details>
                    {/each}
                  </td>
                  <td class="num" class:sev-error={p.spread >= 2} class:sev-warning={p.spread === 1}>{p.spread}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {/snippet}
  </Load>
</section>

<style>
  .head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
  .check { display: inline-flex; align-items: center; gap: 6px; }
  td { vertical-align: top; }
  summary { cursor: pointer; }
  ul { margin: 4px 0 6px 16px; padding: 0; }
  .pill.vuln { background: color-mix(in srgb, var(--err) 15%, transparent); color: var(--err); font-weight: 600; }
  .pill.latest { opacity: 0.7; }
</style>
