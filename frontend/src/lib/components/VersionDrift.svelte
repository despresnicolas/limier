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
    <div>
      <h2>{t('drift.title')}</h2>
      <p class="muted hint">{t('drift.hint')}</p>
    </div>
    <label class="check"><input type="checkbox" bind:checked={all} /> {t('drift.indirect')}</label>
  </div>
  <Load r={drift}>
    {#snippet children(list)}
      {#if !list.length}<p class="card muted">{t('drift.none')}</p>{:else}
        <div class="scroll-x">
          <table>
            <thead><tr><th>{t('drift.package')}</th><th>{t('drift.versions')}</th><th class="num">{t('drift.spread')} <Help text={t('drift.spreadHelp')} /></th></tr></thead>
            <tbody>
              {#each list as p (p.name)}
                <tr>
                  <td><code class="name">{p.name}</code><div class="muted sub">{t('drift.projectCount', { n: p.projects })}</div></td>
                  <td>
                    <ul class="versions">
                      {#each p.versions as v (v.version)}
                        <li>
                          <span class="pill ver" class:vuln={v.open_vulns > 0}>{v.version}</span>
                          {#if v.open_vulns > 0}<span class="tag sev-error">{t('drift.vulns', { n: v.open_vulns })}</span>
                          {:else if v.version === p.latest_version}<span class="tag ok" title={t('drift.latest')}>{t('drift.latestTag')}</span>{/if}
                          <span class="where">
                            {#each v.projects as pr, i (pr.id)}{#if i}, {/if}<a href="#/projects/{pr.id}?tab=dependencies" title={pr.path}>{pr.path.split('/').filter(Boolean).pop() ?? pr.path}</a>{/each}
                          </span>
                        </li>
                      {/each}
                    </ul>
                  </td>
                  <td class="num">
                    <span class="pill spread" class:sev-error={p.spread >= 2} class:sev-warning={p.spread === 1}>
                      {p.spread ? t('drift.majors', { n: p.spread }) : t('drift.sameMajor')}
                    </span>
                  </td>
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
  .head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 12px; }
  .head h2 { margin-bottom: 4px; }
  .hint { margin: 0; font-size: 12px; }
  .check { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; font-size: 13px; color: var(--text); margin-top: 2px; cursor: pointer; }
  td { vertical-align: top; }
  .name { font-weight: 600; }
  .sub { font-size: 12px; }
  .versions { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
  .versions li { display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px; }
  .ver { font-family: var(--mono); font-size: 12px; color: var(--text); }
  .pill.vuln { background: color-mix(in srgb, var(--err) 15%, transparent); color: var(--err); font-weight: 600; }
  .tag { font-size: 11px; font-weight: 600; }
  .tag.ok { color: var(--muted); }
  .where { font-size: 12px; }
  .spread { white-space: nowrap; font-size: 12px; }
  .spread.sev-error { background: color-mix(in srgb, var(--err) 15%, transparent); color: var(--err); }
  .spread.sev-warning { background: color-mix(in srgb, var(--warn) 15%, transparent); color: var(--warn); }
</style>
