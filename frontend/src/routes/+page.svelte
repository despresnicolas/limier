<script lang="ts">
  import NoProjects from '$lib/components/NoProjects.svelte';
  import { api } from '$lib/api';
  import { fmtDate, fmtNumber } from '$lib/format';
  import { t } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import Chart from '$lib/components/Chart.svelte';
  import Grade, { gradeFromRisk } from '$lib/components/Grade.svelte';
  import Load from '$lib/components/Load.svelte';
  import { sevClass } from '$lib/components/Sev.svelte';
  import { SEV_COLORS } from '$lib/components/colors';

  // Refresh while a scan runs, so pending grades turn into letters.
  const q = resource(api.dashboard, { poll: (d) => (d?.top_risk_projects.some((p) => p.scanning) ? 5000 : false) });
  const MAIN = ['critical', 'high', 'medium', 'low'] as const;
</script>

<h1>{t('nav.dashboard')}</h1>

<Load r={q}>
  {#snippet children(d)}
    {#if d.counts.projects === 0}
      <NoProjects onadded={q.reload} />
    {:else}
      {@const open = Object.values(d.vulnerabilities_by_severity).reduce((a, b) => a + b, 0)}
      <section class="stats">
        <a class="card stat" href="#/projects"><span class="lbl">{t('nav.projects')}</span><span class="big">{fmtNumber(d.counts.projects)}</span></a>
        <a class="card stat" href="#/findings"><span class="lbl">{t('dash.open')}</span><span class="big">{fmtNumber(open)}</span></a>
        <a class="card stat" href="#/findings?kev=true">
          <span class="lbl">{t('dash.kev')}</span>
          <span class="big" class:sev-error={d.vulnerabilities_in_kev > 0}>{fmtNumber(d.vulnerabilities_in_kev)}</span>
        </a>
        <a class="card stat" href="#/findings?malicious=true">
          <span class="lbl">{t('dash.malicious')}</span>
          <span class="big" class:sev-error={d.vulnerabilities_malicious > 0}>{fmtNumber(d.vulnerabilities_malicious)}</span>
        </a>
      </section>

      <section class="card">
        <h2>{t('dash.bySeverity')}</h2>
        <ul class="sevs">
          {#each MAIN as s (s)}
            <li>
              <a href="#/findings?severity={s}">
                <span class={sevClass[s]}>{t(`sev.${s}`)}</span>
                <span class="big">{fmtNumber(d.vulnerabilities_by_severity[s] ?? 0)}</span>
              </a>
            </li>
          {/each}
        </ul>
      </section>

      <div class="two">
        <section class="card">
          <h2>{t('dash.trend')}</h2>
          {#if d.trend.length === 0}
            <p class="muted">{t('dash.noHistory')}</p>
          {:else}
            <Chart label={t('dash.trendLabel')} stacked labels={d.trend.map((x) => fmtDate(x.day))}
              series={MAIN.map((s) => ({ name: t(`sev.${s}`), color: SEV_COLORS[s], data: d.trend.map((x) => x[`vulns_${s}`]) }))} />
          {/if}
        </section>
        <section class="card">
          <h2>{t('dash.topRisk')}</h2>
          {#if d.top_risk_projects.length === 0}
            <p class="muted">{t('dash.noRisk')}</p>
          {:else}
            <ol class="top">
              {#each d.top_risk_projects.slice(0, 10) as p (p.id)}
                <li>
                  <a href="#/projects/{p.id}">
                    <Grade grade={gradeFromRisk(p.risk_score)} size={22} pending={p.scanning} />
                    <span class="path">{p.path}</span>
                    <span class="muted" title={t('risk.title')}>{p.risk_score.toFixed(0)}</span>
                  </a>
                </li>
              {/each}
            </ol>
          {/if}
        </section>
      </div>
    {/if}
  {/snippet}
</Load>

<style>
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 16px; }
  .stat { display: grid; gap: 2px; color: inherit; text-decoration: none; }
  .stat:hover { border-color: var(--accent); }
  .lbl { font-size: 12px; color: var(--muted); }
  .big { font-size: 28px; font-weight: 600; font-variant-numeric: tabular-nums; }
  .sevs { list-style: none; padding: 0; margin: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; }
  .sevs a { display: grid; padding: 10px 12px; border: 1px solid var(--border); border-radius: 6px; color: inherit; text-decoration: none; }
  .sevs a:hover { border-color: var(--accent); }
  .two { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); gap: 16px; margin-top: 16px; }
  .top { list-style: none; padding: 0; margin: 0; display: grid; gap: 2px; }
  .top a { display: flex; align-items: center; gap: 10px; padding: 4px 6px; border-radius: 6px; color: inherit; text-decoration: none; }
  .top a:hover { background: var(--surface-2); }
  .path { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  @media (max-width: 1000px) { .two { grid-template-columns: minmax(0, 1fr); } }
</style>
