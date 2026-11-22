<script lang="ts">
  import { api } from '$lib/api';
  import { fmtDate, fmtDateTime, shortSha } from '$lib/format';
  import { t } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import type { Scan } from '$lib/types';
  import Chart from '$lib/components/Chart.svelte';
  import Load from '$lib/components/Load.svelte';
  import ScanStatus from '$lib/components/ScanStatus.svelte';
  import { SEV_COLORS } from '$lib/components/colors';

  let { projectId }: { projectId: number } = $props();
  let days = $state(90);
  const now = Date.now();
  const trends = resource(() => api.trends(projectId, days));
  const metrics = resource(() => api.codeMetrics(projectId));
  const scans = resource(() => api.scans(projectId));
  const MAIN = ['critical', 'high', 'medium', 'low'] as const;

  function duration(s: Scan) {
    if (!s.started_at || !s.finished_at) return '—';
    const sec = Math.round((new Date(s.finished_at).getTime() - new Date(s.started_at).getTime()) / 1000);
    return sec < 60 ? `${sec} s` : `${Math.floor(sec / 60)} min ${sec % 60} s`;
  }
</script>

<label class="range">
  {t('history.period')}
  <select bind:value={days}>
    <option value={30}>{t('history.days', { n: 30 })}</option>
    <option value={90}>{t('history.days', { n: 90 })}</option>
    <option value={365}>{t('history.year')}</option>
  </select>
</label>

<Load r={trends}>
  {#snippet children(data)}
    {#if data.length === 0}
      <p class="card muted">{t('dash.noHistory')}</p>
    {:else}
      {@const labels = data.map((x) => fmtDate(x.day))}
      <div class="two">
        <section class="card">
          <h2>{t('history.vulns')}</h2>
          <Chart label={t('history.vulns')} stacked {labels}
            series={MAIN.map((s) => ({ name: t(`sev.${s}`), color: SEV_COLORS[s], data: data.map((x) => x[`vulns_${s}`]) }))} />
        </section>
        <section class="card">
          <h2>{t('history.risk')}</h2>
          <Chart label={t('history.risk')} {labels} series={[{ name: t('history.risk'), color: 'var(--accent)', data: data.map((x) => Math.round(x.risk_score * 10) / 10) }]} />
        </section>
      </div>
    {/if}
  {/snippet}
</Load>

<section class="card">
  <h2>{t('history.code')}</h2>
  <Load r={metrics}>
    {#snippet children(all)}
      {@const items = all.filter((m) => new Date(m.created_at).getTime() >= now - days * 86400000).sort((a, b) => a.created_at.localeCompare(b.created_at))}
      {#if items.length === 0}
        <p class="muted">{t('history.noCode')}</p>
      {:else}
        {@const labels = items.map((m) => fmtDateTime(m.created_at))}
        <div class="two">
          <Chart label={t('code.loc')} {labels} series={[{ name: t('code.loc'), color: 'var(--accent)', data: items.map((m) => m.loc) }]} />
          <Chart label={t('history.quality')} {labels} series={[
            { name: t('code.cycles'), color: 'var(--info)', data: items.map((m) => m.cycles) },
            { name: t('code.unusedDeps'), color: 'var(--muted)', data: items.map((m) => m.unused_deps) },
          ]} />
          <Chart label={t('history.debt')} {labels} series={[{ name: t('history.debt'), color: 'var(--warn)', data: items.map((m) => Math.round((m.debt_minutes ?? 0) / 6) / 10) }]} />
        </div>
      {/if}
    {/snippet}
  </Load>
</section>

<section class="card">
  <h2>{t('history.scans')}</h2>
  <Load r={scans}>
    {#snippet children(list)}
      {#if list.length === 0}<p class="muted">{t('history.noScans')}</p>{:else}
        <div class="scroll-x">
          <table>
            <thead><tr><th>{t('findings.type')}</th><th>{t('history.trigger')}</th><th>{t('findings.status')}</th><th>Commit</th><th>{t('history.created')}</th><th>{t('history.duration')}</th><th>{t('history.error')}</th></tr></thead>
            <tbody>
              {#each list as s (s.id)}
                <tr>
                  <td>{t(`kind.${s.kind}`)} {#if s.from_sbom}<span class="pill">SBOM</span>{/if}</td>
                  <td>{t(`trigger.${s.trigger}`)}</td>
                  <td><ScanStatus status={s.status} /></td>
                  <td><code>{shortSha(s.commit_sha)}</code></td>
                  <td class="nowrap">{fmtDateTime(s.created_at)}</td>
                  <td class="nowrap">{duration(s)}</td>
                  <td class="sev-error err">{s.error}</td>
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
  .range { max-width: 200px; margin-bottom: 12px; }
  section { margin-top: 16px; }
  .two { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }
  .two section { margin-top: 0; }
  .nowrap { white-space: nowrap; }
  .err { font-size: 12px; max-width: 320px; }
</style>
