<script lang="ts">
  import { fmtDateTime, fmtNumber, fmtPercent } from '$lib/format';
  import CodeIssues from '$lib/components/CodeIssues.svelte';
  import Hotspots from '$lib/components/Hotspots.svelte';
  import Grade from '$lib/components/Grade.svelte';
  import { t } from '$lib/i18n.svelte';
  import type { CodeMetrics, CoverageMetric } from '$lib/types';

  let { metrics: m, projectId }: { metrics: CodeMetrics | null; projectId: number } = $props();
  const d = $derived(m?.details ?? {});
  const secrets = $derived(d.secrets ?? []);
  const flaws = $derived(d.flaws ?? []);
  const quick = $derived(new Set(d.quick_wins ?? []));
  const smells = $derived(d.smells ?? []);
  const quickWins = $derived(smells.filter((i) => quick.has(i.rule)));
  const refactor = $derived(smells.filter((i) => !quick.has(i.rule)));
  const hotspots = $derived(d.hotspots ?? []);
  const clones = $derived(d.duplication?.clones ?? []);
  const dupRatio = $derived(Math.round((d.duplication?.ratio ?? 0) * 1000) / 10);
  const cycles = $derived(d.cycles ?? []);
  const deadFiles = $derived(d.dead_files ?? []);
  const unusedExports = $derived(d.unused_exports ?? []);
  const unused = $derived(d.unused_dependencies ?? []);
  const ignored = $derived(d.ignored ?? []);
  const ignoredByRule = $derived(
    Object.entries(ignored.reduce<Record<string, number>>((acc, i) => ({ ...acc, [i.rule]: (acc[i.rule] ?? 0) + 1 }), {}))
      .map(([r, n]) => `${r} ×${n}`)
      .join(', '),
  );
  const cov = $derived(d.coverage);
  const covPct = $derived(cov ? (cov.measured?.lines.pct ?? cov.estimate.pct) : null);
  const partly = $derived((cov?.measured?.files ?? []).filter((f) => f.lines.pct < 100));
  // Below 50 % most code runs untested; below 80 % the usual target is missed.
  const covClass = (pct: number) => (pct < 50 ? 'sev-error' : pct < 80 ? 'sev-warning' : '');
  // Scans from before the Go analysis only carry LOC, unused deps and cycles.
  const legacy = $derived(!!m && d.secrets === undefined);
  // Debt ratio of the maintainability rating: debt / (lines × 30 min), as in the backend.
  const debtRatio = $derived(m && m.loc > 0 ? m.debt_minutes / (m.loc * 30) : 0);
  const AXES = ['security', 'reliability', 'maintainability'] as const;
  const fmtDebt = (min: number) => (min < 60 ? `${min} min` : `${Math.floor(min / 60)} h${min % 60 ? ` ${min % 60} min` : ''}`);

  // Ids, not href="#…": the hash belongs to the router.
  function goTo(id: string) {
    const el = document.getElementById(id);
    el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    el?.focus({ preventScroll: true });
  }
  const where = (i: { file: string; line?: number }) => (i.line ? `${i.file}:${i.line}` : i.file);
</script>

{#snippet metric(label: string, v: CoverageMetric)}
  <div class="metric">
    <span class="lbl">{label}</span>
    <span class="v {covClass(v.pct)}">{v.total ? fmtPercent(v.pct / 100) : '—'}</span>
    <span class="bar" aria-hidden="true"><span style:width="{v.pct}%" class={covClass(v.pct) || 'ok'}></span></span>
    <span class="lbl">{fmtNumber(v.covered)} / {fmtNumber(v.total)}</span>
  </div>
{/snippet}

{#snippet stat(target: string, label: string, value: string, bad: boolean, cls = 'sev-warning')}
  <button type="button" class="card" onclick={() => goTo(target)}><span class="lbl">{label}</span><span class="v {bad ? cls : ''}">{value}</span></button>
{/snippet}

{#if !m}
  <p class="card muted">{t('code.none')}</p>
{:else}
  {#if m.details.tool_errors?.length}
    <div class="card warn" role="alert">
      <strong class="sev-warning">{t('code.toolErrors')}</strong>
      <ul>{#each m.details.tool_errors as e, i (i)}<li>{e}</li>{/each}</ul>
    </div>
  {/if}
  {#if legacy}<p class="card muted warn">{t('code.legacy')}</p>{/if}
  {#if d.truncated}<p class="card muted warn">{t('code.truncated')}</p>{/if}

  {#if m.security_rating}
    <section class="card ratings" aria-label={t('code.ratings')}>
      {#each AXES as axis (axis)}
        {@const g = m[`${axis}_rating`]}
        {@const tip = t(`code.rating.${axis}Tip`, { g, pct: fmtPercent(debtRatio) })}
        <span class="rating" title={tip}><Grade grade={g} size={32} title={tip} /><span class="lbl">{t(`code.rating.${axis}`)}</span></span>
      {/each}
      <span class="debt" title={t('code.debtTip')}>{t('code.debt', { d: fmtDebt(m.debt_minutes) })}</span>
    </section>
  {/if}

  <section class="stats">
    {@render stat('code-secrets', t('code.secrets'), fmtNumber(m.secrets ?? 0), (m.secrets ?? 0) > 0, 'sev-error')}
    {@render stat('code-flaws', t('code.flaws'), fmtNumber(m.sast_findings ?? 0), (m.sast_findings ?? 0) > 0, 'sev-error')}
    {@render stat('code-hotspots', t('code.complex'), fmtNumber(m.complex_functions ?? 0), (m.complex_functions ?? 0) > 0)}
    {@render stat('code-dup', t('code.duplication'), `${dupRatio} %`, dupRatio >= 5)}
    {@render stat('code-cycles', t('code.cycles'), fmtNumber(m.cycles), m.cycles > 0)}
    {@render stat('code-dead', t('code.deadFiles'), fmtNumber(m.dead_files ?? 0), (m.dead_files ?? 0) > 0)}
    {@render stat('code-unused', t('code.unusedDeps'), fmtNumber(m.unused_deps), m.unused_deps > 0)}
    {#if covPct !== null}
      {@render stat('code-coverage', t('code.coverage'), `${cov?.measured ? '' : '~'}${fmtPercent(covPct / 100)}`, covPct < 80, covClass(covPct))}
    {/if}
  </section>

  {#if !legacy}
    <section id="code-secrets" tabindex="-1" class="card block" class:alert={secrets.length > 0}>
      <h2>{t('code.secrets')} ({secrets.length})</h2>
      <p class="muted hint">{t('code.secretsHint')}</p>
      <CodeIssues list={secrets} empty={t('code.noSecrets')} detailLabel={t('code.masked')} {projectId} />
    </section>

    <section id="code-flaws" tabindex="-1" class="card block">
      <h2>{t('code.flaws')} ({flaws.length})</h2>
      <p class="muted hint">{t('code.flawsHint')}</p>
      <CodeIssues list={flaws} empty={t('code.noFlaws')} detailLabel={t('code.detail')} {projectId} />
    </section>

    <section id="code-hotspots" tabindex="-1" class="card block">
      <h2>{t('code.hotspots')} ({hotspots.length})</h2>
      <p class="muted hint">{t('code.hotspotsHint', { n: d.functions ?? 0, avg: (d.avg_complexity ?? 0).toFixed(1) })}</p>
      <Hotspots list={hotspots} files={d.hot_files ?? []} />
    </section>

    <section class="card block">
      <h2>{t('code.quickWins')} ({quickWins.length})</h2>
      <p class="muted hint">{t('code.quickWinsHint')}</p>
      <CodeIssues list={quickWins} empty={t('code.noQuickWins')} detailLabel={t('code.detail')} {projectId} />
    </section>

    <section class="card block">
      <h2>{t('code.smells')} ({refactor.length})</h2>
      <p class="muted hint">{t('code.smellsHint')}</p>
      <CodeIssues list={refactor} empty={t('code.noSmells')} detailLabel={t('code.detail')} {projectId} />
    </section>

    {#if ignored.length}
      <section class="card block">
        <details class="ignored">
          <summary><h2>{t('code.ignored', { n: ignored.length })}</h2></summary>
          <p class="muted hint">{t('code.ignoredHint')} {ignoredByRule}</p>
          <ul class="list">
            {#each ignored as i, k (k)}
              <li><code>{where(i)}</code> <code>{i.rule}</code> — <span class="muted">{i.reason || t('code.ignoredNoReason')}</span></li>
            {/each}
          </ul>
        </details>
      </section>
    {/if}

    <section id="code-dup" tabindex="-1" class="card block">
      <h2>{t('code.duplication')} — {dupRatio} %</h2>
      <p class="muted hint">{t('code.duplicationHint', { n: fmtNumber(d.duplication?.duplicated_lines ?? 0) })}</p>
      {#if !clones.length}<p class="muted">{t('code.noClones')}</p>{:else}
        <ul class="list clones">
          {#each clones as c, k (k)}
            <li>
              <strong>{t('code.clone', { lines: c.lines, n: c.locations.length })}</strong>
              <ul>{#each c.locations as l, j (j)}<li><code>{l.file}:{l.line}–{l.end_line}</code></li>{/each}</ul>
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    {#if cov}
      <section id="code-coverage" tabindex="-1" class="card block">
        <h2>{t('code.coverage')}</h2>
        {#if cov.measured}
          {@const mm = cov.measured}
          <p class="muted hint">{t('code.coverageReport', { date: fmtDateTime(mm.date), files: mm.reports.join(', ') })}</p>
          <div class="metrics">
            {@render metric(t('code.covLines'), mm.lines)}
            {#if mm.statements}{@render metric(t('code.covStatements'), mm.statements)}{/if}
            {@render metric(t('code.covFunctions'), mm.functions)}
            {@render metric(t('code.covBranches'), mm.branches)}
          </div>
          <h3>{t('code.covFiles')} ({partly.length})</h3>
          {#if !partly.length}<p class="muted">{t('code.covAllFiles')}</p>{:else}
            <div class="scroll-x">
              <table>
                <thead><tr><th>{t('code.where')}</th><th class="num">{t('code.covLines')}</th><th class="num">%</th></tr></thead>
                <tbody>
                  {#each partly as f (f.file)}
                    <tr><td><code>{f.file}</code></td><td class="num">{f.lines.covered} / {f.lines.total}</td><td class="num {covClass(f.lines.pct)}">{fmtPercent(f.lines.pct / 100)}</td></tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        {:else}
          <p class="muted hint">{t('code.coverageNoReport')}</p>
          <p class="hint"><code>npx vitest run --coverage --coverage.reporter=json-summary</code></p>
        {/if}

        <h3>{t('code.covEstimate')} — <span class={covClass(cov.estimate.pct)}>~{fmtPercent(cov.estimate.pct / 100)}</span></h3>
        <p class="muted hint">{t('code.covEstimateHint', { reached: cov.estimate.reached, n: cov.estimate.source_files, tests: cov.estimate.test_files })}</p>
        {#if !cov.estimate.untested.length}<p class="muted">{t('code.covNoUntested')}</p>{:else}
          <p class="lbl">{t('code.covUntested', { n: cov.estimate.untested.length })}</p>
          <ul class="list">{#each cov.estimate.untested as f (f)}<li><code>{f}</code></li>{/each}</ul>
        {/if}
      </section>
    {/if}
  {/if}

  <section id="code-cycles" tabindex="-1" class="card block">
    <h2>{t('code.cycles')} ({cycles.length || m.cycles})</h2>
    <p class="muted hint">{t('code.cyclesHint')}</p>
    {#if !cycles.length}<p class="muted">{m.cycles ? t('code.cyclesLegacy') : t('code.noCycles')}</p>{:else}
      <ul class="list">{#each cycles as c, k (k)}<li><code>{[...c, c[0]].join(' → ')}</code></li>{/each}</ul>
    {/if}
  </section>

  <section id="code-unused" tabindex="-1" class="card block">
    <h2>{t('code.unusedDeps')} ({unused.length})</h2>
    <p class="muted hint">{t('code.unusedDepsHint')}</p>
    {#if !unused.length}<p class="muted">{t('code.noUnusedDeps')}</p>{:else}
      <ul class="list">{#each unused as n (n)}<li><code>{n}</code></li>{/each}</ul>
    {/if}
  </section>

  {#if !legacy}
    <section id="code-dead" tabindex="-1" class="card block">
      <h2>{t('code.deadFiles')} ({deadFiles.length})</h2>
      <p class="muted hint">{t('code.deadFilesHint')}</p>
      {#if !deadFiles.length}<p class="muted">{t('code.noDeadFiles')}</p>{:else}
        <ul class="list">{#each deadFiles as f (f)}<li><code>{f}</code></li>{/each}</ul>
      {/if}
    </section>

    <section class="card block">
      <h2>{t('code.unusedExports')} ({unusedExports.length})</h2>
      <p class="muted hint">{t('code.unusedExportsHint')}</p>
      {#if !unusedExports.length}<p class="muted">{t('code.noUnusedExports')}</p>{:else}
        <ul class="list">{#each unusedExports as e, k (k)}<li><code>{e.detail}</code> <span class="muted">{where(e)}</span></li>{/each}</ul>
      {/if}
    </section>
  {/if}

{/if}

<style>
  .warn { margin-bottom: 16px; }
  .warn ul { margin: 6px 0 0; padding-left: 18px; font-size: 13px; }
  .ratings { display: flex; flex-wrap: wrap; align-items: center; gap: 12px 24px; margin-bottom: 16px; padding: 10px 12px; }
  .rating { display: inline-flex; align-items: center; gap: 8px; }
  .debt { margin-left: auto; font-weight: 600; font-variant-numeric: tabular-nums; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 16px; }
  .stats .card { display: grid; padding: 10px 12px; text-align: left; }
  section[tabindex]:focus { outline: none; }
  .lbl { font-size: 12px; color: var(--muted); }
  .v { font-size: 20px; font-weight: 600; font-variant-numeric: tabular-nums; }
  .block { margin-bottom: 16px; }
  .alert { border-color: var(--err); }
  .hint { font-size: 12px; margin: -4px 0 8px; }
  .list { margin: 0; padding-left: 18px; font-size: 13px; }
  .clones > li { margin-bottom: 6px; }
  .ignored summary { cursor: pointer; }
  .ignored summary h2 { display: inline; }
  .ignored .hint { margin-top: 8px; }
  .clones ul { padding-left: 16px; }
  .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 4px 0 16px; }
  .metric { display: grid; gap: 4px; }
  .bar { display: block; height: 6px; border-radius: 99px; background: var(--surface-2); overflow: hidden; }
  .bar span { display: block; height: 100%; background: var(--accent); }
  .bar span.sev-error { background: var(--err); }
  .bar span.sev-warning { background: var(--warn); }
  h3 { font-size: 14px; margin: 16px 0 6px; }
  code { word-break: break-all; }
</style>
