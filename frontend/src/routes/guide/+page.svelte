<script lang="ts">
  import { api } from '$lib/api';
  import Grade from '$lib/components/Grade.svelte';
  import { t, ruleTitle, type Key } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';

  // Same numbers as the backend: policy.DefaultRules, policy.SecurityGrade and app/rating.go.
  const DEFAULT_WEIGHTS = { cvss: 6, epss: 25, kev: 15, unreachable: 0.3, transitive: 0.8 };
  const policy = resource(() => api.globalPolicy());
  const w = $derived({ ...DEFAULT_WEIGHTS, ...policy.data?.effective.priority_weights });
  const num = (n: number) => n.toLocaleString(undefined, { maximumFractionDigits: 2 });

  const GRADES = ['A', 'B', 'C', 'D', 'E'] as const;
  const RISK_BANDS = ['0 – 9', '10 – 29', '30 – 49', '50 – 69', '70 – 100'];
  // Remediation minutes per finding (app/rating.go remediationMinutes and fallbacks).
  const COSTS: [string, number][] = $derived([
    [ruleTitle('quality.console-log'), 2],
    [ruleTitle('quality.ts-any'), 5],
    [ruleTitle('quality.todo'), 10],
    [ruleTitle('quality.empty-catch'), 10],
    [t('code.duplication'), 15],
    [ruleTitle('quality.complex-function'), 30],
    [t('code.secrets'), 30],
    [t('code.flaws'), 30],
    [ruleTitle('imports.cycle'), 60],
    [ruleTitle('node.eol'), 60],
  ]);
  const fmtMin = (m: number) => (m < 60 ? `${m} min` : `${m / 60} h`);
  const WHAT: [Key, Key][] = [['guide.deps', 'guide.depsText'], ['guide.code', 'guide.codeText'], ['guide.fix', 'guide.fixText'], ['guide.watch', 'guide.watchText']];
  const OTHER: [Key, Key][] = [['guide.coverage', 'guide.coverageText'], ['guide.unreachable', 'guide.unreachableText'], ['guide.drift', 'guide.driftText']];
</script>

<h1>{t('nav.guide')}</h1>
<p class="lead">{t('guide.intro')}</p>

<section>
  <h2>{t('guide.what')}</h2>
  <div class="grid">
    {#each WHAT as [title, text] (title)}<div class="card"><h3>{t(title)}</h3><p>{t(text)}</p></div>{/each}
  </div>
  <p class="card promise">{t('guide.promise')}</p>
</section>

<section>
  <h2>{t('guide.scale')}</h2>
  <p class="muted">{t('guide.scaleText')}</p>
  <ul class="scale">
    {#each GRADES as g (g)}<li><Grade grade={g} size={32} /><span>{t(`guide.grade${g}`)}</span></li>{/each}
  </ul>
</section>

<section class="card">
  <h2>{t('guide.project')}</h2>
  <p>{t('guide.projectText')}</p>
  <ol>
    <li>{t('guide.project1')}</li>
    <li>{t('guide.project2')}</li>
    <li>{t('guide.project3')}</li>
  </ol>
  <ul class="bands">
    {#each GRADES as g, i (g)}<li><Grade grade={g} size={24} /><span>{RISK_BANDS[i]}</span></li>{/each}
  </ul>
  <p class="tip">{t('guide.projectTip')}</p>
</section>

<section class="card">
  <h2>{t('guide.priority')}</h2>
  <p>{t('guide.priorityText')}</p>
  <div class="scroll-x">
    <table>
      <thead><tr><th>{t('guide.question')}</th><th>{t('guide.effect')}</th></tr></thead>
      <tbody>
        <tr><td>{t('guide.qSeverity')}</td><td>{t('guide.qSeverityFx', { w: num(w.cvss), max: num(w.cvss * 10) })}</td></tr>
        <tr><td>{t('guide.qExploit')}</td><td>{t('guide.qExploitFx', { w: num(w.epss) })}</td></tr>
        <tr><td>{t('guide.qKev')}</td><td>{t('guide.qKevFx', { w: num(w.kev) })}</td></tr>
        <tr><td>{t('guide.qReach')}</td><td>{t('guide.qReachFx', { w: num(w.unreachable) })}</td></tr>
        <tr><td>{t('guide.qDirect')}</td><td>{t('guide.qDirectFx', { w: num(w.transitive) })}</td></tr>
      </tbody>
    </table>
  </div>
  <p>{t('guide.malicious')}</p>
  <p class="muted small">{t('guide.weights')}</p>
</section>

<section class="card">
  <h2>{t('guide.codeGrades')}</h2>
  <p>{t('guide.codeGradesText')}</p>
  <dl>
    <dt>{t('guide.sec')}</dt>
    <dd>{t('guide.secText')} <span class="muted">{t('guide.sevScale')}</span></dd>
    <dt>{t('guide.rel')}</dt>
    <dd>{t('guide.relText')} <span class="muted">{t('guide.sevScale')}</span></dd>
    <dt>{t('guide.maint')}</dt>
    <dd>{t('guide.maintText')} <span class="muted">{t('guide.maintScale')}</span><br /><span class="muted small">{t('guide.maintExample')}</span></dd>
  </dl>
</section>

<section class="card">
  <h2>{t('guide.debt')}</h2>
  <p>{t('guide.debtText')}</p>
  <div class="scroll-x">
    <table>
      <thead><tr><th>{t('guide.problem')}</th><th class="num">{t('guide.cost')}</th></tr></thead>
      <tbody>{#each COSTS as [label, min] (label)}<tr><td>{label}</td><td class="num">{fmtMin(min)}</td></tr>{/each}</tbody>
    </table>
  </div>
  <p class="muted small">{t('guide.debtNote')}</p>
</section>

<section>
  <h2>{t('guide.other')}</h2>
  <div class="grid">
    {#each OTHER as [title, text] (title)}<div class="card"><h3>{t(title)}</h3><p>{t(text)}</p></div>{/each}
  </div>
</section>

<style>
  .lead { font-size: 15px; line-height: 1.5; max-width: 70ch; margin: -8px 0 24px; }
  section { margin-bottom: 24px; }
  section.card { padding: 16px 20px; }
  p, li, dd { font-size: 13px; line-height: 1.5; max-width: 75ch; }
  h3 { font-size: 13px; margin: 0 0 4px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }
  .grid p { margin: 0; color: var(--muted); }
  .promise { margin-top: 10px; border-left: 3px solid var(--accent); }
  .scale, .bands { list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: 10px 20px; }
  .scale li, .bands li { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; }
  .bands span { font-variant-numeric: tabular-nums; }
  ol { padding-left: 20px; }
  .tip { margin-bottom: 0; padding: 8px 12px; border-radius: 6px; background: var(--accent-soft); }
  dt { font-weight: 600; font-size: 13px; margin-top: 12px; }
  dd { margin: 2px 0 0; }
  .small { font-size: 12px; }
  table { max-width: 640px; }
</style>
