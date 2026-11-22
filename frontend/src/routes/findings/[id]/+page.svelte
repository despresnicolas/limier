<script lang="ts">
  import { page } from '$app/state';
  import { api } from '$lib/api';
  import { fmtDate, fmtDateTime, fmtPercent } from '$lib/format';
  import { t } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import Load from '$lib/components/Load.svelte';
  import Sev from '$lib/components/Sev.svelte';

  const id = $derived(Number(page.params.id));
  const q = resource(() => api.finding(id));

  const aliasURL = (a: string) =>
    a.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${a}` : a.startsWith('GHSA-') ? `https://github.com/advisories/${a}` : undefined;
</script>

<p class="back"><a href="#/findings">← {t('nav.findings')}</a></p>

<Load r={q}>
  {#snippet children(f)}
    {@const refs = (f.refs ?? []).map((r) => ({ url: r.URL ?? r.url ?? '', type: r.Type ?? r.type ?? '' })).filter((r) => r.url)}
    <header class="head">
      <div class="title">
        <h1>{f.vulnerability_id}</h1>
        <p class="meta">
          <Sev severity={f.severity} />
          <span>{t(`status.${f.status}One`)}</span>
          {#if f.malicious}<span class="pill sev-error">{t('findings.malicious')}</span>{/if}
          {#if f.in_kev}<span class="pill sev-error">KEV</span>{/if}
          {#if f.reachable === false}<span class="pill">{t('findings.unreachable')}</span>{/if}
          <span class="muted">{t('findings.priority')} <strong>{f.priority.toFixed(1)}</strong></span>
          <code>{f.package_name}@{f.package_version}</code>
        </p>
      </div>
      <div class="actions">
        <a class="btn primary" href="#/projects/{f.project_id}?tab=fixes">{t('finding.seeFixes')}</a>
      </div>
    </header>

    {#if f.malicious}
      <section class="card malicious" role="alert">
        <h2 class="sev-error">{t('finding.maliciousTitle')}</h2>
        <p>{t('finding.maliciousNoFix')}</p>
        <p>{t('finding.maliciousAction')}</p>
        <p><strong>{t('finding.maliciousCompromised')}</strong></p>
      </section>
    {/if}

    {#if f.summary}<p class="summary">{f.summary}</p>{/if}

    <div class="two">
      <section class="card">
        <h2>{t('finding.vuln')}</h2>
        <dl>
          <dt>{t('finding.aliases')}</dt>
          <dd>{#each f.aliases ?? [] as a (a)}{@const u = aliasURL(a)}<span class="alias">{#if u}<a href={u} target="_blank" rel="noreferrer noopener">{a}</a>{:else}{a}{/if}</span>{:else}—{/each}</dd>
          <dt>CVSS</dt>
          <dd>{#if f.cvss_score !== null}<strong>{f.cvss_score.toFixed(1)}</strong>{#if f.cvss_vector}<div><code class="muted">{f.cvss_vector}</code></div>{/if}{:else}—{/if}</dd>
          <dt>EPSS</dt><dd>{fmtPercent(f.epss_score, 2)}</dd>
          <dt>CISA KEV</dt><dd class:sev-error={f.in_kev}>{f.in_kev ? t('finding.kevYes') : t('finding.no')}</dd>
          <dt>{t('finding.published')}</dt><dd>{fmtDate(f.published_at)}</dd>
          <dt>{t('finding.firstSeen')}</dt><dd>{fmtDateTime(f.first_seen_at)}</dd>
          <dt>{t('finding.source')}</dt><dd><a href="https://osv.dev/vulnerability/{encodeURIComponent(f.vulnerability_id)}" target="_blank" rel="noreferrer noopener">OSV</a></dd>
        </dl>
      </section>
      <section class="card">
        <h2>{t('finding.package')}</h2>
        <dl>
          <dt>{t('findings.package')}</dt><dd><code>{f.package_name}@{f.package_version}</code></dd>
          <dt>purl</dt><dd>{#if f.purl}<code>{f.purl}</code>{:else}—{/if}</dd>
          <dt>{t('findings.fixedIn')}</dt><dd>{#if f.fixed_version}<code>{f.fixed_version}</code>{:else}{t('finding.noFix')}{/if}</dd>
          <dt>{t('findings.dependency')}</dt>
          <dd>{f.direct ? t('dep.directOne') : t('dep.transitiveOne')}{f.dev === true ? ` (${t('finding.dev')})` : f.dev === false ? ` (${t('finding.prod')})` : ''}</dd>
          {#if !f.direct && f.via?.length}
            <dt>{t('finding.via')}</dt><dd>{#each f.via as n, i (n)}{#if i}, {/if}<code>{n}</code>{/each}</dd>
          {/if}
          <dt>{t('finding.path')}</dt>
          <dd>{#if f.dependency_path?.length}<code>{f.dependency_path.join(' › ')}</code>{:else}—{/if}</dd>
          <dt>{t('finding.reachable')}</dt>
          <dd>{f.reachable === null ? t('finding.notAnalysed') : f.reachable ? t('finding.yes') : t('finding.neverImported')}</dd>
          <dt>{t('findings.project')}</dt><dd><a href="#/projects/{f.project_id}">{t('finding.seeProject')}</a></dd>
        </dl>
      </section>
    </div>

    {#if refs.length}
      <section class="card">
        <h2>{t('finding.refs')}</h2>
        <ul class="refs">
          {#each refs as r, i (i)}<li>{#if r.type}<span class="pill">{r.type}</span>{/if} <a href={r.url} target="_blank" rel="noreferrer noopener">{r.url}</a></li>{/each}
        </ul>
      </section>
    {/if}
  {/snippet}
</Load>

<style>
  .back { font-size: 13px; margin-bottom: 12px; }
  .head { display: flex; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
  .title { flex: 1; min-width: 0; }
  .title h1 { margin: 0 0 4px; overflow-wrap: anywhere; }
  .meta { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 12px; font-size: 13px; }
  .actions { display: flex; gap: 8px; }
  .summary { margin: 16px 0; font-size: 15px; }
  .two { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 16px; }
  section { margin-bottom: 16px; }
  .two section { margin-bottom: 0; }
  dl { display: grid; grid-template-columns: 140px minmax(0, 1fr); gap: 8px 12px; margin: 0; font-size: 13px; }
  dt { color: var(--muted); }
  dd { margin: 0; overflow-wrap: anywhere; }
  .alias { margin-right: 10px; }
  .malicious { border-color: var(--err); margin-top: 16px; }
  .malicious h2 { margin-top: 0; }
  .malicious p { margin: 6px 0; }
  .refs { list-style: none; margin: 0; padding: 0; display: grid; gap: 4px; font-size: 13px; overflow-wrap: anywhere; }
</style>
