<script lang="ts">
  import { api } from '$lib/api';
  import { changelogURL, openExternal } from '$lib/external';
  import { fmtDateTime, fmtRelative } from '$lib/format';
  import { t } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import { toast } from '$lib/toast.svelte';
  import type { CodeMetrics, FixEffort, LocalFix, LocalFixes, LocalFixProposal } from '$lib/types';
  import CodeIssues from '$lib/components/CodeIssues.svelte';
  import Help from '$lib/components/Help.svelte';
  import Hotspots from '$lib/components/Hotspots.svelte';
  import Load from '$lib/components/Load.svelte';
  import Sev from '$lib/components/Sev.svelte';

  // Each proposal is accepted (a limier/… branch is created in the repository) or rejected.
  let { projectId, metrics }: { projectId: number; metrics: CodeMetrics | null } = $props();
  // Code findings are fixed by hand: no branch, no decision to record.
  const cd = $derived(metrics?.details ?? {});
  const quick = $derived(new Set(cd.quick_wins ?? []));
  const codeLists = $derived([
    { key: 'secrets', items: cd.secrets ?? [], hint: 'code.secretsHint', detail: 'code.masked' },
    { key: 'flaws', items: cd.flaws ?? [], hint: 'code.flawsHint', detail: 'code.detail' },
    { key: 'quickWins', items: (cd.smells ?? []).filter((i) => quick.has(i.rule)), hint: 'code.quickWinsHint', detail: 'code.detail' },
  ] as const);
  const hotspots = $derived(cd.hotspots ?? []);
  const codeCount = $derived(codeLists.reduce((n, l) => n + l.items.length, 0) + hotspots.length);
  const pending = (d?: LocalFixes) => !!d?.decisions.some((f) => f.status === 'queued' || f.status === 'running');
  const q = resource(() => api.localFixes(projectId), { poll: (d) => (pending(d) ? 3000 : false) });

  let kind = $state<'all' | 'security' | 'updates'>('all');
  let effort = $state<'all' | FixEffort>('all');
  let busyKey = $state('');
  const key = (p: LocalFixProposal) => `${p.manifest_dir}\0${p.package_name}\0${p.to_version}`;
  const effortClass: Record<FixEffort, string> = { low: 'ok', medium: 'sev-warning', high: 'sev-error' };
  const ageDays = (p: LocalFixProposal) => (p.released_at ? Math.floor((Date.now() - Date.parse(p.released_at)) / 86_400_000) : 0);
  const statusClass: Record<LocalFix['status'], string> = { queued: 'muted', running: 'muted', created: 'ok', failed: 'sev-error', rejected: 'muted' };

  async function decide(p: LocalFixProposal, decision: 'accept' | 'reject') {
    busyKey = key(p);
    try {
      const fx = await api.decideLocalFix(projectId, { manifest_dir: p.manifest_dir, package_name: p.package_name, to_version: p.to_version, decision });
      toast(decision === 'accept' ? t('fixes.accepted', { b: fx.branch }) : t('fixes.rejected', { p: `${fx.package_name} ${fx.to_version}` }));
    } catch (err) {
      toast((err as Error).message, 'err');
    } finally {
      busyKey = '';
      q.reload();
    }
  }
  // The backend speaks English: its usual refusal gets a friendlier word.
  const fixError = (e: string, b: string) => (/already exists/.test(e) ? t('fixes.errBranchExists', { b }) : e);
  async function group(d: LocalFixes) {
    busyKey = 'group';
    try {
      const fxs = await api.groupLocalFixes(projectId);
      toast(t('fixes.grouped', { n: fxs.length, b: d.group_branch }));
    } catch (err) {
      toast(fixError((err as Error).message, d.group_branch), 'err');
    } finally {
      busyKey = '';
      q.reload();
    }
  }
  async function reopen(fx: LocalFix) {
    try {
      await api.reopenLocalFix(projectId, fx.id);
      toast(t('fixes.reopened', { p: `${fx.package_name} ${fx.to_version}` }));
      q.reload();
    } catch (err) {
      toast((err as Error).message, 'err');
    }
  }
</script>

<Load r={q}>
  {#snippet children(d)}
    {@const proposals = d.proposals.filter((p) => (kind === 'all' || (kind === 'security') === p.vulnerability_ids.length > 0) && (effort === 'all' || p.effort === effort))}
    <p class="card note">{t('fixes.note')}</p>
    {#if !d.git_repository}<p class="card sev-error" role="alert">{t('fixes.noGit')}</p>{/if}

    <section class="card">
      <div class="h">
        <h2>{t('fixes.proposals')}</h2>
        <select bind:value={kind} aria-label={t('findings.type')}>
          <option value="all">{t('fixes.allKinds')}</option>
          <option value="security">{t('nav.findings')}</option>
          <option value="updates">{t('fixes.updates')}</option>
        </select>
        <select bind:value={effort} aria-label={t('fixes.effort')}>
          <option value="all">{t('fixes.allEfforts')}</option>
          <option value="low">{t('effort.low')}</option>
          <option value="medium">{t('effort.medium')}</option>
          <option value="high">{t('effort.high')}</option>
        </select>
        {#if d.git_repository && d.low_risk > 0}
          <button class="primary" disabled={busyKey === 'group'} title={t('fixes.groupHint', { b: d.group_branch })} onclick={() => group(d)}>{t('fixes.group', { n: d.low_risk })}</button>
        {/if}
      </div>
      {#if proposals.length === 0}
        <p class="muted">{t('fixes.none')}</p>
      {:else}
        <div class="scroll-x">
          <table>
            <thead><tr><th>{t('findings.package')}</th><th>{t('deps.version')}</th><th>{t('nav.findings')}</th><th>{t('fixes.effort')}</th><th>{t('fixes.branch')}</th>{#if d.git_repository}<th class="r">{t('fixes.decision')}</th>{/if}</tr></thead>
            <tbody>
              {#each proposals as p (key(p))}
                <tr>
                  <td><code><strong>{p.package_name}</strong></code> {#if p.dev}<span class="pill">dev</span>{/if}
                    {#if p.manifest_dir}<div class="muted small">{p.manifest_dir}</div>{/if}</td>
                  <td><code>{p.from_version} → <strong>{p.to_version}</strong></code>
                    <div class="muted small">{t(`fixKind.${p.kind}`)} {#if p.update_type}<span class="pill">{p.update_type}</span>{/if}</div>
                    {#if p.transitive?.length}<div class="muted small">{t('fixes.transitive', { c: p.transitive.join(', '), p: p.package_name })}</div>{/if}
                    {#if p.kind === 'override'}<div class="muted small">{t('fixes.transitive', { c: p.package_name, p: p.via?.join(', ') || '?' })} <Help text={t('fixes.overrideHint')} /></div>{/if}
                    {#if p.too_fresh}<div class="sev-warning small">{t('fixes.freshAge', { n: ageDays(p) })} <Help text={t('fixes.freshUrgent')} /></div>{/if}</td>
                  <td>
                    {#if p.vulnerability_ids.length === 0}<span class="muted">—</span>{:else}
                      <span title={p.vulnerability_ids.join(', ')}>{#if p.severity}<Sev severity={p.severity} />{/if}
                        {#if p.in_kev}<span class="pill sev-error">KEV</span>{/if}
                        <span class="muted small">{t('fixes.vulns', { n: p.vulnerability_ids.length })}</span></span>
                    {/if}
                    {#if p.decision?.status === 'failed'}<p class="sev-error small">{t('fixes.prevFail')} {fixError(p.decision.error, p.decision.branch)}</p>{/if}
                  </td>
                  <td class="nowrap">
                    <span class={effortClass[p.effort]}>{t(`effort.${p.effort}`)}{p.breaking ? ' ⚠' : ''}</span>
                    <Help text={p.effort_reason} />
                    {#if p.repository_url}<a class="small" class:muted={!p.breaking} href={p.breaking ? changelogURL(p.repository_url) : p.repository_url} title={t(p.breaking ? 'fixes.changelogHint' : 'fixes.repoHint')} onclick={openExternal}>{t(p.breaking ? 'fixes.changelog' : 'fixes.repo')}</a>{/if}
                    {#if p.breaking || (p.usage_files !== null && p.kind === 'bump')}
                      <div class="muted small">
                        {#if p.breaking}breaking{p.breaking_steps > 1 ? ` ×${p.breaking_steps}` : ''}{/if}
                        {#if p.usage_files !== null && p.kind === 'bump'} · {t('fixes.files', { n: p.usage_files })}{/if}
                      </div>
                    {/if}
                  </td>
                  <td><code class="small">{p.branch}</code></td>
                  {#if d.git_repository}
                    <td class="r nowrap">
                      <button class="primary" disabled={busyKey === key(p)} onclick={() => decide(p, 'accept')}>{p.decision?.status === 'failed' ? t('action.retry') : t('fixes.accept')}</button>
                      <button class="ghost" disabled={busyKey === key(p)} onclick={() => decide(p, 'reject')} aria-label={t('fixes.rejectLabel', { p: `${p.package_name} ${p.to_version}` })}>{t('fixes.reject')}</button>
                    </td>
                  {/if}
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    {#if d.held.length}
      <section class="card">
        <h2>{t('fixes.held', { n: d.held.length })}</h2>
        <p class="muted hint">{t('fixes.heldHint', { n: d.min_release_age_days })}</p>
        <div class="scroll-x">
          <table>
            <thead><tr><th>{t('findings.package')}</th><th>{t('deps.version')}</th><th>{t('nav.findings')}</th></tr></thead>
            <tbody>
              {#each d.held as p (key(p))}
                <tr>
                  <td><code><strong>{p.package_name}</strong></code>{#if p.manifest_dir}<div class="muted small">{p.manifest_dir}</div>{/if}</td>
                  <td><code>{p.from_version} → {p.to_version}</code>
                    <div class="sev-warning small" title={p.released_at ? fmtDateTime(p.released_at) : ''}>{t('fixes.freshAge', { n: ageDays(p) })}</div></td>
                  <td>{#if p.vulnerability_ids.length === 0}<span class="muted">—</span>{:else}{#if p.severity}<Sev severity={p.severity} />{/if}
                    <span class="muted small">{t('fixes.vulns', { n: p.vulnerability_ids.length })}</span>{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    {/if}

    <section class="card">
      <h2>{t('fixes.fromCode')} ({codeCount})</h2>
      <p class="muted hint">{t('fixes.fromCodeHint')}</p>
      {#if !metrics || cd.secrets === undefined}<p class="muted">{t('fixes.noCodeScan')}</p>
      {:else if codeCount === 0}<p class="muted">{t('fixes.codeClean')}</p>
      {:else}
        {#each codeLists.slice(0, 2) as l (l.key)}
          {#if l.items.length}
            <h3 class:sev-error={l.key === 'secrets'}>{t(`code.${l.key}`)} ({l.items.length})</h3>
            <p class="muted hint">{t(l.hint)}</p>
            <CodeIssues list={l.items} empty="" detailLabel={t(l.detail)} {projectId} />
          {/if}
        {/each}
        {#if hotspots.length}
          <h3>{t('code.hotspots')} ({hotspots.length})</h3>
          <p class="muted hint">{t('code.hotspotsHint', { n: cd.functions ?? 0, avg: (cd.avg_complexity ?? 0).toFixed(1) })}</p>
          <Hotspots list={hotspots} />
        {/if}
        {#if codeLists[2].items.length}
          <h3>{t('code.quickWins')} ({codeLists[2].items.length})</h3>
          <p class="muted hint">{t('code.quickWinsHint')}</p>
          <CodeIssues list={codeLists[2].items} empty="" detailLabel={t('code.detail')} {projectId} />
        {/if}
      {/if}
    </section>

    {#if d.decisions.length}
      <section class="card">
        <h2>{t('fixes.decisions')}</h2>
        <p class="muted hint">{t('fixes.installHint')} <code>{d.install_command}</code></p>
        <div class="scroll-x">
          <table>
            <thead><tr><th>{t('findings.package')}</th><th>{t('deps.version')}</th><th>{t('findings.status')}</th><th>{t('fixes.branch')}</th><th>{t('fixes.date')}</th><th></th></tr></thead>
            <tbody>
              {#each d.decisions as fx (fx.id)}
                <tr>
                  <td><code><strong>{fx.package_name}</strong></code>{#if fx.manifest_dir}<div class="muted small">{fx.manifest_dir}</div>{/if}</td>
                  <td><code>{fx.from_version} → <strong>{fx.to_version}</strong></code>{#if fx.kind === 'override'}<div class="muted small">{t('fixKind.override')}</div>{/if}</td>
                  <td><span class={statusClass[fx.status]}>{t(`fixStatus.${fx.status}`)}</span>
                    {#if fx.status === 'failed' && fx.error}<p class="sev-error small">{fixError(fx.error, fx.branch)}</p>{/if}</td>
                  <td>{#if fx.status === 'rejected'}<span class="muted">—</span>{:else}<code class="small">{fx.branch}</code>{#if fx.commit_sha}<div class="muted small"><code>{fx.commit_sha.slice(0, 10)}</code></div>{/if}{/if}</td>
                  <td title={fmtDateTime(fx.updated_at)}>{fmtRelative(fx.updated_at)}</td>
                  <td class="r">{#if fx.status === 'rejected'}<button onclick={() => reopen(fx)}>{t('fixes.reopen')}</button>{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    {/if}
  {/snippet}
</Load>

<style>
  .note { margin-bottom: 12px; font-size: 13px; }
  section { margin-top: 16px; }
  .h { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 12px; }
  .h h2 { margin: 0 auto 0 0; }
  .h select { width: auto; }
  .small { font-size: 12px; margin: 2px 0 0; }
  .nowrap { white-space: nowrap; }
  .r { text-align: right; }
  .ok { color: var(--ok); }
  h3 { font-size: 14px; margin: 16px 0 6px; }
  .hint { font-size: 12px; margin: -4px 0 8px; }
</style>
