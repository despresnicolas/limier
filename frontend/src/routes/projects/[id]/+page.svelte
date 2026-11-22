<script module lang="ts">
  // Module level so a scan that fails while the user is on another page still toasts on return.
  const seen = new Map<number, string>();
</script>

<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { route } from '$lib/route.svelte';
  import { api, ApiError } from '$lib/api';
  import { fmtDateTime, fmtRelative } from '$lib/format';
  import { t, type Key } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import { toast } from '$lib/toast.svelte';
  import type { ProjectDetail, ScanKind } from '$lib/types';
  import FindingsView from '$lib/components/FindingsView.svelte';
  import DeleteProject from '$lib/components/DeleteProject.svelte';
  import Grade from '$lib/components/Grade.svelte';
  import Load from '$lib/components/Load.svelte';
  import ScanStatus from '$lib/components/ScanStatus.svelte';
  import SevCounts from '$lib/components/SevCounts.svelte';
  import Code from '$lib/project/Code.svelte';
  import Dependencies from '$lib/project/Dependencies.svelte';
  import Fixes from '$lib/project/Fixes.svelte';
  import History from '$lib/project/History.svelte';
  import Settings from '$lib/project/Settings.svelte';

  const TABS = ['vulnerabilities', 'fixes', 'code', 'dependencies', 'history', 'settings'] as const;
  type Tab = (typeof TABS)[number];
  const KINDS: ScanKind[] = ['deps', 'code'];

  const id = $derived(Number(page.params.id));
  const tab = $derived<Tab>(TABS.find((x) => x === route().searchParams.get('tab')) ?? 'vulnerabilities');
  const busy = (d?: ProjectDetail) => !!d?.latest_scans.some((s) => s.status === 'queued' || s.status === 'running');
  const q = resource(() => api.project(id), { poll: (d) => (busy(d) ? 5000 : false) });

  // Tabs reload their data when a running scan ends.
  let version = $state(0);
  let wasBusy = false;
  $effect(() => {
    const b = busy(q.data);
    if (wasBusy && !b) version++;
    wasBusy = b;
  });

  // shortcut: failures toast only when a project page sees them, move to the layout if scans start elsewhere.
  $effect(() => {
    for (const s of q.data?.latest_scans ?? []) {
      const before = seen.get(s.id);
      if (s.status === 'failed' && (before === 'queued' || before === 'running')) {
        const e = /no lockfile/.test(s.error) ? t('scan.errNoLockfile') : /docker\.sock|docker daemon/i.test(s.error) ? t('scan.errDocker') : s.error;
        toast(t('scan.failedToast', { k: t(`kind.${s.kind}`), e }), 'err');
      }
      seen.set(s.id, s.status);
    }
  });

  async function scan(kind: ScanKind) {
    try {
      const s = await api.createScan(id, kind);
      seen.set(s.id, 'queued'); // a scan can fail before the next reload sees it queued
      toast(t('project.scanQueued', { k: t(`kind.${kind}`) }));
      q.reload();
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) toast(t('project.scanBusy'), 'info');
      else toast(`${t('project.scanFailed')} : ${(err as Error).message}`, 'err');
    }
  }
</script>

<Load r={q}>
  {#snippet children(d)}
    {@const p = d.project}
    {#if p.parent_id}<p class="muted crumb">{t('project.workspaceOf')} <a href="#/projects/{p.parent_id}">#{p.parent_id}</a></p>{/if}
    <header class="head">
      <Grade grade={d.security_grade} size={36} pending={busy(d) || d.project.last_deps_scan_id === null} />
      <div class="title">
        <h1>{p.path}</h1>
        <p class="muted meta">
          <code>{p.local_path}</code>
          <span>{p.package_manager || t('project.unknownPm')}</span>
          {#if p.subdir}<span>{t('project.folder')} {p.subdir}</span>{/if}
          <span>{t('project.risk', { n: Math.round(p.risk_score) })}</span>
        </p>
      </div>
      <div class="actions">
        {#each KINDS as k (k)}<button onclick={() => scan(k)}>{t('project.scan', { k: t(`kind.${k}`) })}</button>{/each}
        <!-- A workspace is removed with its root project. -->
        <DeleteProject id={p.parent_id ?? p.id} path={p.path} ondeleted={() => goto('#/projects')} />
      </div>
    </header>

    <div class="status">
      <span><span class="muted">{t('nav.findings')}</span> <SevCounts counts={d.vulnerabilities} /></span>
      {#each KINDS as k (k)}
        {@const s = d.latest_scans.find((x) => x.kind === k)}
        {@const time = s ? (s.finished_at ?? s.started_at ?? s.created_at) : null}
        <span title={s?.error || undefined}>
          <span class="muted">{t(`kind.${k}`)}</span>
          {#if s}<ScanStatus status={s.status} />{:else}<span class="muted">{t('project.never')}</span>{/if}
          {#if time}<time class="muted" datetime={time} title={fmtDateTime(time)}>{fmtRelative(time)}</time>{/if}
        </span>
      {/each}
    </div>

    {#if d.workspaces.length}
      <p class="ws"><span class="muted">{t('project.workspaces')}</span>
        {#each d.workspaces as w (w.id)}<a class="pill" class:cur={w.id === p.id} href="#/projects/{w.id}">{w.subdir || w.path}</a>{/each}
      </p>
    {/if}

    <nav class="tabs" aria-label={t('project.sections')}>
      {#each TABS as x (x)}
        <a href="#/projects/{id}{x === 'vulnerabilities' ? '' : `?tab=${x}`}" class:active={tab === x} aria-current={tab === x ? 'page' : undefined}>{t(`tab.${x}` as Key)}</a>
      {/each}
    </nav>

    {#key `${id}-${version}`}
      {#if tab === 'vulnerabilities'}<FindingsView projectId={d.root_project_id} />
      {:else if tab === 'dependencies'}<Dependencies projectId={id} />
      {:else if tab === 'code'}<Code metrics={d.code_metrics} projectId={id} />
      {:else if tab === 'fixes'}<Fixes projectId={id} metrics={d.code_metrics} />
      {:else if tab === 'history'}<History projectId={id} />
      {:else}<Settings detail={d} />
      {/if}
    {/key}
  {/snippet}
</Load>

<style>
  .crumb { font-size: 13px; margin-bottom: 8px; }
  .head { display: flex; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
  .title { flex: 1; min-width: 0; }
  .title h1 { margin: 0; overflow-wrap: anywhere; }
  .meta { display: flex; flex-wrap: wrap; gap: 4px 12px; font-size: 13px; }
  .title { flex-basis: 260px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; }
  .status { display: flex; flex-wrap: wrap; gap: 8px 24px; margin: 12px 0; font-size: 13px; }
  .status > span { display: inline-flex; gap: 6px; align-items: baseline; }
  .ws { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; font-size: 13px; }
  .ws a { text-decoration: none; }
  .ws a.cur { background: var(--accent-soft); color: var(--accent); }
  /* The baseline is an inset shadow so the active underline can cover it without overflowing. */
  .tabs { display: flex; gap: 2px; box-shadow: inset 0 -1px var(--border); margin: 16px 0; overflow-x: auto; scrollbar-width: none; }
  .tabs a { padding: 6px 12px; color: var(--muted); text-decoration: none; border-bottom: 2px solid transparent; white-space: nowrap; }
  .tabs a:hover { color: var(--text); }
  .tabs a.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }
</style>
