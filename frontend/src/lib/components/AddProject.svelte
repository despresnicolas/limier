<script lang="ts">
  import { goto } from '$app/navigation';
  import { api } from '$lib/api';
  import { t } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import { toast } from '$lib/toast.svelte';
  import type { LocalDir, Project } from '$lib/types';

  // Browse the folders under the repositories root and pick the Node.js projects to analyse.
  let { onadded }: { onadded?: () => void } = $props();
  let dialog: HTMLDialogElement;
  let open = $state(false);
  let dir = $state('');
  let filter = $state('');
  let selected = $state(new Map<string, LocalDir>());
  let busy = $state(false);

  const q = resource(() => (open ? api.browseLocal(dir) : Promise.resolve(undefined)));
  const parts = $derived(dir ? dir.split('/') : []);
  const current = $derived.by((): LocalDir | null => {
    const d = q.data;
    return d && d.path && d.node ? { name: parts[parts.length - 1], path: d.path, node: true, git: d.git, registered: d.registered } : null;
  });
  const dirs = $derived((q.data?.dirs ?? []).filter((d) => d.name.toLowerCase().includes(filter.trim().toLowerCase())));

  function show() {
    dir = '';
    filter = '';
    selected = new Map();
    open = true;
    dialog.showModal();
  }
  function go(path: string) {
    dir = path;
    filter = '';
  }
  function toggle(d: LocalDir, on: boolean) {
    const next = new Map(selected);
    if (on) next.set(d.path, d);
    else next.delete(d.path);
    selected = next;
  }

  async function add() {
    busy = true;
    // One request per folder: a failing folder does not prevent the others.
    const done: Project[] = [];
    for (const d of selected.values()) {
      try {
        done.push(await api.createLocalProject(d.path));
      } catch (err) {
        toast(`${d.path} : ${(err as Error).message}`, 'err');
      }
    }
    busy = false;
    if (done.length === 0) return;
    toast(done.length === 1 ? t('add.doneOne', { p: done[0].path }) : t('add.doneMany', { n: done.length }));
    dialog.close();
    onadded?.();
    if (done.length === 1) goto(`#/projects/${done[0].id}`);
  }
</script>

<button class="primary" onclick={show}>{t('add.button')}</button>

<dialog bind:this={dialog} onclose={() => (open = false)} aria-labelledby="add-title">
  <header>
    <h2 id="add-title">{t('add.title')}</h2>
    <p class="muted">{t('add.desc')}</p>
  </header>
  <div class="body">
    <nav class="crumbs" aria-label={t('add.current')}>
      <button class="ghost" onclick={() => go('')} title={q.data?.root}>{q.data?.root.split('/').filter(Boolean).pop() ?? '/'}</button>
      {#each parts as part, i (i)}
        <span class="muted">›</span>
        <button class="ghost" onclick={() => go(parts.slice(0, i + 1).join('/'))} aria-current={i === parts.length - 1 ? 'page' : undefined}>{part}</button>
      {/each}
    </nav>
    <input type="search" bind:value={filter} placeholder={t('add.filter')} aria-label={t('add.filter')} />
    <div class="list">
      {#if q.error}
        <p class="sev-error">{q.error.message}</p>
      {:else if !q.data}
        <p class="muted">{t('load.loading')}</p>
      {:else}
        {#if current}
          {@render row(current, t('add.thisFolder'))}
        {/if}
        {#each dirs as d (d.path)}
          {@render row(d)}
        {:else}
          <p class="muted empty">{filter ? t('add.noMatch') : t('add.noSub')}</p>
        {/each}
        {#if q.data.truncated}<p class="muted empty">{t('add.truncated')}</p>{/if}
      {/if}
    </div>
    {#if selected.size}
      <p class="muted">{t('add.selection')} <code>{[...selected.keys()].join(', ')}</code></p>
    {/if}
  </div>
  <footer>
    <button onclick={() => dialog.close()}>{t('action.cancel')}</button>
    <button class="primary" disabled={!selected.size || busy} onclick={add}>{t('add.analyse')}{selected.size ? ` (${selected.size})` : ''}</button>
  </footer>
</dialog>

{#snippet row(d: LocalDir, label?: string)}
  <div class="row">
    <input type="checkbox" checked={selected.has(d.path)} disabled={!d.node || d.registered}
      onchange={(e) => toggle(d, e.currentTarget.checked)} aria-label={t('add.analyseFolder', { p: d.path })}
      title={d.registered ? t('add.registered') : d.node ? t('add.analyseThis') : t('add.noPkg')} />
    {#if label}
      <strong class="name">{label}</strong>
    {:else}
      <button class="ghost name" onclick={() => go(d.path)}>{d.name}</button>
    {/if}
    {#if d.node}<span class="pill">Node.js</span>{/if}
    {#if d.git}<span class="pill">git</span>{/if}
    {#if d.registered}<span class="pill">{t('add.registered')}</span>{/if}
  </div>
{/snippet}

<style>
  .body { display: grid; gap: 10px; padding: 12px 20px; min-width: 0; }
  header p { font-size: 13px; margin-top: 4px; }
  .crumbs { display: flex; flex-wrap: wrap; align-items: center; gap: 2px; }
  .crumbs button { padding: 2px 6px; }
  .list { max-height: 320px; overflow-y: auto; border: 1px solid var(--border); border-radius: 6px; }
  .row { display: flex; align-items: center; gap: 8px; padding: 4px 10px; border-bottom: 1px solid var(--border); }
  .row:last-child { border-bottom: 0; }
  .row:hover { background: var(--surface-2); }
  .row input { width: auto; }
  .name { flex: 1; min-width: 0; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; padding: 2px 4px; border: 0; }
  .empty { padding: 12px; text-align: center; }
</style>
