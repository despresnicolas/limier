<script lang="ts">
  import { api } from '$lib/api';
  import { t } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import type { ProjectDetail } from '$lib/types';
  import Load from '$lib/components/Load.svelte';
  import PolicyForm from '$lib/components/PolicyForm.svelte';
  import BranchPrefixForm from '$lib/components/BranchPrefixForm.svelte';
  import { EDITORS, editor, editorName, projectEditor, saveProjectEditor } from '$lib/editor.svelte';
  import { toast } from '$lib/toast.svelte';

  // Workspaces share the root project's policy.
  let { detail }: { detail: ProjectDetail } = $props();
  const rootId = $derived(detail.root_project_id);
  const isWorkspace = $derived(rootId !== detail.project.id);
  const root = resource(() => (isWorkspace ? api.project(rootId) : Promise.resolve(detail)));
  const policy = resource(() => api.projectPolicy(rootId));

  // Stored on this device, like the default editor; '' follows the default one.
  const pid = $derived(detail.project.id);
  let projEditor = $state('');
  $effect(() => {
    projEditor = projectEditor(pid);
  });
  function saveEditorChoice() {
    saveProjectEditor(pid, projEditor);
    toast(t('project.editorSaved', { name: editorName(projEditor || editor.id) || t('project.editorNone') }));
  }
</script>

<Load r={root}>
  {#snippet children(base)}
    {@const p = base.project}
    {#if isWorkspace}
      <p class="card note">{t('settings.workspace')} <a href="#/projects/{rootId}?tab=settings">{p.path}</a></p>
    {/if}

    <section class="card">
      <h2>{t('settings.folder')}</h2>
      <dl>
        <div><dt>{t('settings.path')}</dt><dd><code>{p.local_path}</code></dd></div>
        <div><dt>{t('projects.pm')}</dt><dd>{p.package_manager || t('project.unknownPm')}</dd></div>
      </dl>
    </section>

    <section class="card">
      <h2>{t('project.editor')}</h2>
      <label class="editor">
        {t('project.editorLabel')}
        <select bind:value={projEditor} onchange={saveEditorChoice}>
          <option value="">{t('project.editorDefault', { name: editorName(editor.id) || t('project.editorNone') })}</option>
          {#each EDITORS as e (e.id)}<option value={e.id}>{e.name}</option>{/each}
        </select>
      </label>
      <p class="muted hint">{t('project.editorHint')}</p>
    </section>

    <section class="card">
      <h2>{t('settings.fixes')}</h2>
      {#key p.id}<BranchPrefixForm id={p.id} value={p.branch_prefix ?? 'fix'} />{/key}
    </section>

    <section class="card">
      <h2>{t('settings.policy')}</h2>
      <Load r={policy}>
        {#snippet children(pol)}
          {#key pol}
            <PolicyForm rules={pol.rules} effective={pol.effective} save={async (r) => { await api.putProjectPolicy(rootId, r); policy.reload(); }} />
          {/key}
        {/snippet}
      </Load>
    </section>

  {/snippet}
</Load>

<style>
  section { margin-bottom: 16px; }
  .note { margin-bottom: 16px; font-size: 13px; }
  dl { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 0; }
  dt { font-size: 12px; color: var(--muted); }
  dd { margin: 2px 0 0; }
  .editor { display: grid; gap: 4px; max-width: 320px; }
  .hint { margin: 8px 0 0; font-size: 13px; }
</style>
