<script lang="ts">
  import EditorPicker from '$lib/components/EditorPicker.svelte';
  import Help from '$lib/components/Help.svelte';
  import { editorFor, openInEditor } from '$lib/editor.svelte';
  import { t } from '$lib/i18n.svelte';
  import type { CodeFunction, HotFile } from '$lib/types';

  let { list, files = [], projectId }: { list: CodeFunction[]; files?: HotFile[]; projectId?: number } = $props();

  // Same as CodeIssues: a click opens the file at the line, asking for an editor if none is set.
  let picker = $state<EditorPicker>();
  function open(file: string, line?: number) {
    const go = () => openInEditor(projectId!, file, line);
    if (editorFor(projectId!)) go();
    else picker?.show(go);
  }
  // Churn exists only with a git history: without it the list stays ranked by complexity.
  const withChurn = $derived(files.length > 0 || list.some((f) => f.churn));
</script>

{#snippet where(file: string, line?: number)}
  {#if projectId}
    <button type="button" class="where" title={t('editor.open')} onclick={() => open(file, line)}><code>{file}{line ? `:${line}` : ''}</code></button>
  {:else}<code>{file}{line ? `:${line}` : ''}</code>{/if}
{/snippet}

{#if projectId}<EditorPicker bind:this={picker} />{/if}

{#if files.length}
  <h3>{t('code.hotFiles')} ({files.length})</h3>
  <p class="muted hint">{t('code.hotFilesHint')}</p>
  <div class="scroll-x">
    <table>
      <thead><tr><th>{t('code.where')}</th><th class="num">{t('code.churn')} <Help text={t('code.churnHelp')} /></th><th class="num">{t('code.complexity')}</th><th class="num">{t('code.lines')}</th><th class="num">{t('code.score')}</th></tr></thead>
      <tbody>
        {#each files as f (f.file)}
          <tr>
            <td>{@render where(f.file)}</td><td class="num">{f.churn}</td>
            <td class="num" class:sev-error={f.complexity > 30} class:sev-warning={f.complexity > 15 && f.complexity <= 30}>{f.complexity}</td>
            <td class="num">{f.lines}</td><td class="num"><strong>{f.score}</strong></td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  <h3>{t('code.hotspots')}</h3>
{/if}

{#if !list.length}<p class="muted">{t('code.noHotspots')}</p>{:else}
  <div class="scroll-x">
    <table>
      <thead><tr><th>{t('code.function')}</th><th>{t('code.where')}</th>{#if withChurn}<th class="num">{t('code.churn')} <Help text={t('code.churnHelp')} /></th>{/if}<th class="num">{t('code.complexity')} <Help text={t('code.complexityHelp')} /></th><th class="num">{t('code.lines')}</th><th class="num">{t('code.params')} <Help text={t('code.paramsHelp')} /></th><th class="num">{t('code.nesting')} <Help text={t('code.nestingHelp')} /></th></tr></thead>
      <tbody>
        {#each list as f, k (k)}
          <tr>
            <td><code>{f.name}</code></td><td>{@render where(f.file, f.line)}</td>
            {#if withChurn}<td class="num">{f.churn ?? 0}</td>{/if}
            <td class="num" class:sev-error={f.complexity > 30} class:sev-warning={f.complexity > 15 && f.complexity <= 30}>{f.complexity}</td>
            <td class="num">{f.lines}</td><td class="num" class:sev-warning={f.params > 5}>{f.params}</td><td class="num" class:sev-warning={f.max_nesting > 4}>{f.max_nesting}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  code { word-break: break-all; }
  .where { background: none; border: none; padding: 0; text-align: left; cursor: pointer; color: inherit; }
  .where:hover code { text-decoration: underline; }
</style>
