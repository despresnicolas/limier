<script lang="ts">
  import Help from '$lib/components/Help.svelte';
  import { t } from '$lib/i18n.svelte';
  import type { CodeFunction, HotFile } from '$lib/types';

  let { list, files = [] }: { list: CodeFunction[]; files?: HotFile[] } = $props();
  // Churn exists only with a git history: without it the list stays ranked by complexity.
  const withChurn = $derived(files.length > 0 || list.some((f) => f.churn));
</script>

{#if files.length}
  <h3>{t('code.hotFiles')} ({files.length})</h3>
  <p class="muted hint">{t('code.hotFilesHint')}</p>
  <div class="scroll-x">
    <table>
      <thead><tr><th>{t('code.where')}</th><th class="num">{t('code.churn')} <Help text={t('code.churnHelp')} /></th><th class="num">{t('code.complexity')}</th><th class="num">{t('code.lines')}</th><th class="num">{t('code.score')}</th></tr></thead>
      <tbody>
        {#each files as f (f.file)}
          <tr>
            <td><code>{f.file}</code></td><td class="num">{f.churn}</td>
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
            <td><code>{f.name}</code></td><td><code>{f.file}:{f.line}</code></td>
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
</style>
