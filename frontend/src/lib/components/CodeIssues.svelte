<script lang="ts">
  import { editorFor, openInEditor } from '$lib/editor.svelte';
  import EditorPicker from '$lib/components/EditorPicker.svelte';
  import { t, ruleTitle, ruleHelp } from '$lib/i18n.svelte';
  import type { CodeIssue, IssueSeverity } from '$lib/types';

  // With projectId, file:line opens the file in the user's editor.
  let { list, empty, detailLabel, projectId }: { list: CodeIssue[]; empty: string; detailLabel: string; projectId?: number } = $props();
  const sevClass: Record<IssueSeverity, string> = { high: 'sev-error', medium: 'sev-warning', low: 'sev-info', info: 'muted' };
  let onlyNew = $state(false);
  const hasNew = $derived(list.some((i) => i.new));
  const shown = $derived(onlyNew && hasNew ? list.filter((i) => i.new) : list);
  const where = (i: { file: string; line?: number }) => (i.line ? `${i.file}:${i.line}` : i.file);
  // Rules a limier-ignore comment can hide (backend ignore package); never node.eol or imports.
  const ignorable = (rule: string) => /^(sast|quality|secret)\./.test(rule);

  // Without any editor (first-launch question skipped), the click asks for the default one.
  let picker = $state<EditorPicker>();
  function open(i: CodeIssue) {
    const go = () => openInEditor(projectId!, i.file, i.line);
    if (editorFor(projectId!)) go();
    else picker?.show(go);
  }
</script>

<!-- `backticks` in rule help become inline code -->
{#snippet rich(s: string)}{#each s.split('`') as part, n (n)}{#if n % 2}<code>{part}</code>{:else}{part}{/if}{/each}{/snippet}

{#if !list.length}<p class="muted">{empty}</p>{:else}
  {#if hasNew}
    <label class="check"><input type="checkbox" bind:checked={onlyNew} /> {t('code.newOnly')}</label>
  {/if}
  <div class="scroll-x">
    <table>
      <thead><tr><th>{t('code.severity')}</th><th>{t('code.what')}</th><th>{t('code.where')}</th><th>{detailLabel}</th></tr></thead>
      <tbody>
        {#each shown as i, k (k)}
          <tr>
            <td class={sevClass[i.severity] ?? 'muted'}>{t(`code.sev.${i.severity ?? 'info'}`)}</td>
            <td>
              {ruleTitle(i.rule)}
              {#if i.new}<span class="pill new" title={t('findings.newTitle')}>{t('findings.new')}</span>{/if}
              {#if ruleHelp(i.rule, 'why') || ruleHelp(i.rule, 'fix') || ignorable(i.rule)}
                <details class="help">
                  <summary>{t('code.help')}</summary>
                  {#if ruleHelp(i.rule, 'why')}<p><b>{t('code.why')}</b> {@render rich(ruleHelp(i.rule, 'why'))}</p>{/if}
                  {#if ruleHelp(i.rule, 'fix')}<p><b>{t('code.fix')}</b> {@render rich(ruleHelp(i.rule, 'fix'))}</p>{/if}
                  {#if ignorable(i.rule)}<p class="muted">{@render rich(t('code.ignoreTip', { rule: i.rule }))}</p>{/if}
                </details>
              {/if}
            </td>
            <td>
              {#if projectId}
                <button type="button" class="where" title={t('editor.open')} onclick={() => open(i)}><code>{where(i)}</code></button>
              {:else}<code>{where(i)}</code>{/if}
            </td>
            <td class="detail">{i.detail ?? ''}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if projectId}<EditorPicker bind:this={picker} />{/if}

<style>
  .where { background: none; border: none; padding: 0; text-align: left; cursor: pointer; color: inherit; }
  .where:hover code { text-decoration: underline; }
  .detail { font-size: 12px; color: var(--muted); word-break: break-word; }
  code { word-break: break-all; }
  .new { color: var(--accent); border-color: var(--accent); }
  .check { display: inline-flex; align-items: center; gap: 6px; margin-bottom: 8px; font-size: 13px; }
  .check input { width: auto; }
  .help { margin-top: 4px; max-width: 60ch; font-size: 12px; }
  .help summary { cursor: pointer; color: var(--muted); width: fit-content; }
  .help summary:hover, .help[open] summary { color: var(--accent); }
  .help p { margin: 6px 0 0; line-height: 1.45; }
  .help code { word-break: normal; overflow-wrap: anywhere; }
</style>
