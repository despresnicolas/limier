<script lang="ts">
  import { api } from '$lib/api';
  import { t } from '$lib/i18n.svelte';
  import { toast } from '$lib/toast.svelte';

  // Same rule as fixbot.ValidBranchPrefix: a valid git ref part that never reads as an option.
  const valid = /^[A-Za-z0-9_][A-Za-z0-9._-]*(\/[A-Za-z0-9_][A-Za-z0-9._-]*)*$/;

  let { id, value }: { id: number; value: string } = $props();
  // Seeded once: the parent remounts the form with {#key}.
  // svelte-ignore state_referenced_locally
  let saved = $state(value);
  // svelte-ignore state_referenced_locally
  let prefix = $state(value);
  let busy = $state(false);
  let error = $state('');
  const clean = $derived(prefix.trim().replace(/^\/+|\/+$/g, ''));
  const ok = $derived(clean.length <= 50 && valid.test(clean) && !clean.includes('..') && !clean.endsWith('.lock') && !clean.endsWith('.'));

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!ok) return (error = t('settings.branchPrefixBad'));
    error = '';
    busy = true;
    try {
      saved = prefix = (await api.putBranchPrefix(id, clean)).branch_prefix;
      toast(t('settings.branchPrefixSaved'));
    } catch (err) {
      error = (err as Error).message;
    } finally {
      busy = false;
    }
  }
</script>

<form onsubmit={submit}>
  <p class="muted intro">{t('settings.branchPrefixIntro')}</p>
  <label>
    <span>{t('settings.branchPrefix')}</span>
    <input type="text" bind:value={prefix} placeholder="fix" maxlength="50" spellcheck="false" autocomplete="off" aria-invalid={!ok} />
  </label>
  <p class="preview">{t('settings.branchPrefixExample')} <code>{ok ? clean : '…'}/bump-lodash-4.17.21</code></p>
  {#if error}<p class="sev-error" role="alert">{error}</p>{/if}
  <button type="submit" class="primary" disabled={busy || clean === saved}>{t('action.save')}</button>
</form>

<style>
  .intro { font-size: 13px; margin: 0 0 12px; }
  label { display: grid; gap: 4px; max-width: 320px; font-size: 13px; }
  .preview { font-size: 13px; margin: 8px 0 12px; }
</style>
