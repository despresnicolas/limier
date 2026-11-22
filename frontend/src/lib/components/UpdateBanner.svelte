<script lang="ts">
  import { t } from '$lib/i18n.svelte';
  import { update, refreshUpdate, installUpdate, installing } from '$lib/update.svelte';
  import { toast } from '$lib/toast.svelte';

  // The backend checks at start and every 24 h; the UI only reads the local status.
  $effect(() => {
    refreshUpdate();
    const timer = setInterval(refreshUpdate, 10 * 60 * 1000);
    return () => clearInterval(timer);
  });
  const s = $derived(update.status);
  const show = $derived(!!s?.available && (installing() || (s.available !== update.dismissed && s.state !== 'up-to-date')));

  async function install() {
    try {
      await installUpdate();
    } catch (err) {
      toast(t('update.failed', { e: (err as Error).message }), 'err');
    }
  }
</script>

{#if show && s}
  <div class="banner" role="status">
    {#if installing()}
      <span class="spin" aria-hidden="true"></span>
      <span>{t(`update.state.${s.state}` as 'update.state.downloading')}</span>
    {:else}
      <span><strong>{t('update.available', { v: s.available ?? '' })}</strong>{#if s.notes} — {s.notes}{/if}</span>
      {#if s.error}<span class="sev-error small">{t('update.failed', { e: s.error })}</span>{/if}
      <span class="actions">
        <button type="button" onclick={() => (update.dismissed = s.available ?? '')}>{t('update.later')}</button>
        <button type="button" class="primary" onclick={install}>{t('update.install')}</button>
      </span>
    {/if}
  </div>
{/if}

<style>
  .banner { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 10px 16px; margin-bottom: 16px; border: 1px solid var(--accent); border-radius: 10px; background: var(--accent-soft); font-size: 13px; }
  .actions { margin-left: auto; display: flex; gap: 8px; }
  .small { font-size: 12px; }
  .spin { width: 14px; height: 14px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
