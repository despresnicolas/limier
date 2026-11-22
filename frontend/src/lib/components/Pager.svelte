<script lang="ts">
  import { t } from '$lib/i18n.svelte';
  let { total, limit, offset, onchange }: { total: number; limit: number; offset: number; onchange: (o: number) => void } = $props();
  const page = $derived(Math.floor(offset / limit) + 1);
  const pages = $derived(Math.ceil(total / limit));
</script>

{#if total > limit}
  <nav class="pager" aria-label={t('pager.label')}>
    <span class="muted">{t('pager.range', { from: offset + 1, to: Math.min(offset + limit, total), total })}</span>
    <button class="ghost" disabled={page <= 1} onclick={() => onchange(Math.max(0, offset - limit))} aria-label={t('pager.prev')}>‹</button>
    <span>{page} / {pages}</span>
    <button class="ghost" disabled={page >= pages} onclick={() => onchange(offset + limit)} aria-label={t('pager.next')}>›</button>
  </nav>
{/if}

<style>
  .pager { display: flex; align-items: center; justify-content: flex-end; gap: 8px; margin-top: 12px; font-size: 13px; }
  .pager span:first-child { margin-right: auto; }
</style>
