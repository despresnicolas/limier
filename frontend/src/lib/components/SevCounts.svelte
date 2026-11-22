<script lang="ts">
  import { t } from '$lib/i18n.svelte';
  import type { SeverityCounts } from '$lib/types';
  import { sevClass } from './Sev.svelte';
  let { counts }: { counts: SeverityCounts } = $props();
  const items = $derived((['critical', 'high', 'medium', 'low'] as const).filter((s) => counts[s] > 0));
</script>

{#if items.length === 0}
  <span class="muted">{t('sev.none')}</span>
{:else}
  <span class="counts">
    {#each items as s (s)}<span class={sevClass[s]} title={t(`sev.${s}`)}>{counts[s]} {t(`sev.${s}Short`)}</span>{/each}
  </span>
{/if}

<style>
  .counts { display: inline-flex; flex-wrap: wrap; gap: 8px; font-variant-numeric: tabular-nums; white-space: nowrap; }
</style>
