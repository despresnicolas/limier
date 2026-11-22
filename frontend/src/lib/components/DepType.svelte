<script lang="ts">
  import { t } from '$lib/i18n.svelte';

  // Direct or indirect; an indirect package also names the direct dependencies that pull it in.
  // Scans before the lockfile graph only have the shortest path, whose first step is one of them.
  let { direct, via, path }: { direct: boolean; via?: string[] | null; path?: string[] | null } = $props();
  const names = $derived(via?.length ? via : path?.length && path.length > 1 ? [path[0]] : []);
</script>

{#if direct}{t('dep.directOne')}{:else}
  <span title={path?.length ? path.join(' → ') : undefined}>{t('dep.transitiveOne')}</span>
  {#if names.length}
    <div class="via" title={names.join(', ')}>
      {t('dep.via')} <code>{names[0]}</code>{#if names.length > 1}{' '}{t('dep.viaMore', { n: names.length - 1 })}{/if}
    </div>
  {/if}
{/if}

<style>
  .via { font-size: 12px; color: var(--muted); }
  .via code { overflow-wrap: normal; white-space: nowrap; }
</style>
