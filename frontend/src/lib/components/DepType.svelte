<script lang="ts">
  import { t } from '$lib/i18n.svelte';

  // Direct or indirect; an indirect package also names the direct dependencies that pull it in.
  // Scans before the lockfile graph only have the shortest path, whose first step is one of them.
  let { direct, via, path }: { direct: boolean; via?: string[] | null; path?: string[] | null } = $props();
  const MAX = 3;
  const names = $derived(via?.length ? via : path?.length && path.length > 1 ? [path[0]] : []);
</script>

{#if direct}{t('dep.directOne')}{:else}
  <span title={path?.length ? path.join(' → ') : undefined}>{t('dep.transitiveOne')}</span>
  {#if names.length}
    <div class="via" title={names.join(', ')}>
      {t('dep.via')} {#each names.slice(0, MAX) as n, i (n)}{#if i}, {/if}<code>{n}</code>{/each}{#if names.length > MAX} {t('dep.viaMore', { n: names.length - MAX })}{/if}
    </div>
  {/if}
{/if}

<style>
  .via { font-size: 12px; color: var(--muted); }
</style>
