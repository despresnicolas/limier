<script lang="ts" generics="T">
  import type { Snippet } from 'svelte';
  import { t } from '$lib/i18n.svelte';
  let { r, children }: { r: { data?: T; error?: Error; loading: boolean; reload: () => void }; children: Snippet<[T]> } = $props();
</script>

{#if r.data !== undefined && !r.error}
  {@render children(r.data)}
{:else if r.error}
  <div class="card err" role="alert">
    <strong>{t('load.error')}</strong>
    <p class="muted">{r.error.message}</p>
    <button onclick={r.reload}>{t('action.retry')}</button>
  </div>
{:else}
  <p class="muted" aria-busy="true">{t('load.loading')}</p>
{/if}

<style>
  .err { display: grid; gap: 8px; justify-items: start; }
  .err strong { color: var(--err); }
</style>
