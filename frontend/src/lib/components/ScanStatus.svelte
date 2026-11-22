<script lang="ts">
  import { t } from '$lib/i18n.svelte';
  import type { ScanStatus } from '$lib/types';
  let { status }: { status: ScanStatus | null | undefined } = $props();
  const cls: Record<ScanStatus, string> = { queued: 'muted', running: 'accent', succeeded: 'ok', failed: 'sev-error' };
</script>

{#if status}<span class={cls[status]}>{t(`scan.${status}`)}</span>{:else}<span class="muted">—</span>{/if}

<style>
  .accent { color: var(--accent); }
  .ok { color: var(--ok); }
</style>
