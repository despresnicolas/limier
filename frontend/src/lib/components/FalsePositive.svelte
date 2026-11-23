<script lang="ts">
  import { api } from '$lib/api';
  import { t } from '$lib/i18n.svelte';
  import { toast } from '$lib/toast.svelte';

  // Marks a code finding as a false positive (or, with restore, unmarks it); the backend then rescans the code.
  let { projectId, rule, file, detail = '', restore = false, ondone }: {
    projectId: number; rule: string; file: string; detail?: string; restore?: boolean; ondone: () => void;
  } = $props();
  let busy = $state(false);

  async function go() {
    busy = true;
    try {
      await api.setFalsePositive(projectId, { rule, file, detail, false_positive: !restore });
      toast(t(restore ? 'fp.restored' : 'fp.marked'));
      ondone();
    } catch (err) {
      toast(t('fp.failed', { e: (err as Error).message }), 'err');
    }
    busy = false;
  }
</script>

<button type="button" class="fp" disabled={busy} onclick={go} title={t(restore ? 'fp.restoreTitle' : 'fp.markTitle')}>
  {t(restore ? 'fp.restore' : 'fp.mark')}
</button>

<style>
  .fp { padding: 1px 8px; font-size: 11px; white-space: nowrap; background: transparent; color: var(--muted); }
  .fp:hover { color: var(--accent); }
</style>
