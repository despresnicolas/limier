<script lang="ts">
  import { api } from '$lib/api';
  import { t } from '$lib/i18n.svelte';
  import { toast } from '$lib/toast.svelte';

  // Removes a root project and its workspaces from limier; the folder is never touched.
  let { id, path, ondeleted }: { id: number; path: string; ondeleted: () => void } = $props();

  let dialog = $state<HTMLDialogElement>();
  let deleting = $state(false);
  async function remove() {
    deleting = true;
    try {
      await api.deleteProject(id);
      toast(t('settings.deleted'));
      dialog?.close();
      ondeleted();
    } catch (err) {
      toast((err as Error).message, 'err');
    } finally {
      deleting = false;
    }
  }
</script>

<button class="danger" title={t('settings.deleteDesc')} onclick={() => dialog?.showModal()}>{t('settings.delete')}</button>
<dialog bind:this={dialog} aria-labelledby="del-title-{id}">
  <header><h2 id="del-title-{id}">{t('settings.deleteTitle')}</h2></header>
  <p class="body">{t('settings.deleteConfirm', { p: path })} {t('settings.deleteDesc')}</p>
  <footer>
    <button onclick={() => dialog?.close()}>{t('action.cancel')}</button>
    <button class="primary" disabled={deleting} onclick={remove}>{t('settings.delete')}</button>
  </footer>
</dialog>

<style>
  .danger { color: var(--err); white-space: nowrap; }
  dialog { width: min(480px, 100vw - 32px); }
  .body { padding: 16px 20px; margin: 0; }
</style>
