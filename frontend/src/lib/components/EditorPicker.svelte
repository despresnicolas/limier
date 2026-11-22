<script lang="ts">
  import { EDITORS, editor, saveEditor } from '$lib/editor.svelte';
  import { t } from '$lib/i18n.svelte';

  // Asks for the default editor: at first launch (layout), or at the first click if the user skipped it.
  let dialog = $state<HTMLDialogElement>();
  let choice = $state<string>(editor.id || EDITORS[0].id);
  let after: (() => void) | undefined;

  export function show(then?: () => void) {
    after = then;
    choice = editor.id || EDITORS[0].id;
    dialog?.showModal();
  }
  function pick(e: SubmitEvent) {
    e.preventDefault();
    saveEditor(choice);
    dialog?.close();
    after?.();
    after = undefined;
  }
</script>

<dialog bind:this={dialog} aria-label={t('editor.pickTitle')}>
  <form onsubmit={pick}>
    <header><h2>{t('editor.pickTitle')}</h2></header>
    <div class="body">
      <p>{t('editor.pickWhy')}</p>
      <label>
        {t('settings.editor')}
        <select bind:value={choice}>
          {#each EDITORS as e (e.id)}<option value={e.id}>{e.name}</option>{/each}
        </select>
      </label>
      <p class="muted">{t('editor.pickHint')}</p>
    </div>
    <footer>
      <button type="button" onclick={() => dialog?.close()}>{t('editor.later')}</button>
      <button type="submit" class="primary">{t('action.save')}</button>
    </footer>
  </form>
</dialog>

<style>
  dialog { width: min(440px, 100vw - 32px); }
  .body { padding: 16px 20px; display: grid; gap: 10px; }
  .body p { margin: 0; font-size: 13px; line-height: 1.45; }
</style>
