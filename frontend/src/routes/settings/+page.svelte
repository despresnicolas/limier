<script lang="ts">
  import { api } from '$lib/api';
  import { EDITORS, editor, saveEditor } from '$lib/editor.svelte';
  import { i18n, t, store, type Lang } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import { toast } from '$lib/toast.svelte';
  import { update, checkUpdate, refreshUpdate } from '$lib/update.svelte';
  import Load from '$lib/components/Load.svelte';
  import PolicyForm from '$lib/components/PolicyForm.svelte';
  import Help from '$lib/components/Help.svelte';

  const root = document.documentElement;
  // Display choices apply only when saved.
  let savedTheme = $state(root.dataset.theme ?? 'system');
  let theme = $state(root.dataset.theme ?? 'system');
  let lang = $state<Lang>(i18n.lang);
  let editorId = $state(editor.id);
  const changed = $derived(theme !== savedTheme || lang !== i18n.lang || editorId !== editor.id);
  const policy = resource(api.globalPolicy);
  const settings = resource(api.settings);

  // The watch setting lives in the backend: the 6-hourly recheck job reads it.
  async function setWatch(on: boolean) {
    try {
      await api.putSettings({ watch_vulns: on });
      toast(t(on ? 'settings.watchOn' : 'settings.watchOff'));
    } catch (err) {
      toast((err as Error).message, 'err');
    }
    settings.reload();
  }

  function save(e: SubmitEvent) {
    e.preventDefault();
    if (theme === 'system') delete root.dataset.theme;
    else root.dataset.theme = theme;
    store('theme', theme === 'system' ? null : theme);
    savedTheme = theme;
    i18n.lang = lang;
    store('lang', lang);
    saveEditor(editorId);
    toast(t('settings.displaySaved'));
  }

  let uninstallDialog = $state<HTMLDialogElement>();
  let leaving = $state(false);
  async function uninstall() {
    leaving = true;
    try {
      await api.uninstall(); // the app quits right after
    } catch (err) {
      leaving = false;
      toast(t('uninstall.failed', { e: (err as Error).message }), 'err');
    }
  }

  async function lookForUpdate() {
    checking = true;
    try {
      const st = await checkUpdate();
      if (st.error) toast(t('update.failed', { e: st.error }), 'err');
      else toast(st.available ? t('update.available', { v: st.available }) : t('update.upToDate'));
    } catch (err) {
      toast(t('update.failed', { e: (err as Error).message }), 'err');
    } finally {
      checking = false;
    }
  }
  let checking = $state(false);
  $effect(() => {
    refreshUpdate();
  });
</script>

<h1>{t('nav.settings')}</h1>

<form class="card" onsubmit={save}>
  <h2>{t('settings.display')}</h2>
  <div class="grid">
    <label>
      {t('settings.theme')}
      <select bind:value={theme}>
        <option value="system">{t('settings.themeSystem')}</option>
        <option value="light">{t('settings.themeLight')}</option>
        <option value="dark">{t('settings.themeDark')}</option>
      </select>
    </label>
    <label>
      {t('settings.language')}
      <select bind:value={lang}>
        <option value="fr">Français</option>
        <option value="en">English</option>
      </select>
    </label>
    <label>
      {t('settings.editor')}
      <select bind:value={editorId}>
        <option value="">{t('settings.editorAsk')}</option>
        {#each EDITORS as e (e.id)}<option value={e.id}>{e.name}</option>{/each}
      </select>
    </label>
  </div>
  <p class="muted hint">{t('settings.editorHint')}</p>
  <button type="submit" class="primary" disabled={!changed}>{t('action.save')}</button>
</form>

<section class="card">
  <h2>{t('settings.watch')}</h2>
  <Load r={settings}>
    {#snippet children(d)}
      <label class="check">
        <input type="checkbox" checked={d.watch_vulns} onchange={(e) => setWatch(e.currentTarget.checked)} />
        {t('settings.watchVulns')} <Help text={t('settings.watchHelp')} />
      </label>
    {/snippet}
  </Load>
</section>

<section class="card">
  <h2>{t('settings.globalPolicy')}</h2>
  <Load r={policy}>
    {#snippet children(d)}
      {#key d}
        <PolicyForm global rules={d.policy.rules} effective={d.effective} save={async (r) => { await api.putGlobalPolicy(r); policy.reload(); }} />
      {/key}
    {/snippet}
  </Load>
</section>

<section class="card">
  <h2>{t('update.title')}</h2>
  {#if update.status?.enabled}
    <p class="hint">{t('update.current', { v: update.status.current })}</p>
    <p class="muted hint">{t('update.hint')}</p>
    <button type="button" disabled={checking} onclick={lookForUpdate}>{t('update.check')}</button>
  {:else}
    <p class="muted hint">{t('update.dev')}</p>
  {/if}
</section>

<section class="card">
  <h2>{t('uninstall.title')}</h2>
  <p class="muted hint">{t('uninstall.hint')}</p>
  <button type="button" class="danger" onclick={() => uninstallDialog?.showModal()}>{t('uninstall.button')}</button>
</section>

<dialog bind:this={uninstallDialog} aria-label={t('uninstall.ask')}>
  <header><h2>{t('uninstall.ask')}</h2></header>
  <div class="body">
    <p>{t('uninstall.what')}</p>
    <ul>
      <li>{t('uninstall.data')}</li>
      <li>{t('uninstall.prefs')}</li>
      <li>{t('uninstall.app')}</li>
    </ul>
    <p class="muted">{t('uninstall.keep')}</p>
  </div>
  <footer>
    <button type="button" onclick={() => uninstallDialog?.close()}>{t('action.cancel')}</button>
    <button type="button" class="danger" disabled={leaving} onclick={uninstall}>{t('uninstall.confirm')}</button>
  </footer>
</dialog>

<style>
  section, form { margin-bottom: 16px; }
  form button { margin-top: 16px; }
  .hint { margin: 8px 0 0; font-size: 13px; }
  section > .hint + button { margin-top: 12px; }
  dialog { width: min(480px, 100vw - 32px); }
  .body { padding: 16px 20px; display: grid; gap: 8px; font-size: 13px; line-height: 1.45; }
  .body p, .body ul { margin: 0; }
  .body ul { padding-left: 18px; }
  .check { display: flex; align-items: center; gap: 6px; }
  .check input { width: auto; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 16px; max-width: 560px; }
</style>
