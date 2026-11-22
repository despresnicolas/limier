<script lang="ts">
  import '../app.css';
  // The Wails runtime handles window dragging (--wails-draggable).
  import '@wailsio/runtime';
  import { route } from '$lib/route.svelte';
  import { goto } from '$app/navigation';
  import { api, ApiError } from '$lib/api';
  import { i18n, t, type Key } from '$lib/i18n.svelte';
  import { editor } from '$lib/editor.svelte';
  import EditorPicker from '$lib/components/EditorPicker.svelte';
  import UpdateBanner from '$lib/components/UpdateBanner.svelte';
  import { toasts } from '$lib/toast.svelte';
  import Icon, { type IconName } from '$lib/components/Icon.svelte';

  let { children } = $props();

  type Item = { href: string; label: Key; sub: Key; key: string; kbd: string; icon: IconName };
  const items: Item[] = [
    { href: '/', label: 'nav.dashboard', sub: 'nav.dashboardSub', key: '1', kbd: '⌘1', icon: 'dashboard' },
    { href: '/projects', label: 'nav.projects', sub: 'nav.projectsSub', key: '2', kbd: '⌘2', icon: 'folder' },
    { href: '/findings', label: 'nav.findings', sub: 'nav.findingsSub', key: '3', kbd: '⌘3', icon: 'shield' },
    { href: '/packages', label: 'nav.packages', sub: 'nav.packagesSub', key: '4', kbd: '⌘4', icon: 'package' },
    { href: '/settings', label: 'nav.settings', sub: 'nav.settingsSub', key: ',', kbd: '⌘,', icon: 'settings' },
  ];
  const active = (href: string) => (href === '/' ? route().pathname === '/' : route().pathname.startsWith(href));

  // The embedded backend starts with the window: wait for it.
  let ready = $state(false);
  let failure = $state('');
  $effect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const check = () =>
      api.features().then(
        () => (ready = true),
        (e) => {
          if (e instanceof ApiError && e.starting && e.message === 'starting') timer = setTimeout(check, 1000);
          else failure = (e as Error).message;
        },
      );
    check();
    return () => clearTimeout(timer);
  });

  $effect(() => {
    document.documentElement.lang = i18n.lang;
  });

  // At each launch until a default editor is saved: "Later" only skips it for this session.
  let picker = $state<EditorPicker>();
  let asked = false;
  $effect(() => {
    if (ready && picker && !editor.id && !asked) {
      asked = true;
      picker.show();
    }
  });

  function onkeydown(e: KeyboardEvent) {
    if (!(e.metaKey || e.ctrlKey) || e.altKey || e.shiftKey) return;
    const hit = items.find((it) => it.key === e.key);
    if (hit) {
      e.preventDefault();
      goto('#' + hit.href);
    }
  }
</script>

<svelte:window {onkeydown} />

<div class="drag" aria-hidden="true"></div>
<div class="shell">
  <nav aria-label={t('nav.label')}>
    {#each items as it (it.href)}
      <a href={'#' + it.href} class:active={active(it.href)} class:bottom={it.key === ','} aria-current={active(it.href) ? 'page' : undefined}>
        <Icon name={it.icon} />
        <span class="text">
          <strong>{t(it.label)}</strong>
          <span class="sub">{t(it.sub)}</span>
        </span>
        <kbd>{it.kbd}</kbd>
      </a>
    {/each}
  </nav>
  <main>
    {#if ready}
      <UpdateBanner />
      {@render children()}
    {:else if failure}
      <div class="card start" role="alert">
        <strong class="sev-error">{t('start.failed')}</strong>
        <code>{failure}</code>
        <p class="muted">{t('start.failedHint')}</p>
      </div>
    {:else}
      <div class="loading" role="status" aria-busy="true">
        <span class="spinner" aria-hidden="true"></span>
        <span class="muted">{t('start.waiting')}</span>
      </div>
    {/if}
  </main>
</div>

<EditorPicker bind:this={picker} />

<div class="toasts" aria-live="polite">
  {#each toasts as m (m.id)}
    <div class="toast {m.kind}">{m.text}</div>
  {/each}
</div>

<style>
  .shell { display: grid; grid-template-columns: 230px minmax(0, 1fr); min-height: 100vh; }
  .drag { display: none; }
  :global(:root[data-mac]) .drag {
    display: block; position: fixed; inset: 0 0 auto; height: 28px; z-index: 10;
    --wails-draggable: drag;
  }
  nav {
    display: flex; flex-direction: column; gap: 2px;
    position: sticky; top: 0; height: 100vh;
    padding: 12px 8px; background: var(--surface); border-right: 1px solid var(--border);
    --wails-draggable: drag;
  }
  nav a { --wails-draggable: no-drag; }
  :global(:root[data-mac]) nav { padding-top: 44px; }
  a {
    display: flex; align-items: center; gap: 10px;
    padding: 6px 8px; border-radius: 6px; color: inherit; text-decoration: none;
  }
  a:hover { background: var(--surface-2); }
  a.active { background: var(--accent-soft); color: var(--accent); }
  a.bottom { margin-top: auto; }
  .text { display: grid; min-width: 0; }
  .sub { font-size: 12px; color: var(--muted); }
  a.active .sub { color: inherit; }
  kbd { margin-left: auto; }
  main { padding: 28px 24px 60px; min-width: 0; }
  .start { display: grid; gap: 8px; max-width: 560px; }
  .loading { display: grid; place-items: center; align-content: center; gap: 12px; min-height: 60vh; }
  .spinner { width: 28px; height: 28px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .spinner { animation-duration: 3s; } }
  .toasts { position: fixed; right: 16px; bottom: 16px; display: grid; gap: 8px; z-index: 50; max-width: 360px; }
  .toast { overflow-wrap: anywhere; background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--ok); border-radius: 6px; padding: 8px 12px; font-size: 13px; }
  .toast.err { border-left-color: var(--err); }
  .toast.info { border-left-color: var(--info); }

  @media (max-width: 760px) {
    .shell { grid-template-columns: minmax(0, 1fr); }
    nav { flex-direction: row; height: auto; border-right: 0; border-bottom: 1px solid var(--border); z-index: 1; overflow-x: auto; }
    :global(:root[data-mac]) nav { padding-top: 32px; }
    .sub, kbd { display: none; }
    a.bottom { margin-top: 0; margin-left: auto; }
  }
</style>
