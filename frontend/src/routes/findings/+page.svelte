<script lang="ts">
  import { api } from '$lib/api';
  import { t } from '$lib/i18n.svelte';
  import { resource } from '$lib/resource.svelte';
  import FindingsView from '$lib/components/FindingsView.svelte';
  import Load from '$lib/components/Load.svelte';
  import NoProjects from '$lib/components/NoProjects.svelte';

  const projects = resource(() => api.projects({ limit: 1 }));
</script>

<h1>{t('nav.findings')}</h1>
<p class="muted intro">{t('findings.intro')}</p>
<Load r={projects}>
  {#snippet children(p)}
    {#if p.total === 0}<NoProjects onadded={projects.reload} />{:else}<FindingsView />{/if}
  {/snippet}
</Load>

<style>
  .intro { margin: -8px 0 16px; font-size: 13px; }
</style>
