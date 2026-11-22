<script lang="ts">
  import { t } from '$lib/i18n.svelte';
  import AddProject from './AddProject.svelte';

  // Empty state shared by the pages that need at least one project.
  let { onadded }: { onadded?: () => void } = $props();
</script>

<div class="card empty">
  <p>{t('dash.empty')}</p>
  <AddProject {onadded} />
</div>

<style>
  .empty { display: grid; gap: 12px; justify-items: start; }
  p { margin: 0; }
</style>
