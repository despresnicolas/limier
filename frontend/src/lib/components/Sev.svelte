<script lang="ts" module>
  import type { Severity } from '$lib/types';
  export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown'];
  export const sevClass: Record<Severity, string> = {
    critical: 'sev-error strong', high: 'sev-error', medium: 'sev-warning', low: 'sev-info', unknown: 'muted',
  };
</script>

<script lang="ts">
  import { t } from '$lib/i18n.svelte';
  let { severity }: { severity: Severity | string } = $props();
  const s = $derived((SEVERITIES.includes(severity as Severity) ? severity : 'unknown') as Severity);
</script>

<span class={sevClass[s]}>{t(`sev.${s}`)}</span>

<style>
  .strong { font-weight: 600; }
</style>
