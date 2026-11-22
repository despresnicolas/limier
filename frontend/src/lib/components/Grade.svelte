<script lang="ts" module>
  /** Risk score 0..100 to grade, same bands as the backend badge. */
  export const gradeFromRisk = (risk: number) => (risk < 10 ? 'A' : risk < 30 ? 'B' : risk < 50 ? 'C' : risk < 70 ? 'D' : 'E');
</script>

<script lang="ts">
  import { t } from '$lib/i18n.svelte';
  // pending: a scan is running or none has finished yet, so the grade is not known.
  let { grade, size = 28, pending = false, title = '' }: { grade: string; size?: number; pending?: boolean; title?: string } = $props();
</script>

<span class="grade g{pending ? 'pending' : grade}" style:width="{size}px" style:height="{size}px" style:font-size="{size / 2}px"
  title={pending ? t('grade.pending') : title || t('grade.title', { g: grade })}>{pending ? '?' : grade}</span>

<style>
  /* Business scale A..E (Nutri-Score colors) */
  .grade { display: inline-grid; place-items: center; flex: none; border-radius: 6px; font-weight: 700; color: #fff; }
  .gA { background: #038141; }
  .gB { background: #85bb2f; }
  .gC { background: #fecb02; color: #1d1c1a; }
  .gD { background: #ee8100; }
  .gE { background: #e63e11; }
  .gpending { background: var(--muted); }
</style>
