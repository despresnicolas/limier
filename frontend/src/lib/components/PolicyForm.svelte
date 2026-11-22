<script lang="ts">
  import { t } from '$lib/i18n.svelte';
  import { toast } from '$lib/toast.svelte';
  import type { EffectiveRules, PolicyRules, PriorityWeights } from '$lib/types';
  import Help from './Help.svelte';

  // Policy rules that apply to local projects. Unset fields inherit (project: from the global policy; global: built-in defaults).
  let { rules, effective, save, global = false }: {
    rules: PolicyRules;
    effective: EffectiveRules;
    save: (r: PolicyRules) => Promise<unknown>;
    global?: boolean;
  } = $props();

  const WEIGHTS: { key: keyof PriorityWeights; max?: number }[] = [
    { key: 'cvss' }, { key: 'epss' }, { key: 'kev' }, { key: 'unreachable', max: 1 }, { key: 'transitive', max: 1 },
  ];
  // svelte-ignore state_referenced_locally
  const w0 = rules.priority_weights ?? effective.priority_weights;
  // svelte-ignore state_referenced_locally
  let maxAge = $state(rules.max_dependency_age_days ? String(rules.max_dependency_age_days) : '');
  // svelte-ignore state_referenced_locally
  let minRelease = $state(rules.min_release_age_days !== undefined ? String(rules.min_release_age_days) : '');
  // svelte-ignore state_referenced_locally
  let weightsOverride = $state(!!rules.priority_weights);
  let weights = $state(Object.fromEntries(WEIGHTS.map(({ key }) => [key, String(w0?.[key] ?? 0)])) as Record<keyof PriorityWeights, string>);
  let error = $state('');
  let busy = $state(false);
  const inherit = $derived(global ? t('policy.default') : t('policy.inherit'));

  /** Returns the rules to save, or an error message. */
  function toRules(): PolicyRules | string {
    const r: PolicyRules = {};
    if (maxAge.trim()) {
      const n = Number(maxAge);
      if (!Number.isInteger(n) || n < 0) return t('policy.badAge');
      if (n > 0) r.max_dependency_age_days = n;
    }
    if (minRelease.trim()) {
      const n = Number(minRelease);
      if (!Number.isInteger(n) || n < 0 || n > 90) return t('policy.badMinRelease');
      r.min_release_age_days = n; // 0 is kept: it turns the inherited limit off
    }
    if (weightsOverride) {
      const w = {} as PriorityWeights;
      for (const { key, max } of WEIGHTS) {
        const n = Number(weights[key]);
        if (weights[key].trim() === '' || !Number.isFinite(n) || n < 0 || (max !== undefined && n > max)) {
          return t('policy.badWeight', { w: t(`weight.${key}`), r: max !== undefined ? `0–${max}` : '≥ 0' });
        }
        w[key] = n;
      }
      r.priority_weights = w;
    }
    return r;
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    const r = toRules();
    if (typeof r === 'string') return (error = r);
    error = '';
    busy = true;
    try {
      await save(r);
      toast(t('policy.saved'));
    } catch (err) {
      error = (err as Error).message;
    } finally {
      busy = false;
    }
  }
</script>

<form onsubmit={submit}>
  <p class="muted intro">{global ? t('policy.introGlobal') : t('policy.introProject')}</p>

  <fieldset>
    <label>
      <span>{t('policy.maxAge')} <Help text={t('policy.maxAgeHelp')} /></span>
      <input type="number" min="0" bind:value={maxAge} placeholder={inherit} />
      <span>{t('policy.effective', { v: effective.max_dependency_age_days ? t('policy.days', { n: effective.max_dependency_age_days }) : t('policy.noLimit') })}</span>
    </label>
    <label>
      <span>{t('policy.minRelease')} <Help text={t('policy.minReleaseHelp')} /></span>
      <input type="number" min="0" max="90" bind:value={minRelease} placeholder={inherit} />
      <span>{t('policy.effective', { v: effective.min_release_age_days ? t('policy.days', { n: effective.min_release_age_days }) : t('policy.disabled') })}</span>
    </label>
  </fieldset>

  <fieldset>
    <legend><label class="check"><input type="checkbox" bind:checked={weightsOverride} /> {t('policy.weightsOverride')}</label>
      <Help text={t('policy.weightsHelp')} /></legend>
    <div class="weights">
      {#each WEIGHTS as { key, max } (key)}
        <label>
          {t(`weight.${key}`)}
          <input type="number" step="0.05" min="0" {max} bind:value={weights[key]} disabled={!weightsOverride} />
          <span>{max !== undefined ? `0–${max}` : '≥ 0'} · {t('policy.effectiveShort', { v: effective.priority_weights?.[key] ?? '—' })}</span>
        </label>
      {/each}
    </div>
  </fieldset>

  {#if error}<p class="sev-error" role="alert">{error}</p>{/if}
  <button type="submit" class="primary" disabled={busy}>{t('policy.save')}</button>
</form>

<style>
  form { display: grid; gap: 16px; }
  .intro { font-size: 13px; }
  fieldset { border: 0; padding: 0; margin: 0; display: grid; gap: 8px; max-width: 720px; }
  legend { display: flex; align-items: center; gap: 6px; padding: 0; margin-bottom: 8px; }
  .check { display: flex; align-items: center; gap: 6px; font-size: 14px; color: var(--text); }
  .check input { width: auto; }
  .weights { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; }
  button { justify-self: start; }
</style>
