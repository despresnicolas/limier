<script lang="ts">
  // Minimal SVG line chart: one line per series, optionally stacked. No chart library.
  export type Series = { name: string; color: string; data: (number | null)[] };
  let { labels, series, stacked = false, label, height = 200 }: { labels: string[]; series: Series[]; stacked?: boolean; label: string; height?: number } = $props();

  const W = 600;
  const pad = { l: 36, r: 8, t: 8, b: 20 };
  const lines = $derived.by(() => {
    const acc = labels.map(() => 0);
    return series.map((s) => ({
      ...s,
      ys: s.data.map((v, i) => (stacked ? (acc[i] += v ?? 0) : v)),
    }));
  });
  const max = $derived(Math.max(1, ...lines.flatMap((l) => l.ys.filter((v): v is number => v !== null))));
  const x = (i: number) => pad.l + (labels.length < 2 ? 0 : (i * (W - pad.l - pad.r)) / (labels.length - 1));
  const y = (v: number) => pad.t + (1 - v / max) * (height - pad.t - pad.b);
  const d = (ys: (number | null)[]) =>
    ys.map((v, i) => (v === null ? '' : `${i && ys[i - 1] !== null ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`)).join('');
  const ticks = $derived([...new Set([0, max / 2, max].map((v) => Math.round(v)))]);
</script>

<figure>
  <svg viewBox="0 0 {W} {height}" role="img" aria-label={label}>
    {#each ticks as v (v)}
      <line x1={pad.l} x2={W - pad.r} y1={y(v)} y2={y(v)} class="grid" />
      <text x={pad.l - 6} y={y(v) + 4} text-anchor="end">{v}</text>
    {/each}
    {#if labels.length}
      <text x={pad.l} y={height - 4}>{labels[0]}</text>
      <text x={W - pad.r} y={height - 4} text-anchor="end">{labels[labels.length - 1]}</text>
    {/if}
    {#each lines as l (l.name)}
      <path d={d(l.ys)} style:stroke={l.color} fill="none" stroke-width="1.6" vector-effect="non-scaling-stroke" />
    {/each}
  </svg>
  <figcaption>
    {#each series as s (s.name)}
      <span><i style:background={s.color}></i>{s.name}</span>
    {/each}
  </figcaption>
</figure>

<style>
  figure { margin: 0; }
  svg { width: 100%; height: auto; display: block; }
  .grid { stroke: var(--border); stroke-dasharray: 3 3; }
  text { fill: var(--muted); font-size: 11px; }
  figcaption { display: flex; flex-wrap: wrap; gap: 12px; font-size: 12px; color: var(--muted); margin-top: 6px; }
  i { display: inline-block; width: 10px; height: 2px; margin-right: 4px; vertical-align: middle; }
</style>
