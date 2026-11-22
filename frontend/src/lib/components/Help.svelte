<script lang="ts">
  // "?" help: shown on hover AND keyboard focus, kept inside the window, closed by Escape.
  let { text }: { text: string } = $props();
  let btn: HTMLButtonElement;
  let tip = $state<HTMLDivElement>();
  let open = $state(false);
  let pos = $state({ x: 0, y: 0 });

  $effect(() => {
    if (!open || !tip) return;
    const b = btn.getBoundingClientRect();
    const w = tip.offsetWidth;
    const h = tip.offsetHeight;
    const x = Math.min(Math.max(8, b.left + b.width / 2 - w / 2), innerWidth - w - 8);
    // Above the "?" so the cursor never covers the text; below only when there is no room on top.
    const y = b.top - h - 6 < 8 ? b.bottom + 6 : b.top - h - 6;
    pos = { x, y };
  });
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && (open = false)} />

<button type="button" class="help" aria-label={text} bind:this={btn}
  onmouseenter={() => (open = true)} onmouseleave={() => (open = false)}
  onfocus={() => (open = true)} onblur={() => (open = false)}>?</button>
{#if open}
  <div class="tip" role="tooltip" bind:this={tip} style:left="{pos.x}px" style:top="{pos.y}px">{text}</div>
{/if}

<style>
  .help {
    display: inline-grid; place-items: center; width: 16px; height: 16px; padding: 0;
    border-radius: 99px; font-size: 11px; line-height: 1; color: var(--muted); vertical-align: middle;
  }
  .tip {
    position: fixed; z-index: 100; max-width: 300px; padding: 6px 8px; border-radius: 6px;
    background: var(--text); color: var(--bg); font-size: 12px; font-weight: 400; pointer-events: none;
    white-space: pre-line; text-align: left;
  }
</style>
