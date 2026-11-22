/**
 * Loads data and reloads it whenever the reactive values read by `fn` change.
 * The previous data stays shown while reloading, so tables don't flash.
 */
export function resource<T>(fn: () => Promise<T>, opts: { poll?: (data: T | undefined) => number | false } = {}) {
  const r = $state({ data: undefined as T | undefined, error: undefined as Error | undefined, loading: true, reload: () => {} });
  let run = 0;
  $effect(() => {
    const id = ++run;
    const load = () => {
      r.loading = true;
      fn().then(
        (d) => id === run && Object.assign(r, { data: d, error: undefined, loading: false }),
        (e: Error) => id === run && Object.assign(r, { error: e, loading: false }),
      );
    };
    r.reload = load;
    load();
    return () => run++;
  });
  $effect(() => {
    const ms = opts.poll?.(r.data);
    if (!ms || r.loading) return;
    const t = setTimeout(r.reload, ms);
    return () => clearTimeout(t);
  });
  return r;
}
