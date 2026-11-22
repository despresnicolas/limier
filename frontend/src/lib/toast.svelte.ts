export type Toast = { id: number; kind: 'ok' | 'err' | 'info'; text: string };

export const toasts = $state<Toast[]>([]);
let next = 0;

export function toast(text: string, kind: Toast['kind'] = 'ok') {
  const id = next++;
  toasts.push({ id, kind, text });
  setTimeout(() => toasts.splice(toasts.findIndex((t) => t.id === id) >>> 0, 1), kind === 'err' ? 8000 : 4000);
}
