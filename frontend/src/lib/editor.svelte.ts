// Editor that opens code findings at their line; the id is the URL scheme the backend allows.
import { api } from './api';
import { stored, store, t } from './i18n.svelte';
import { toast } from './toast.svelte';

export const EDITORS = [
  { id: 'vscode', name: 'VS Code' },
  { id: 'vscodium', name: 'VSCodium' },
  { id: 'cursor', name: 'Cursor' },
  { id: 'webstorm', name: 'WebStorm' },
  { id: 'idea', name: 'IntelliJ IDEA' },
  { id: 'phpstorm', name: 'PhpStorm' },
  { id: 'pycharm', name: 'PyCharm' },
  { id: 'goland', name: 'GoLand' },
  { id: 'rubymine', name: 'RubyMine' },
  { id: 'rider', name: 'Rider' },
  { id: 'clion', name: 'CLion' },
] as const;

/** Default editor id, or '' until the user picks one. */
export const editor = $state({ id: stored('editor') ?? '' });

export function saveEditor(id: string) {
  editor.id = id;
  store('editor', id || null);
}

/** A project's own editor, or '' when it uses the default one. */
export const projectEditor = (projectId: number) => stored(`editor:${projectId}`) ?? '';
export const saveProjectEditor = (projectId: number, id: string) => store(`editor:${projectId}`, id || null);
export const editorFor = (projectId: number) => projectEditor(projectId) || editor.id;
export const editorName = (id: string) => EDITORS.find((e) => e.id === id)?.name ?? '';

export async function openInEditor(projectId: number, file: string, line?: number) {
  try {
    await api.openInEditor(projectId, { editor: editorFor(projectId), file, line: line ?? 1 });
  } catch (err) {
    toast(t('editor.failed', { e: (err as Error).message }), 'err');
  }
}
