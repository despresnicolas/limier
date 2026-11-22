// Shared updater state: the banner and the Settings card read the same status.
import { api } from './api';
import type { UpdateStatus } from './types';

export const update = $state<{ status?: UpdateStatus; dismissed: string }>({ dismissed: '' });

const busy = (s?: UpdateStatus) => s?.state === 'downloading' || s?.state === 'verifying' || s?.state === 'installing' || s?.state === 'ready';

export async function refreshUpdate() {
  try {
    update.status = await api.updateStatus();
  } catch {
    // Offline or an older backend: the banner just stays hidden.
  }
}

export async function checkUpdate() {
  update.status = await api.checkUpdate();
  update.dismissed = '';
  return update.status;
}

/** Starts download + signature check + swap; the app restarts by itself. Polls until then. */
export async function installUpdate() {
  update.status = await api.installUpdate();
  const poll = setInterval(async () => {
    await refreshUpdate();
    if (!busy(update.status) && update.status?.state !== 'available') clearInterval(poll);
    if (update.status?.error) clearInterval(poll);
  }, 1000);
}

export const installing = () => busy(update.status);
