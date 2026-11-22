import { Browser } from '@wailsio/runtime';

// The webview does not open target="_blank" links: hand https links to the system browser.
export function openExternal(e: MouseEvent) {
  const href = (e.currentTarget as HTMLAnchorElement).href;
  e.preventDefault();
  if (href.startsWith('https://')) Browser.OpenURL(href).catch(() => {});
}

// GitHub keeps release notes under /releases; elsewhere the repository is the best guess.
export const changelogURL = (repo: string) => (repo.startsWith('https://github.com/') ? `${repo}/releases` : repo);
