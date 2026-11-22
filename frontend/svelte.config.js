import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default {
  preprocess: vitePreprocess(),
  kit: {
    // main.go embeds frontend/dist
    adapter: adapter({ pages: 'dist', assets: 'dist', fallback: 'index.html' }),
    // Hash routes: a reload never asks the Wails asset server for a path it doesn't have
    router: { type: 'hash' },
  },
};
