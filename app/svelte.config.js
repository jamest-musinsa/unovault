import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

// Minimal Svelte config — Vite + TypeScript preprocessor. No
// adapter, no router layer, no SvelteKit. The Tauri app is a
// single-window app whose top-level view is picked by a store,
// not a URL.
export default {
  preprocess: vitePreprocess(),
  compilerOptions: {
    // Svelte 5 runes mode — use $state, $derived, $effect in
    // components instead of the legacy reactive-variable syntax.
    runes: true,
  },
};
