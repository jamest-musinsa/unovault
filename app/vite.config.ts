// vite.config.ts — Vite configuration for the Svelte frontend.
//
// Tauri expects the dev server on a fixed port (1420) so the runtime
// knows where to load the WebView contents from. `strictPort` is set
// so port conflicts fail loudly instead of silently moving to a
// different port the Tauri runtime does not know about.

import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Tauri v2 expects the devUrl in tauri.conf.json to match here.
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: 'ws',
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // Don't watch src-tauri — the Tauri CLI handles Rust rebuilds.
      ignored: ['**/src-tauri/**'],
    },
  },
  build: {
    // Match the minimum supported macOS version — Tauri v2 requires
    // WKWebView features from Safari 15+ on macOS 12+, so we can use
    // fairly modern JS without transpilation overhead.
    target: 'es2022',
    minify: 'esbuild',
    sourcemap: true,
    outDir: 'dist',
    emptyOutDir: true,
  },
});
