import { defineConfig } from 'vite';
import { resolve } from 'node:path';

// The Chrome extension needs multiple separate entry points bundled
// into standalone files (no shared chunks), which rules out Vite's
// default SPA build. We use Rollup directly through Vite's `lib`
// mode isn't flexible enough either — it only handles one entry per
// build. The trick that works: a single `build` with multiple
// `rollupOptions.input` entries and `output.entryFileNames` fixed so
// each file lands in `dist/<name>.js`.
//
// The extension's `manifest.json` references the output paths
// verbatim, so don't rename without updating the manifest.
export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    minify: false,
    sourcemap: true,
    rollupOptions: {
      input: {
        background: resolve(__dirname, 'src/background.ts'),
        content: resolve(__dirname, 'src/content.ts'),
        popup: resolve(__dirname, 'popup/popup.ts'),
      },
      output: {
        entryFileNames: '[name].js',
        // Each entry must be self-contained — Chrome's service
        // worker and content scripts can't share dynamic imports.
        inlineDynamicImports: false,
        manualChunks: undefined,
        format: 'es',
      },
    },
    // The `target` must match the Chrome minimum we declare in the
    // manifest. Chrome 114 supports ES2022 comfortably.
    target: 'chrome114',
  },
});
