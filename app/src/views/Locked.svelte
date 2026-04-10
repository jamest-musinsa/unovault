<script lang="ts">
  // Locked Vault Home screen — matches the design spike at
  // design/spike/locked-home.html. Intentionally less polished in
  // this v0; the full design system lands in weeks 10-13.

  import { createVault, unlockVault, toCommandError } from '../lib/ipc';
  import { app } from '../lib/store.svelte';

  let password = $state('');
  let bundlePath = $state('');

  async function unlock() {
    if (!bundlePath.trim() || !password) return;
    app.setBusy(true);
    app.setError(null);
    try {
      const items = await unlockVault(bundlePath, password);
      password = ''; // drop the plaintext from JS as soon as possible
      app.onUnlock(items, bundlePath);
    } catch (raw) {
      const err = toCommandError(raw);
      app.setError(`${err.category}: ${err.message}`);
    } finally {
      app.setBusy(false);
    }
  }

  async function create() {
    if (!bundlePath.trim() || !password) return;
    app.setBusy(true);
    app.setError(null);
    try {
      const items = await createVault(bundlePath, password);
      password = '';
      app.onUnlock(items, bundlePath);
    } catch (raw) {
      const err = toCommandError(raw);
      app.setError(`${err.category}: ${err.message}`);
    } finally {
      app.setBusy(false);
    }
  }
</script>

<section class="locked-canvas">
  <div class="vault-card">
    <h1 class="brand">unovault</h1>
    <p class="vault-filename">{bundlePath || 'default.unovault'}</p>

    <form class="stack" onsubmit={(e) => { e.preventDefault(); unlock(); }}>
      <label for="bundle-path" class="sr-only">Vault path</label>
      <input
        id="bundle-path"
        type="text"
        class="input"
        placeholder="/path/to/default.unovault"
        bind:value={bundlePath}
        autocomplete="off"
      />

      <label for="master" class="sr-only">Master password</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input
        id="master"
        type="password"
        class="input"
        placeholder="Master password"
        bind:value={password}
        autocomplete="current-password"
        autofocus
      />

      <div class="actions">
        <button type="submit" class="btn-primary" disabled={app.busy}>
          {#if app.busy}Unlocking…{:else}Unlock{/if}
        </button>
        <button
          type="button"
          class="btn-secondary"
          onclick={create}
          disabled={app.busy}
        >
          Create new
        </button>
      </div>
    </form>

    {#if app.error}
      <div class="error-banner">{app.error}</div>
    {/if}
  </div>
</section>

<style>
  .locked-canvas {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--s-8);
  }

  .vault-card {
    width: 380px;
    padding: var(--s-8) var(--s-8) var(--s-6) var(--s-8);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    box-shadow: var(--shadow-3);
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
  }

  .brand {
    font-family: var(--font-serif);
    font-size: var(--fs-lg);
    font-weight: 400;
    font-style: italic;
    color: var(--text);
    margin: 0;
    text-align: center;
    letter-spacing: -0.005em;
  }
  .brand::first-letter { color: var(--accent); }

  .vault-filename {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--text-faint);
    margin: 0 0 var(--s-4) 0;
    text-align: center;
  }

  .stack {
    display: flex;
    flex-direction: column;
    gap: var(--s-3);
  }

  .actions {
    display: flex;
    gap: var(--s-2);
    margin-top: var(--s-2);
  }
  .actions > * { flex: 1; }
</style>
