<script lang="ts">
  // Locked Vault Home — rebuilt on top of primitives. Matches the
  // structure of design/spike/locked-home.html but uses Card +
  // Input + Button + FieldLabel instead of inline CSS.

  import { createVault, unlockVault, toCommandError } from '../lib/ipc';
  import { app } from '../lib/store.svelte';
  import Card from '../lib/components/Card.svelte';
  import Button from '../lib/components/Button.svelte';
  import Input from '../lib/components/Input.svelte';
  import ErrorBanner from '../lib/components/ErrorBanner.svelte';

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
      app.setError(toCommandError(raw));
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
      app.setError(toCommandError(raw));
    } finally {
      app.setBusy(false);
    }
  }
</script>

<section class="locked-canvas">
  <Card width={380} padding="md">
    <header class="brand-header">
      <h1 class="t-brand">unovault</h1>
      <p class="filename t-mono">{bundlePath || 'default.unovault'}</p>
    </header>

    <form
      class="stack"
      onsubmit={(e) => {
        e.preventDefault();
        unlock();
      }}
    >
      <label for="bundle-path" class="sr-only">Vault path</label>
      <Input
        id="bundle-path"
        bind:value={bundlePath}
        placeholder="/path/to/default.unovault"
        autocomplete="off"
      />

      <label for="master" class="sr-only">Master password</label>
      <Input
        id="master"
        bind:value={password}
        type="password"
        placeholder="Master password"
        autocomplete="current-password"
        autofocus
      />

      <div class="actions">
        <Button
          type="submit"
          variant="primary"
          size="md"
          fullWidth
          disabled={app.busy}
        >
          {#if app.busy}Unlocking…{:else}Unlock{/if}
        </Button>
        <Button
          type="button"
          variant="secondary"
          size="md"
          fullWidth
          disabled={app.busy}
          onclick={create}
        >
          Create new
        </Button>
      </div>
    </form>

    {#if app.error}
      <div class="error-wrap">
        <ErrorBanner error={app.error} onDismiss={() => app.clearError()} />
      </div>
    {/if}
  </Card>
</section>

<style>
  .locked-canvas {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--s-8);
    /* Subtle warm vignette — keeps the card from floating on flat paper. */
    background-image: radial-gradient(
      ellipse at center top,
      rgba(255, 255, 255, 0.5) 0%,
      rgba(255, 255, 255, 0) 60%
    );
    view-transition-name: locked-canvas;
  }

  .brand-header {
    text-align: center;
    margin-bottom: var(--s-6);
    display: flex;
    flex-direction: column;
    gap: var(--s-2);
  }

  .filename {
    color: var(--text-faint);
    font-size: var(--fs-xs);
    margin: 0;
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

  .error-wrap {
    margin-top: var(--s-4);
  }

  :global(.t-brand) {
    text-align: center;
  }
</style>
