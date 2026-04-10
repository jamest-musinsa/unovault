<script lang="ts">
  // Minimal Add Item form. Fields: title, kind, username, url.
  // Password is set on the next screen (item detail) via set_password.
  // That split matches the backend API where CreateItem carries
  // non-secret metadata only and secrets flow through UpdateField
  // events afterwards.

  import { app } from '../lib/store.svelte';
  import { addItem, listItems, toCommandError, type ItemKindTag } from '../lib/ipc';

  let title = $state('');
  let kind = $state<ItemKindTag>('Password');
  let username = $state('');
  let url = $state('');

  async function submit() {
    if (!title.trim()) return;
    try {
      const created = await addItem(
        title.trim(),
        kind,
        username.trim() || null,
        url.trim() || null,
      );
      // Refresh the full list from the backend so the sort order is
      // consistent with everything else the vault shows.
      const items = await listItems();
      app.setItems(items);
      app.setView({ name: 'item-detail', itemId: created.id });
    } catch (raw) {
      const err = toCommandError(raw);
      app.setError(`${err.category}: ${err.message}`);
    }
  }

  function cancel() {
    app.setView({ name: 'vault-list' });
  }
</script>

<section class="add-canvas">
  <header class="header">
    <button class="back-btn" onclick={cancel}>← Cancel</button>
  </header>

  <form class="form" onsubmit={(e) => { e.preventDefault(); submit(); }}>
    <h2 class="form-title">New item</h2>

    <label class="field">
      <span class="field-label">TITLE</span>
      <!-- svelte-ignore a11y_autofocus -->
      <input type="text" class="input" bind:value={title} placeholder="GitHub" autofocus />
    </label>

    <label class="field">
      <span class="field-label">KIND</span>
      <select class="select" bind:value={kind}>
        <option value="Password">Password</option>
        <option value="Passkey">Passkey</option>
        <option value="Totp">TOTP</option>
        <option value="SshKey">SSH Key</option>
        <option value="ApiToken">API Token</option>
        <option value="SecureNote">Secure Note</option>
      </select>
    </label>

    <label class="field">
      <span class="field-label">USERNAME</span>
      <input type="text" class="input" bind:value={username} placeholder="james@personal" />
    </label>

    <label class="field">
      <span class="field-label">URL</span>
      <input type="text" class="input" bind:value={url} placeholder="github.com" />
    </label>

    <div class="actions">
      <button type="submit" class="btn-primary">Create</button>
      <button type="button" class="btn-secondary" onclick={cancel}>Cancel</button>
    </div>

    {#if app.error}
      <div class="error-banner">{app.error}</div>
    {/if}
  </form>
</section>

<style>
  .add-canvas {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }

  .header {
    padding: var(--s-4) var(--s-6);
    border-bottom: 1px solid var(--border-subtle);
  }
  .back-btn {
    color: var(--text-muted);
    font-size: var(--fs-sm);
    padding: var(--s-1) var(--s-3);
    border-radius: var(--r-sm);
  }
  .back-btn:hover { background: var(--surface-2); }

  .form {
    flex: 1;
    padding: var(--s-6) var(--s-8);
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
    max-width: 520px;
    margin: 0 auto;
    width: 100%;
  }

  .form-title {
    font-size: var(--fs-xl);
    font-weight: 600;
    margin: 0 0 var(--s-2) 0;
    letter-spacing: -0.015em;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--s-2);
  }
  .field-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 600;
    color: var(--text-faint);
  }
  .select {
    height: 40px;
    padding: 0 var(--s-4);
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    font-size: var(--fs-md);
    color: var(--text);
  }

  .actions {
    display: flex;
    gap: var(--s-3);
    margin-top: var(--s-2);
  }
</style>
