<script lang="ts">
  // Add Item — rebuilt on primitives.
  //
  // Shows a compact form for the non-secret metadata: title, kind,
  // username, url. The password is set on the following detail
  // screen because the backend CreateItem carries metadata only.

  import { app } from '../lib/store.svelte';
  import {
    addItem,
    listItems,
    toCommandError,
    type ItemKindTag,
  } from '../lib/ipc';
  import Button from '../lib/components/Button.svelte';
  import Input from '../lib/components/Input.svelte';
  import FieldLabel from '../lib/components/FieldLabel.svelte';
  import ErrorBanner from '../lib/components/ErrorBanner.svelte';

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
      // consistent across the UI.
      const items = await listItems();
      app.setItems(items);
      app.setView({ name: 'item-detail', itemId: created.id });
    } catch (raw) {
      app.setError(toCommandError(raw));
    }
  }

  function cancel() {
    app.setView({ name: 'vault-list' });
  }
</script>

<section class="add-view">
  <header class="topbar">
    <Button variant="ghost" size="sm" onclick={cancel}>← Cancel</Button>
  </header>

  <form
    class="form"
    onsubmit={(e) => {
      e.preventDefault();
      submit();
    }}
  >
    <h2 class="t-headline">New item</h2>

    {#if app.error}
      <ErrorBanner error={app.error} onDismiss={() => app.clearError()} />
    {/if}

    <div class="field">
      <FieldLabel for="ni-title">Title</FieldLabel>
      <Input id="ni-title" bind:value={title} placeholder="GitHub" autofocus />
    </div>

    <div class="field">
      <FieldLabel for="ni-kind">Kind</FieldLabel>
      <select id="ni-kind" class="select" bind:value={kind}>
        <option value="Password">Password</option>
        <option value="Passkey">Passkey</option>
        <option value="Totp">TOTP</option>
        <option value="SshKey">SSH Key</option>
        <option value="ApiToken">API Token</option>
        <option value="SecureNote">Secure Note</option>
      </select>
    </div>

    <div class="field">
      <FieldLabel for="ni-user">Username</FieldLabel>
      <Input id="ni-user" bind:value={username} placeholder="james@personal" />
    </div>

    <div class="field">
      <FieldLabel for="ni-url">URL</FieldLabel>
      <Input id="ni-url" bind:value={url} placeholder="github.com" />
    </div>

    <div class="actions">
      <Button type="submit" variant="primary" size="md">Create</Button>
      <Button type="button" variant="secondary" size="md" onclick={cancel}>
        Cancel
      </Button>
    </div>
  </form>
</section>

<style>
  .add-view {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    view-transition-name: add-view;
  }

  .topbar {
    padding: var(--s-4) var(--s-6);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .form {
    flex: 1;
    padding: var(--s-6) var(--s-8);
    max-width: 520px;
    margin: 0 auto;
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
    overflow-y: auto;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--s-2);
  }

  .select {
    height: 40px;
    padding: 0 var(--s-4);
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    font-family: var(--font-ui);
    font-size: var(--fs-md);
    color: var(--text);
    cursor: pointer;
  }

  .actions {
    display: flex;
    gap: var(--s-3);
    margin-top: var(--s-2);
  }
</style>
