<script lang="ts">
  // Vault list — rebuilt on primitives (CommandBar, ListRow,
  // EmptyState, KindChip, Button, ErrorBanner).
  //
  // Layout: command bar at the top, header strip with item count +
  // actions, then scrollable list or empty state. No inline styles
  // for any of the row chrome; it all lives in ListRow.svelte.

  import { app } from '../lib/store.svelte';
  import { lockVault, toCommandError } from '../lib/ipc';
  import CommandBar from '../lib/components/CommandBar.svelte';
  import ListRow from '../lib/components/ListRow.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import KindChip from '../lib/components/KindChip.svelte';
  import Button from '../lib/components/Button.svelte';
  import ErrorBanner from '../lib/components/ErrorBanner.svelte';

  let query = $state('');

  const filtered = $derived(
    query.trim().length === 0
      ? app.items
      : app.items.filter((item) => {
          const q = query.toLowerCase();
          return (
            item.title.toLowerCase().includes(q) ||
            (item.username ?? '').toLowerCase().includes(q) ||
            (item.url ?? '').toLowerCase().includes(q)
          );
        }),
  );

  async function onLock() {
    try {
      await lockVault();
      app.onLock();
    } catch (raw) {
      app.setError(toCommandError(raw));
    }
  }

  function openItem(id: string) {
    app.setView({ name: 'item-detail', itemId: id });
  }

  function addNew() {
    app.setView({ name: 'add-item' });
  }

  function openImport() {
    app.setView({ name: 'import' });
  }

  function openSettings() {
    app.setView({ name: 'settings' });
  }

  function metaFor(username: string | null, url: string | null): string {
    const parts = [username, url].filter((x): x is string => !!x);
    return parts.join(' · ');
  }
</script>

<section class="vault-list-view">
  <div class="command-bar-wrap">
    <CommandBar bind:value={query} />
  </div>

  <header class="list-header">
    <span class="count t-meta">{filtered.length} items</span>
    <div class="header-actions">
      <Button variant="secondary" size="sm" onclick={addNew}>Add item</Button>
      <Button variant="ghost" size="sm" onclick={openImport}>Import</Button>
      <Button variant="ghost" size="sm" onclick={openSettings}>Settings</Button>
      <Button variant="ghost" size="sm" onclick={onLock}>Lock</Button>
    </div>
  </header>

  {#if app.error}
    <div class="error-wrap">
      <ErrorBanner error={app.error} onDismiss={() => app.clearError()} />
    </div>
  {/if}

  {#if filtered.length === 0 && app.items.length === 0}
    <EmptyState
      headline="Your vault is empty."
      hint="Add your first credential, or import one from 1Password, Bitwarden, or KeePass."
    >
      {#snippet action()}
        <div class="empty-actions">
          <Button variant="primary" size="md" onclick={addNew}>
            Add your first item
          </Button>
          <Button variant="secondary" size="md" onclick={openImport}>
            Import from another vault
          </Button>
        </div>
      {/snippet}
    </EmptyState>
  {:else if filtered.length === 0}
    <EmptyState headline={`No matches for "${query}"`} />
  {:else}
    <ul class="items">
      {#each filtered as item (item.id)}
        <li>
          <ListRow
            initial={item.title.charAt(0)}
            title={item.title}
            meta={metaFor(item.username, item.url)}
            onclick={() => openItem(item.id)}
          >
            {#snippet trailing()}
              <KindChip kind={item.kind} />
            {/snippet}
          </ListRow>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .vault-list-view {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    view-transition-name: vault-list;
  }

  .command-bar-wrap {
    padding: var(--s-4) var(--s-6) var(--s-3) var(--s-6);
    flex-shrink: 0;
  }

  .list-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--s-2) var(--s-6);
    flex-shrink: 0;
  }

  .count {
    text-transform: uppercase;
    letter-spacing: 0.04em;
    font-weight: var(--fw-medium);
  }

  .header-actions {
    display: flex;
    gap: var(--s-2);
  }

  .error-wrap {
    padding: 0 var(--s-6);
  }

  .items {
    flex: 1;
    list-style: none;
    margin: 0;
    padding: 0 var(--s-3);
    overflow-y: auto;
  }

  .items li {
    margin: 0;
  }

  .empty-actions {
    display: flex;
    gap: var(--s-3);
    flex-wrap: wrap;
    justify-content: center;
  }
</style>
