<script lang="ts">
  // Vault list screen — matches design/spike/vault-list.html.
  //
  // Command bar + single panel layout. Search is client-side over
  // the in-memory items cache; the list of item IDs never crosses
  // the IPC boundary (we only fetched metadata).

  import { app } from '../lib/store.svelte';
  import { lockVault, toCommandError } from '../lib/ipc';

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
      const err = toCommandError(raw);
      app.setError(`${err.category}: ${err.message}`);
    }
  }

  function openItem(id: string) {
    app.setView({ name: 'item-detail', itemId: id });
  }

  function addNew() {
    app.setView({ name: 'add-item' });
  }
</script>

<section class="vault-list">
  <div class="command-bar">
    <!-- svelte-ignore a11y_autofocus -->
    <input
      type="text"
      class="cmd-input"
      placeholder="Search or type a command"
      bind:value={query}
      autofocus
    />
    <span class="kbd">⌘K</span>
  </div>

  <div class="list-header">
    <span class="count">{filtered.length} items</span>
    <div class="header-actions">
      <button class="btn-secondary btn-small" onclick={addNew}>Add item</button>
      <button class="btn-secondary btn-small" onclick={onLock}>Lock</button>
    </div>
  </div>

  {#if filtered.length === 0 && app.items.length === 0}
    <div class="empty-state">
      <p>Your vault is empty.</p>
      <button class="btn-primary" onclick={addNew}>Add your first item</button>
    </div>
  {:else if filtered.length === 0}
    <div class="empty-state">
      <p>No matches for &quot;{query}&quot;.</p>
    </div>
  {:else}
    <ul class="items">
      {#each filtered as item (item.id)}
        <li>
          <button class="item-row" onclick={() => openItem(item.id)}>
            <span class="item-icon">{item.title.charAt(0).toUpperCase()}</span>
            <span class="item-content">
              <span class="item-title">{item.title}</span>
              <span class="item-meta">
                {item.username ?? ''}{#if item.username && item.url} · {/if}{item.url ?? ''}
              </span>
            </span>
            <span class="item-kind" class:passkey={item.kind === 'Passkey'}>{item.kind}</span>
          </button>
        </li>
      {/each}
    </ul>
  {/if}

  {#if app.error}
    <div class="error-banner">{app.error}</div>
  {/if}
</section>

<style>
  .vault-list {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }

  .command-bar {
    display: flex;
    align-items: center;
    gap: var(--s-3);
    margin: var(--s-4) var(--s-6);
    height: 48px;
    padding: 0 var(--s-4);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    box-shadow: var(--shadow-1);
  }
  .cmd-input {
    flex: 1;
    font-size: var(--fs-lg);
  }
  .cmd-input::placeholder { color: var(--text-faint); }
  .kbd {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--text-faint);
    padding: 3px 8px;
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    background: var(--surface-2);
  }

  .list-header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    padding: var(--s-2) var(--s-6);
  }
  .count {
    font-size: var(--fs-xs);
    color: var(--text-faint);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    font-weight: 500;
  }
  .header-actions {
    display: flex;
    gap: var(--s-2);
  }
  .btn-small {
    height: 28px;
    padding: 0 var(--s-3);
    font-size: var(--fs-xs);
  }

  .items {
    flex: 1;
    list-style: none;
    margin: 0;
    padding: 0 var(--s-3);
    overflow-y: auto;
  }

  .item-row {
    width: 100%;
    display: flex;
    align-items: center;
    gap: var(--s-4);
    height: 56px;
    padding: 0 var(--s-4);
    border-bottom: 1px solid var(--border-subtle);
    text-align: left;
    background: transparent;
    transition: background var(--dur-micro) var(--ease-calm);
  }
  .item-row:hover { background: var(--surface-hover); }

  .item-icon {
    width: 32px; height: 32px;
    border-radius: var(--r-sm);
    background: var(--surface-2);
    border: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    color: var(--text-muted);
    font-size: var(--fs-sm);
  }

  .item-content {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .item-title {
    font-size: var(--fs-md);
    font-weight: 500;
    color: var(--text);
    line-height: 20px;
  }
  .item-meta {
    font-size: var(--fs-xs);
    color: var(--text-faint);
    line-height: 14px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .item-kind {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 600;
    color: var(--text-faint);
    padding: 2px 8px;
    border: 1px solid var(--border);
    border-radius: 999px;
  }
  .item-kind.passkey {
    color: var(--accent);
    border-color: rgba(184, 83, 44, 0.28);
    background: var(--accent-soft);
  }

  .empty-state {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--s-4);
    color: var(--text-muted);
  }

  .error-banner {
    margin: var(--s-3) var(--s-6);
  }
</style>
