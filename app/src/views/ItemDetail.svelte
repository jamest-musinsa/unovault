<script lang="ts">
  // Item Detail sheet — matches design/spike/item-detail.html.
  //
  // Metadata-only by construction: the frontend never sees the
  // password bytes. The "Copy password" button calls the backend
  // copy_password_to_clipboard command, which does the work on
  // the Rust side without ever sending the plaintext through IPC.

  import { app } from '../lib/store.svelte';
  import {
    copyPasswordToClipboard,
    setPassword,
    toCommandError,
    type ItemMetadata,
  } from '../lib/ipc';

  interface Props {
    itemId: string;
  }
  let { itemId }: Props = $props();

  const item = $derived<ItemMetadata | undefined>(
    app.items.find((m) => m.id === itemId),
  );

  let newPassword = $state('');
  let copiedNotice = $state<string | null>(null);

  async function onCopy() {
    try {
      await copyPasswordToClipboard(itemId);
      copiedNotice = 'Copied. Clipboard will clear in 30s.';
      setTimeout(() => (copiedNotice = null), 3000);
    } catch (raw) {
      const err = toCommandError(raw);
      app.setError(`${err.category}: ${err.message}`);
    }
  }

  async function onSetPassword() {
    if (!newPassword) return;
    try {
      const updated = await setPassword(itemId, newPassword);
      newPassword = '';
      // Replace the item in the store with the updated metadata.
      app.setItems(app.items.map((m) => (m.id === updated.id ? updated : m)));
    } catch (raw) {
      const err = toCommandError(raw);
      app.setError(`${err.category}: ${err.message}`);
    }
  }

  function back() {
    app.setView({ name: 'vault-list' });
  }
</script>

<section class="detail-canvas">
  <header class="header">
    <button class="back-btn" onclick={back}>← Back</button>
  </header>

  {#if !item}
    <p class="missing">Item not found.</p>
  {:else}
    <div class="sheet">
      <h2 class="sheet-title">{item.title}</h2>
      {#if item.url}
        <a class="sheet-url" href={item.url.startsWith('http') ? item.url : `https://${item.url}`} target="_blank" rel="noreferrer">
          {item.url} ↗
        </a>
      {/if}

      <div class="field">
        <div class="field-label">USERNAME</div>
        <div class="field-value">{item.username ?? '—'}</div>
      </div>

      <div class="field">
        <div class="field-label">PASSWORD</div>
        {#if item.has_password}
          <div class="field-row">
            <span class="field-value mono">••••••••••••••••</span>
            <button class="btn-secondary btn-small" onclick={onCopy}>Copy</button>
          </div>
          {#if copiedNotice}
            <div class="copied-notice">{copiedNotice}</div>
          {/if}
        {:else}
          <form class="set-password" onsubmit={(e) => { e.preventDefault(); onSetPassword(); }}>
            <input
              type="password"
              class="input"
              placeholder="Set a password"
              bind:value={newPassword}
            />
            <button class="btn-primary" type="submit">Set</button>
          </form>
        {/if}
      </div>

      <div class="field">
        <div class="field-label">KIND</div>
        <div class="field-value">{item.kind}</div>
      </div>

      <div class="field metadata">
        <div class="field-label">METADATA</div>
        <div class="field-value metadata-grid">
          <span>Created</span><span>{new Date(item.created_at_ms).toLocaleString()}</span>
          <span>Modified</span><span>{new Date(item.modified_at_ms).toLocaleString()}</span>
        </div>
      </div>
    </div>
  {/if}
</section>

<style>
  .detail-canvas {
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

  .sheet {
    flex: 1;
    padding: var(--s-6) var(--s-8);
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: var(--s-5);
  }

  .sheet-title {
    font-size: var(--fs-xl);
    font-weight: 600;
    margin: 0;
    letter-spacing: -0.015em;
  }
  .sheet-url {
    font-size: var(--fs-sm);
    color: var(--text-muted);
  }
  .sheet-url:hover { color: var(--accent); }

  .field {
    padding: var(--s-3) 0;
    border-bottom: 1px solid var(--border-subtle);
  }
  .field-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 600;
    color: var(--text-faint);
    margin-bottom: var(--s-2);
  }
  .field-value {
    font-size: var(--fs-md);
    font-weight: 500;
  }
  .field-value.mono {
    font-family: var(--font-mono);
    letter-spacing: 0.04em;
  }
  .field-row {
    display: flex;
    align-items: center;
    gap: var(--s-3);
  }
  .field-row > .field-value { flex: 1; }

  .btn-small {
    height: 28px;
    padding: 0 var(--s-3);
    font-size: var(--fs-xs);
  }

  .copied-notice {
    margin-top: var(--s-2);
    font-size: var(--fs-xs);
    color: var(--green-success);
  }

  .set-password {
    display: flex;
    gap: var(--s-2);
  }
  .set-password > .input { flex: 1; }

  .metadata-grid {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--s-2) var(--s-4);
    font-size: var(--fs-xs);
    color: var(--text-muted);
    font-weight: 400;
    font-variant-numeric: tabular-nums;
  }

  .missing {
    padding: var(--s-8);
    text-align: center;
    color: var(--text-muted);
  }
</style>
