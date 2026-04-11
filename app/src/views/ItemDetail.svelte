<script lang="ts">
  // Item Detail — rebuilt on top of Sheet + FieldLabel + Button.
  //
  // The detail sheet slides up over the vault list via the CSS View
  // Transitions API; the Sheet primitive declares the transition
  // name, and the store's setView wraps view changes in
  // document.startViewTransition(), so no extra wiring is needed
  // here beyond picking the right Sheet props.

  import { app } from '../lib/store.svelte';
  import {
    copyPasswordToClipboard,
    setPassword,
    toCommandError,
    type ItemMetadata,
  } from '../lib/ipc';
  import Sheet from '../lib/components/Sheet.svelte';
  import Button from '../lib/components/Button.svelte';
  import Input from '../lib/components/Input.svelte';
  import FieldLabel from '../lib/components/FieldLabel.svelte';
  import KindChip from '../lib/components/KindChip.svelte';
  import ErrorBanner from '../lib/components/ErrorBanner.svelte';

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
      copiedNotice = 'Copied. Clipboard clears in 30 seconds.';
      setTimeout(() => (copiedNotice = null), 3000);
    } catch (raw) {
      app.setError(toCommandError(raw));
    }
  }

  async function onSetPassword() {
    if (!newPassword) return;
    try {
      const updated = await setPassword(itemId, newPassword);
      newPassword = '';
      app.setItems(app.items.map((m) => (m.id === updated.id ? updated : m)));
    } catch (raw) {
      app.setError(toCommandError(raw));
    }
  }

  function close() {
    app.setView({ name: 'vault-list' });
  }

  function formatTimestamp(ms: number): string {
    return new Date(ms).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    });
  }
</script>

{#if item}
  <Sheet title={item.title} onClose={close}>
    <header class="sheet-header">
      <div class="header-main">
        <h2 class="t-headline">{item.title}</h2>
        {#if item.url}
          <a
            class="url-link t-meta-muted"
            href={item.url.startsWith('http') ? item.url : `https://${item.url}`}
            target="_blank"
            rel="noreferrer"
          >
            {item.url} ↗
          </a>
        {/if}
      </div>
      <KindChip kind={item.kind} />
    </header>

    {#if app.error}
      <div class="error-wrap">
        <ErrorBanner error={app.error} onDismiss={() => app.clearError()} />
      </div>
    {/if}

    <section class="field">
      <FieldLabel>Username</FieldLabel>
      <div class="field-value t-body">{item.username ?? '—'}</div>
    </section>

    <section class="field">
      <FieldLabel>Password</FieldLabel>
      {#if item.has_password}
        <div class="field-row">
          <span class="field-value t-mono">••••••••••••••••</span>
          <Button variant="secondary" size="sm" onclick={onCopy}>Copy</Button>
        </div>
        {#if copiedNotice}
          <p class="copied t-meta">{copiedNotice}</p>
        {/if}
      {:else}
        <form
          class="set-password"
          onsubmit={(e) => {
            e.preventDefault();
            onSetPassword();
          }}
        >
          <Input
            bind:value={newPassword}
            type="password"
            placeholder="Set a password"
          />
          <Button type="submit" variant="primary" size="md">Set</Button>
        </form>
      {/if}
    </section>

    <section class="field metadata">
      <FieldLabel>Metadata</FieldLabel>
      <div class="metadata-grid">
        <span class="t-meta">Created</span>
        <span class="t-meta-muted">{formatTimestamp(item.created_at_ms)}</span>
        <span class="t-meta">Modified</span>
        <span class="t-meta-muted">{formatTimestamp(item.modified_at_ms)}</span>
      </div>
    </section>

    {#snippet footer()}
      <Button variant="ghost" size="sm" onclick={close}>Back</Button>
    {/snippet}
  </Sheet>
{:else}
  <Sheet title="Item not found" onClose={close}>
    <p class="t-body-muted">This item does not exist. It may have been deleted.</p>
    {#snippet footer()}
      <Button variant="secondary" size="sm" onclick={close}>Back to list</Button>
    {/snippet}
  </Sheet>
{/if}

<style>
  .sheet-header {
    display: flex;
    align-items: flex-start;
    gap: var(--s-4);
    margin-bottom: var(--s-6);
  }

  .header-main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: var(--s-1);
  }

  .url-link {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    width: fit-content;
  }
  .url-link:hover {
    color: var(--accent);
  }

  .field {
    padding: var(--s-4) 0;
    border-bottom: 1px solid var(--border-subtle);
  }
  .field:last-of-type {
    border-bottom: none;
  }

  .field-row {
    display: flex;
    align-items: center;
    gap: var(--s-3);
  }
  .field-row > .field-value {
    flex: 1;
  }

  .field-value {
    font-weight: var(--fw-medium);
    color: var(--text);
  }

  .set-password {
    display: flex;
    gap: var(--s-2);
  }
  .set-password > :global(input) {
    flex: 1;
  }

  .copied {
    margin: var(--s-2) 0 0 0;
    color: var(--green-success);
  }

  .metadata-grid {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--s-2) var(--s-4);
  }

  .error-wrap {
    margin-bottom: var(--s-4);
  }
</style>
