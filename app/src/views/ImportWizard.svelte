<script lang="ts">
  // Import Wizard — the adoption gate for users switching from
  // 1Password, Bitwarden, or KeePass. Three steps inside a single
  // view component:
  //
  //   1. Pick a file (path input + optional source override).
  //   2. Review the preview (counts + per-item titles + skip reasons).
  //   3. Commit or cancel.
  //
  // The plaintext never crosses the IPC boundary at any point. The
  // Rust side stashes the parsed items in `AppState::pending_import`;
  // the wizard only ever sees titles, kinds, and skip reasons.

  import { app } from '../lib/store.svelte';
  import {
    cancelImport,
    commitImport,
    listItems,
    previewImport,
    previewImportWithSource,
    toCommandError,
    type ImportPreview,
    type ImportSourceTag,
  } from '../lib/ipc';
  import Button from '../lib/components/Button.svelte';
  import Input from '../lib/components/Input.svelte';
  import FieldLabel from '../lib/components/FieldLabel.svelte';
  import KindChip from '../lib/components/KindChip.svelte';
  import ErrorBanner from '../lib/components/ErrorBanner.svelte';

  type Step = 'pick' | 'review' | 'committing' | 'done';

  let step = $state<Step>('pick');
  let filePath = $state('');
  // 'auto' uses the file extension; the named tags force a format.
  let sourceTag = $state<ImportSourceTag | 'auto'>('auto');
  let preview = $state<ImportPreview | null>(null);
  let committedCount = $state(0);
  let failedCount = $state(0);

  async function onPreview() {
    const trimmed = filePath.trim();
    if (!trimmed) return;
    app.setBusy(true);
    try {
      const result =
        sourceTag === 'auto'
          ? await previewImport(trimmed)
          : await previewImportWithSource(trimmed, sourceTag);
      preview = result;
      step = 'review';
    } catch (raw) {
      app.setError(toCommandError(raw));
    } finally {
      app.setBusy(false);
    }
  }

  async function onCommit() {
    step = 'committing';
    app.setBusy(true);
    try {
      const result = await commitImport();
      committedCount = result.committed_count;
      failedCount = result.failed_count;
      // Refresh the main list so the vault view shows the new rows.
      const items = await listItems();
      app.setItems(items);
      step = 'done';
    } catch (raw) {
      app.setError(toCommandError(raw));
      step = 'review';
    } finally {
      app.setBusy(false);
    }
  }

  async function onCancel() {
    // Always call cancel_import if we hold a stashed preview. Even
    // if it fails we still route back so the user isn't stuck.
    if (preview) {
      try {
        await cancelImport();
      } catch (raw) {
        app.setError(toCommandError(raw));
      }
    }
    preview = null;
    step = 'pick';
    app.setView({ name: 'vault-list' });
  }

  function onDone() {
    preview = null;
    step = 'pick';
    app.setView({ name: 'vault-list' });
  }

  function onBackToPick() {
    preview = null;
    step = 'pick';
  }
</script>

<section class="import-view">
  <header class="topbar">
    <Button variant="ghost" size="sm" onclick={onCancel}>← Cancel</Button>
    <h2 class="t-headline">Import from another vault</h2>
  </header>

  <div class="body">
    {#if app.error}
      <ErrorBanner error={app.error} onDismiss={() => app.clearError()} />
    {/if}

    {#if step === 'pick'}
      <form
        class="form"
        onsubmit={(e) => {
          e.preventDefault();
          onPreview();
        }}
      >
        <p class="t-body-muted intro">
          Drop in an export from 1Password (<code>.1pux</code>),
          Bitwarden (<code>.json</code>), or KeePass
          (<code>.xml</code>). Nothing is written to your vault until
          you confirm the preview on the next step.
        </p>

        <div class="field">
          <FieldLabel for="im-path">Export file path</FieldLabel>
          <Input
            id="im-path"
            bind:value={filePath}
            placeholder="/Users/you/Downloads/1password-export.1pux"
            autofocus
          />
        </div>

        <div class="field">
          <FieldLabel for="im-source">Source format</FieldLabel>
          <select id="im-source" class="select" bind:value={sourceTag}>
            <option value="auto">Auto-detect (by extension)</option>
            <option value="OnePassword1pux">1Password (.1pux)</option>
            <option value="BitwardenJson">Bitwarden (.json)</option>
            <option value="KeepassXml">KeePass XML (.xml)</option>
          </select>
        </div>

        <div class="actions">
          <Button
            type="submit"
            variant="primary"
            size="md"
            disabled={!filePath.trim() || app.busy}
          >
            {app.busy ? 'Reading…' : 'Preview import'}
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="md"
            onclick={onCancel}
          >
            Cancel
          </Button>
        </div>
      </form>
    {:else if step === 'review' && preview}
      <div class="review">
        <p class="summary-line t-body">{preview.summary_line}</p>

        {#if preview.preview_items.length > 0}
          <h3 class="section-title">Will import</h3>
          <ul class="row-list">
            {#each preview.preview_items as item (item.title)}
              <li class="row">
                <span class="row-title">{item.title}</span>
                <span class="row-badges">
                  {#if item.has_password}
                    <span class="badge">password</span>
                  {/if}
                  {#if item.has_totp}
                    <span class="badge">totp</span>
                  {/if}
                  {#if item.has_notes}
                    <span class="badge">notes</span>
                  {/if}
                  <KindChip kind={item.kind} />
                </span>
              </li>
            {/each}
          </ul>
        {/if}

        {#if preview.skipped_items.length > 0}
          <h3 class="section-title">Will skip</h3>
          <ul class="row-list">
            {#each preview.skipped_items as skip (skip.title + skip.reason)}
              <li class="row skipped">
                <span class="row-title">{skip.title || '(untitled)'}</span>
                <span class="row-reason t-meta">{skip.reason}</span>
              </li>
            {/each}
          </ul>
        {/if}

        <div class="actions">
          <Button
            type="button"
            variant="primary"
            size="md"
            onclick={onCommit}
            disabled={app.busy || preview.imported_count === 0}
          >
            {preview.imported_count === 1
              ? 'Import 1 item'
              : `Import ${preview.imported_count} items`}
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="md"
            onclick={onBackToPick}
          >
            Pick a different file
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="md"
            onclick={onCancel}
          >
            Cancel
          </Button>
        </div>
      </div>
    {:else if step === 'committing'}
      <div class="committing">
        <p class="t-body-muted">Writing to your vault…</p>
      </div>
    {:else if step === 'done'}
      <div class="done">
        <h3 class="t-headline">
          {committedCount === 1
            ? '1 item imported.'
            : `${committedCount} items imported.`}
        </h3>
        {#if failedCount > 0}
          <p class="t-body-muted">
            {failedCount} item{failedCount === 1 ? '' : 's'} failed to write.
          </p>
        {/if}
        <div class="actions">
          <Button type="button" variant="primary" size="md" onclick={onDone}>
            Back to vault
          </Button>
        </div>
      </div>
    {/if}
  </div>
</section>

<style>
  .import-view {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    view-transition-name: import-view;
  }

  .topbar {
    display: flex;
    align-items: center;
    gap: var(--s-3);
    padding: var(--s-4) var(--s-6);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .topbar h2 {
    margin: 0;
  }

  .body {
    flex: 1;
    padding: var(--s-6) var(--s-8);
    max-width: 640px;
    margin: 0 auto;
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
    overflow-y: auto;
  }

  .intro code {
    font-family: var(--font-mono);
    font-size: 0.9em;
    background: var(--surface-2);
    padding: 0 var(--s-1);
    border-radius: var(--r-xs);
  }

  .form,
  .review,
  .done,
  .committing {
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
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
    flex-wrap: wrap;
    margin-top: var(--s-2);
  }

  .summary-line {
    margin: 0;
    font-weight: var(--fw-medium);
  }

  .section-title {
    margin: var(--s-3) 0 var(--s-2);
    font-family: var(--font-ui);
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted);
  }

  .row-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--s-1);
  }

  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--s-3);
    padding: var(--s-2) var(--s-3);
    background: var(--surface-2);
    border-radius: var(--r-sm);
  }

  .row.skipped {
    background: transparent;
    border: 1px dashed var(--border-subtle);
  }

  .row-title {
    font-family: var(--font-ui);
    font-size: var(--fs-md);
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .row-reason {
    font-style: italic;
  }

  .row-badges {
    display: flex;
    align-items: center;
    gap: var(--s-2);
    flex-shrink: 0;
  }

  .badge {
    font-family: var(--font-ui);
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted);
    padding: 0 var(--s-2);
    border: 1px solid var(--border-subtle);
    border-radius: 999px;
  }
</style>
