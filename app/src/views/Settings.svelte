<script lang="ts">
  // Settings — lands in week 21 to surface the recovery + password
  // rotation flows. Everything that isn't an item lives here: the
  // master password rotation, the recovery phrase slot, and (later)
  // the diagnostics / about panel.
  //
  // Recovery phrase display is intentionally designed as a hard
  // gate: the user cannot leave the phrase screen without confirming
  // they wrote it down. There's no "show again later" button.

  import { onMount } from 'svelte';
  import { app } from '../lib/store.svelte';
  import {
    changePassword,
    enableRecoveryPhrase,
    hasRecovery,
    rotateRecoveryPhrase,
    toCommandError,
  } from '../lib/ipc';
  import Button from '../lib/components/Button.svelte';
  import Input from '../lib/components/Input.svelte';
  import FieldLabel from '../lib/components/FieldLabel.svelte';
  import ErrorBanner from '../lib/components/ErrorBanner.svelte';

  type Panel =
    | { kind: 'idle' }
    | { kind: 'change-password' }
    | { kind: 'reveal-phrase'; phrase: string };

  let panel = $state<Panel>({ kind: 'idle' });
  let recoveryEnabled = $state<boolean | null>(null);
  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let passwordChangeSuccess = $state(false);
  let acknowledged = $state(false);

  onMount(async () => {
    try {
      recoveryEnabled = await hasRecovery();
    } catch (raw) {
      app.setError(toCommandError(raw));
    }
  });

  function backToList() {
    app.setView({ name: 'vault-list' });
  }

  function openChangePassword() {
    currentPassword = '';
    newPassword = '';
    confirmPassword = '';
    passwordChangeSuccess = false;
    panel = { kind: 'change-password' };
  }

  function cancelPanel() {
    currentPassword = '';
    newPassword = '';
    confirmPassword = '';
    panel = { kind: 'idle' };
  }

  async function submitChangePassword() {
    if (!currentPassword || !newPassword) return;
    if (newPassword !== confirmPassword) {
      app.setError({
        category: 'UserActionable',
        message: 'new password confirmation does not match',
      });
      return;
    }
    try {
      await changePassword(currentPassword, newPassword);
      // Wipe the locals — the frontend holds plaintext only as
      // long as necessary.
      currentPassword = '';
      newPassword = '';
      confirmPassword = '';
      passwordChangeSuccess = true;
      panel = { kind: 'idle' };
    } catch (raw) {
      app.setError(toCommandError(raw));
    }
  }

  async function triggerRecoveryFlow() {
    try {
      const phrase =
        recoveryEnabled === true
          ? await rotateRecoveryPhrase()
          : await enableRecoveryPhrase();
      recoveryEnabled = true;
      acknowledged = false;
      panel = { kind: 'reveal-phrase', phrase };
    } catch (raw) {
      app.setError(toCommandError(raw));
    }
  }

  function dismissPhrase() {
    // Reset local state including the acknowledgment flag so a
    // subsequent rotation starts from a clean slate. Svelte's
    // runes don't automatically wipe closures over the phrase
    // string, but narrowing `panel` back to idle drops the only
    // reference we hold.
    panel = { kind: 'idle' };
    acknowledged = false;
  }

  // Split the phrase into numbered rows of 4 words for display.
  // Matches the standard 24-word layout shown by 1Password and
  // Bitwarden so users recognise the format.
  function phraseRows(phrase: string): { index: number; word: string }[][] {
    const words = phrase.trim().split(/\s+/);
    const rows: { index: number; word: string }[][] = [];
    for (let i = 0; i < words.length; i += 4) {
      rows.push(
        words.slice(i, i + 4).map((word, j) => ({
          index: i + j + 1,
          word,
        })),
      );
    }
    return rows;
  }
</script>

<section class="settings-view">
  <header class="topbar">
    <Button variant="ghost" size="sm" onclick={backToList}>← Back</Button>
    <h2 class="t-headline">Settings</h2>
  </header>

  <div class="body">
    {#if app.error}
      <ErrorBanner error={app.error} onDismiss={() => app.clearError()} />
    {/if}

    {#if panel.kind === 'reveal-phrase'}
      <div class="phrase-screen">
        <h3 class="t-headline">Your recovery phrase</h3>
        <p class="t-body-muted">
          Write these 24 words down on paper and store them somewhere
          safe. This is the <strong>only</strong> way to unlock your
          vault if you forget your master password. You will not see
          these words again.
        </p>

        <div class="phrase-grid">
          {#each phraseRows(panel.phrase) as row, rowIdx (rowIdx)}
            <div class="phrase-row">
              {#each row as { index, word } (index)}
                <div class="phrase-word">
                  <span class="phrase-index">{index}.</span>
                  <span class="phrase-text">{word}</span>
                </div>
              {/each}
            </div>
          {/each}
        </div>

        <label class="acknowledge">
          <input type="checkbox" bind:checked={acknowledged} />
          I have written down all 24 words in order.
        </label>

        <div class="actions">
          <Button
            variant="primary"
            size="md"
            onclick={dismissPhrase}
            disabled={!acknowledged}
          >
            Continue
          </Button>
        </div>
      </div>
    {:else if panel.kind === 'change-password'}
      <form
        class="form"
        onsubmit={(e) => {
          e.preventDefault();
          submitChangePassword();
        }}
      >
        <h3 class="t-headline">Change master password</h3>
        <p class="t-body-muted">
          Re-wraps your vault under a new password. Your existing
          items and recovery phrase stay intact. No re-encryption of
          the item chunks.
        </p>

        <div class="field">
          <FieldLabel for="cp-current">Current password</FieldLabel>
          <Input
            id="cp-current"
            type="password"
            bind:value={currentPassword}
            placeholder="••••••••••••"
            autofocus
          />
        </div>
        <div class="field">
          <FieldLabel for="cp-new">New password</FieldLabel>
          <Input
            id="cp-new"
            type="password"
            bind:value={newPassword}
            placeholder="at least 12 characters"
          />
        </div>
        <div class="field">
          <FieldLabel for="cp-confirm">Confirm new password</FieldLabel>
          <Input
            id="cp-confirm"
            type="password"
            bind:value={confirmPassword}
            placeholder="re-type the new password"
          />
        </div>

        <div class="actions">
          <Button
            type="submit"
            variant="primary"
            size="md"
            disabled={!currentPassword || !newPassword || newPassword !== confirmPassword}
          >
            Change password
          </Button>
          <Button type="button" variant="secondary" size="md" onclick={cancelPanel}>
            Cancel
          </Button>
        </div>
      </form>
    {:else}
      <div class="panels">
        {#if passwordChangeSuccess}
          <div class="success-banner t-body">
            Master password changed.
          </div>
        {/if}

        <section class="panel">
          <h3 class="panel-title">Master password</h3>
          <p class="panel-body t-body-muted">
            Rotate the master password. Your existing items and
            recovery phrase stay intact.
          </p>
          <Button variant="secondary" size="md" onclick={openChangePassword}>
            Change master password
          </Button>
        </section>

        <section class="panel">
          <h3 class="panel-title">Recovery phrase</h3>
          {#if recoveryEnabled === null}
            <p class="panel-body t-body-muted">Loading…</p>
          {:else if recoveryEnabled}
            <p class="panel-body t-body-muted">
              A BIP39 recovery phrase is saved for this vault. Rotating
              invalidates the old phrase and generates a new one.
            </p>
            <Button variant="secondary" size="md" onclick={triggerRecoveryFlow}>
              Rotate recovery phrase
            </Button>
          {:else}
            <p class="panel-body t-body-muted">
              Generate a 24-word BIP39 phrase that can unlock your vault
              if you forget your password. The phrase is shown once —
              write it down before dismissing the screen.
            </p>
            <Button variant="primary" size="md" onclick={triggerRecoveryFlow}>
              Enable recovery phrase
            </Button>
          {/if}
        </section>
      </div>
    {/if}
  </div>
</section>

<style>
  .settings-view {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    view-transition-name: settings-view;
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
    gap: var(--s-6);
    overflow-y: auto;
  }

  .panels {
    display: flex;
    flex-direction: column;
    gap: var(--s-6);
  }

  .panel {
    display: flex;
    flex-direction: column;
    gap: var(--s-3);
    padding: var(--s-5);
    background: var(--surface-2);
    border: 1px solid var(--border-subtle);
    border-radius: var(--r-md);
  }

  .panel-title {
    margin: 0;
    font-family: var(--font-ui);
    font-size: var(--fs-md);
    font-weight: var(--fw-medium);
  }

  .panel-body {
    margin: 0;
  }

  .form {
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--s-2);
  }

  .actions {
    display: flex;
    gap: var(--s-3);
    flex-wrap: wrap;
    margin-top: var(--s-2);
  }

  .success-banner {
    padding: var(--s-3) var(--s-4);
    background: rgba(42, 138, 75, 0.1);
    border: 1px solid rgba(42, 138, 75, 0.3);
    border-radius: var(--r-sm);
    color: var(--text);
  }

  .phrase-screen {
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
  }

  .phrase-grid {
    display: flex;
    flex-direction: column;
    gap: var(--s-2);
    padding: var(--s-5);
    background: var(--surface-2);
    border: 1px solid var(--border-subtle);
    border-radius: var(--r-md);
  }

  .phrase-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: var(--s-3);
  }

  .phrase-word {
    display: flex;
    align-items: baseline;
    gap: var(--s-2);
    font-family: var(--font-mono);
    font-size: var(--fs-md);
  }

  .phrase-index {
    color: var(--text-muted);
    font-size: 0.85em;
    min-width: 1.5em;
    text-align: right;
  }

  .phrase-text {
    font-weight: var(--fw-medium);
    color: var(--text);
  }

  .acknowledge {
    display: flex;
    align-items: center;
    gap: var(--s-2);
    font-family: var(--font-ui);
    font-size: var(--fs-md);
    color: var(--text);
    cursor: pointer;
  }
</style>
