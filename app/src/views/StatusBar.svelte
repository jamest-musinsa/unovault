<script lang="ts">
  // Bottom status bar — always-visible "am I looking at a live vault"
  // anchor. Rebuilt on tokens without duplicating .status-bar CSS.
  //
  // Shows:
  //   locked   : grey dot + "Vault locked"
  //   unlocked : green dot with halo + item count + bundle filename
  //
  // The bar also surfaces sync state when the iCloud backend is wired
  // up (week 10+ stretch); currently it just shows "Local" because
  // the vault engine has no sync backend yet.

  import { app } from '../lib/store.svelte';

  function filename(p: string): string {
    if (!p) return '';
    const parts = p.split('/');
    return parts[parts.length - 1] || p;
  }

  const locked = $derived(app.view.name === 'locked');
  const itemCount = $derived(app.items.length);
  const shortPath = $derived(filename(app.bundlePath));
</script>

<div class="status-bar" aria-live="polite" aria-atomic="true">
  {#if locked}
    <span class="dot" aria-hidden="true"></span>
    <span class="t-meta">Vault locked</span>
  {:else}
    <span class="dot dot-ok" aria-hidden="true"></span>
    <span class="t-meta">Unlocked</span>
    <span class="divider" aria-hidden="true"></span>
    <span class="t-meta">{itemCount} {itemCount === 1 ? 'item' : 'items'}</span>
    <span class="divider" aria-hidden="true"></span>
    <span class="t-meta">Local</span>
  {/if}

  <span class="spacer"></span>

  {#if !locked && shortPath}
    <span class="path t-meta" title={app.bundlePath}>{shortPath}</span>
  {/if}
</div>

<style>
  .status-bar {
    height: 28px;
    display: flex;
    align-items: center;
    padding: 0 var(--s-5);
    font-family: var(--font-ui);
    color: var(--text-faint);
    border-top: 1px solid var(--border);
    background: var(--surface-2);
    user-select: none;
    gap: var(--s-2);
    flex-shrink: 0;
    z-index: var(--z-header);
  }

  .dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--text-faint);
    transition: background var(--dur-short) var(--ease-calm),
                box-shadow var(--dur-short) var(--ease-calm);
  }

  .dot-ok {
    background: var(--green-success);
    box-shadow: 0 0 0 3px var(--green-success-soft);
  }

  .divider {
    width: 1px;
    height: 12px;
    background: var(--border);
    margin: 0 var(--s-2);
  }

  .spacer {
    flex: 1;
  }

  .path {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
