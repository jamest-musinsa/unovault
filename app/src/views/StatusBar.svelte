<script lang="ts">
  // Bottom status bar. Always visible regardless of which view is
  // active. Displays unlocked/locked state, item count, and bundle
  // path — the design spike calls this the "sync bar" and it's the
  // single reference point for "am I looking at a live vault."

  import { app } from '../lib/store.svelte';

  function filename(p: string): string {
    const parts = p.split('/');
    return parts[parts.length - 1] || p;
  }

  const locked = $derived(app.view.name === 'locked');
  const itemCount = $derived(app.items.length);
</script>

<div class="status-bar" aria-live="polite">
  {#if locked}
    <span class="dot" aria-hidden="true"></span>
    <span>Vault locked</span>
  {:else}
    <span class="dot ok" aria-hidden="true"></span>
    <span>Unlocked</span>
    <span class="divider" aria-hidden="true"></span>
    <span>{itemCount} items</span>
  {/if}

  <span class="spacer"></span>

  {#if !locked && app.bundlePath}
    <span class="path" title={app.bundlePath}>{filename(app.bundlePath)}</span>
  {/if}
</div>

<style>
  .divider {
    width: 1px;
    height: 12px;
    background: var(--border);
    margin: 0 var(--s-2);
  }
  .path {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--text-faint);
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
