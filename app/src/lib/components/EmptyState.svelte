<script lang="ts">
  // EmptyState — the design doc is explicit that empty states are
  // features, not fallbacks. This component gives every "nothing to
  // show here" moment consistent warmth, a primary action, and an
  // optional hint line.
  //
  // Reviewers: every EmptyState instance must have a headline + a
  // useful primary action (or a clearly labeled ghost action).
  // "No items." with nothing else is a regression.

  import type { Snippet } from 'svelte';

  interface Props {
    headline: string;
    hint?: string;
    action?: Snippet;
  }

  let { headline, hint, action }: Props = $props();
</script>

<div class="empty-state" role="status">
  <p class="headline t-body-muted">{headline}</p>
  {#if hint}
    <p class="hint t-meta">{hint}</p>
  {/if}
  {#if action}
    <div class="action">{@render action()}</div>
  {/if}
</div>

<style>
  .empty-state {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--s-4);
    padding: var(--s-10);
    color: var(--text-muted);
    text-align: center;
  }

  .headline {
    font-size: var(--fs-md);
    margin: 0;
  }

  .hint {
    margin: 0;
    max-width: 36ch;
  }

  .action {
    margin-top: var(--s-2);
  }
</style>
