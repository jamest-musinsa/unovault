<script lang="ts">
  // ListRow — the single row shape used by the vault list.
  //
  // Keeps the icon (single initial letter in a subtle square), the
  // two-line content (title + muted meta), the right-aligned kind
  // chip, and the hover/selected states all in one place.
  //
  // Clicking the row triggers the `onclick` prop; the row is a
  // <button> under the hood for keyboard access and proper focus
  // handling.

  import type { Snippet } from 'svelte';

  interface Props {
    /** Single character shown inside the square icon mark. */
    initial: string;
    title: string;
    /** Secondary line under the title. Optional. */
    meta?: string;
    selected?: boolean;
    onclick?: (event: MouseEvent) => void;
    ariaLabel?: string;
    /** Trailing slot for kind chip + timestamp. */
    trailing?: Snippet;
  }

  let {
    initial,
    title,
    meta,
    selected = false,
    onclick,
    ariaLabel,
    trailing,
  }: Props = $props();
</script>

<button
  type="button"
  class="row"
  class:selected
  aria-label={ariaLabel ?? title}
  {onclick}
>
  <span class="icon" aria-hidden="true">{initial.toUpperCase()}</span>

  <span class="content">
    <span class="title">{title}</span>
    {#if meta}
      <span class="meta">{meta}</span>
    {/if}
  </span>

  {#if trailing}
    <span class="trailing">{@render trailing()}</span>
  {/if}
</button>

<style>
  .row {
    width: 100%;
    display: flex;
    align-items: center;
    gap: var(--s-4);
    height: 60px;
    padding: 0 var(--s-4);
    background: transparent;
    border: none;
    border-bottom: 1px solid var(--border-subtle);
    border-radius: var(--r-sm);
    text-align: left;
    cursor: pointer;
    transition:
      background var(--dur-micro) var(--ease-calm);
  }

  .row:hover {
    background: var(--surface-hover);
  }

  .row.selected {
    background: var(--accent-soft);
  }

  .row:last-of-type {
    border-bottom: none;
  }

  .icon {
    width: 32px;
    height: 32px;
    flex-shrink: 0;
    border-radius: var(--r-sm);
    background: var(--surface-2);
    border: 1px solid var(--border);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-family: var(--font-ui);
    font-size: var(--fs-sm);
    font-weight: var(--fw-semibold);
    color: var(--text-muted);
    letter-spacing: -0.01em;
  }

  .content {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .title {
    font-size: var(--fs-md);
    line-height: 20px;
    font-weight: var(--fw-medium);
    color: var(--text);
    letter-spacing: -0.005em;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .meta {
    font-size: var(--fs-xs);
    line-height: 14px;
    color: var(--text-faint);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .trailing {
    display: inline-flex;
    align-items: center;
    gap: var(--s-3);
    flex-shrink: 0;
  }
</style>
