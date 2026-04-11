<script lang="ts">
  // Sheet — a slide-up panel that covers the bottom ~72% of the
  // window. Used for item detail and the add-item form.
  //
  // The backdrop behind the sheet is dimmed and clickable — clicking
  // it calls `onClose`. Esc does the same via a keydown listener on
  // window (scoped to the mounted lifetime of this component).
  //
  // View transitions: the sheet participates in the document-level
  // view transition so navigation in and out animates smoothly. The
  // `view-transition-name` is set via a CSS class so multiple sheets
  // on different routes don't collide.

  import type { Snippet } from 'svelte';
  import { onMount } from 'svelte';

  interface Props {
    onClose: () => void;
    /** Accessible title announced to screen readers. */
    title: string;
    /** Footer slot renders pinned at the bottom of the sheet. */
    footer?: Snippet;
    children: Snippet;
  }

  let { onClose, title, footer, children }: Props = $props();

  onMount(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });
</script>

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="scrim" onclick={onClose} aria-hidden="true"></div>

<div class="sheet" role="dialog" aria-modal="true" aria-label={title}>
  <div class="sheet-body">
    {@render children()}
  </div>

  {#if footer}
    <footer class="sheet-footer">{@render footer()}</footer>
  {/if}
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    background: var(--overlay-scrim);
    z-index: var(--z-sheet);
    cursor: pointer;
  }

  .sheet {
    position: fixed;
    left: 0;
    right: 0;
    bottom: 28px; /* sit above the status bar */
    height: 72%;
    background: var(--surface);
    background-image: linear-gradient(
      180deg,
      var(--surface) 0%,
      var(--surface-2) 140%
    );
    border-top-left-radius: var(--r-lg);
    border-top-right-radius: var(--r-lg);
    box-shadow: var(--shadow-sheet);
    z-index: calc(var(--z-sheet) + 1);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    view-transition-name: detail-sheet;
  }

  .sheet-body {
    flex: 1;
    overflow-y: auto;
    padding: var(--s-6) var(--s-8);
  }

  .sheet-footer {
    border-top: 1px solid var(--border);
    background: var(--surface-2);
    padding: var(--s-4) var(--s-8);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--s-4);
    flex-shrink: 0;
  }

  /* View transition choreography: sheet slides up on enter, down on
   * exit. The ::view-transition pseudos are applied at the document
   * level; this file only declares the name. */
  @keyframes sheet-slide-up {
    from {
      transform: translateY(8%);
      opacity: 0;
    }
    to {
      transform: translateY(0);
      opacity: 1;
    }
  }
  @keyframes sheet-slide-down {
    from {
      transform: translateY(0);
      opacity: 1;
    }
    to {
      transform: translateY(8%);
      opacity: 0;
    }
  }

  :global(::view-transition-new(detail-sheet)) {
    animation: sheet-slide-up var(--dur-base) var(--ease-calm);
  }
  :global(::view-transition-old(detail-sheet)) {
    animation: sheet-slide-down var(--dur-base) var(--ease-calm);
  }
</style>
