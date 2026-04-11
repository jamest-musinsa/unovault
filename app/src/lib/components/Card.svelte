<script lang="ts">
  // Card — elevated surface used by the Locked Vault Home and the
  // onboarding scenes. Not used for list items (those use ListRow).
  //
  // The background is a very subtle vertical gradient from surface
  // to surface-2 so the card has quiet warmth against the page
  // background instead of looking flat.

  import type { Snippet } from 'svelte';

  type Size = 'sm' | 'md' | 'lg';

  interface Props {
    /** Card width in px. Default 380 matches the locked home spike. */
    width?: number;
    /** Internal padding scale. */
    padding?: Size;
    children: Snippet;
  }

  let { width = 380, padding = 'md', children }: Props = $props();
</script>

<div
  class="card"
  class:padding-sm={padding === 'sm'}
  class:padding-md={padding === 'md'}
  class:padding-lg={padding === 'lg'}
  style="width: {width}px;"
>
  {@render children()}
</div>

<style>
  .card {
    background: var(--surface);
    background-image: linear-gradient(
      180deg,
      var(--surface) 0%,
      var(--surface-2) 180%
    );
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    box-shadow: var(--shadow-3);
    display: flex;
    flex-direction: column;
  }

  .padding-sm { padding: var(--s-5); }
  .padding-md { padding: var(--s-8) var(--s-8) var(--s-6) var(--s-8); }
  .padding-lg { padding: var(--s-10); }
</style>
