<script lang="ts">
  // CommandBar — the always-focused search/command input at the
  // top of the unlocked vault list. Matches the spike: 56px tall,
  // search icon left, kbd chip right, terracotta focus ring.
  //
  // Not a general-purpose search — it's the single anchor for "what
  // would you like to do?" and later evolves to support command
  // palette actions ("new item", "lock", "settings") in addition to
  // free-text search.

  interface Props {
    value: string;
    placeholder?: string;
    onEnter?: () => void;
  }

  let {
    value = $bindable(),
    placeholder = 'Search or type a command',
    onEnter,
  }: Props = $props();

  function handleKeydown(event: KeyboardEvent) {
    if (event.key === 'Enter' && onEnter) {
      onEnter();
    }
  }
</script>

<div class="command-bar">
  <svg
    class="search-icon"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.8"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
  >
    <circle cx="11" cy="11" r="7" />
    <line x1="20" y1="20" x2="16.5" y2="16.5" />
  </svg>

  <!-- svelte-ignore a11y_autofocus -->
  <input
    type="text"
    class="cmd-input"
    {placeholder}
    bind:value
    onkeydown={handleKeydown}
    aria-label="Search vault"
    autofocus
  />

  <span class="kbd" aria-hidden="true">⌘K</span>
</div>

<style>
  .command-bar {
    display: flex;
    align-items: center;
    gap: var(--s-3);
    height: 56px;
    padding: 0 var(--s-5);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    box-shadow: var(--shadow-1);
    transition:
      border-color var(--dur-micro) var(--ease-calm),
      box-shadow var(--dur-micro) var(--ease-calm);
  }

  .command-bar:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-ring), var(--shadow-1);
  }

  .search-icon {
    width: 18px;
    height: 18px;
    color: var(--text-faint);
    flex-shrink: 0;
  }

  .cmd-input {
    flex: 1;
    font-family: var(--font-ui);
    font-size: var(--fs-lg);
    line-height: 1;
    color: var(--text);
    letter-spacing: -0.005em;
    min-width: 0;
  }

  .cmd-input::placeholder {
    color: var(--text-faint);
  }

  .kbd {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--text-faint);
    padding: 3px 8px;
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    background: var(--surface-2);
    user-select: none;
    flex-shrink: 0;
  }
</style>
