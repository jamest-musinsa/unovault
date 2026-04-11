<script lang="ts">
  // FieldLabel — the tiny uppercase letter-spaced label that
  // appears above form fields and in the item detail sheet.
  //
  // Exists as a component (not just a utility class) because every
  // view needed one, every view imported ".t-field-label" slightly
  // differently, and a component lets us swap in tooltips or
  // info-icon affordances later without touching call sites.

  import type { Snippet } from 'svelte';

  interface Props {
    /** Optional id of the control this label names — sets `for=`. */
    for?: string;
    children: Snippet;
  }

  let { for: htmlFor, children }: Props = $props();
</script>

{#if htmlFor}
  <label for={htmlFor} class="t-field-label field-label">{@render children()}</label>
{:else}
  <span class="t-field-label field-label">{@render children()}</span>
{/if}

<style>
  .field-label {
    display: block;
    margin-bottom: var(--s-2);
  }
</style>
