<script lang="ts">
  // ErrorBanner — category-tinted inline error display.
  //
  // The frontend receives `CommandError` from every IPC call as a
  // category + message pair. This component renders the pair with a
  // category-appropriate visual treatment: user-actionable gets a
  // soft red, transient/network gets amber, anything else gets the
  // default error styling.
  //
  // No close button by default — errors are cleared by whatever
  // triggered them (retry, navigate away). If the parent wants a
  // dismiss affordance, pass the `onDismiss` prop.

  import type { CommandErrorShape } from '../ipc';
  import Button from './Button.svelte';

  interface Props {
    error: CommandErrorShape | string;
    onDismiss?: () => void;
  }

  let { error, onDismiss }: Props = $props();

  const category = $derived.by(() => {
    if (typeof error === 'string') {
      return 'unknown';
    }
    return error.category;
  });

  const headline = $derived.by(() => {
    if (typeof error === 'string') {
      return 'Something went wrong';
    }
    return {
      UserActionable: 'Please check your input',
      NetworkTransient: 'Temporary issue',
      HardwareIssue: 'Hardware check',
      BugInUnovault: 'Unexpected error',
      PlatformPolicy: 'Permission needed',
    }[error.category];
  });

  const message = $derived.by(() => {
    if (typeof error === 'string') return error;
    return error.message;
  });
</script>

<div
  class="banner"
  class:tone-user={category === 'UserActionable'}
  class:tone-transient={category === 'NetworkTransient'}
  class:tone-hardware={category === 'HardwareIssue'}
  class:tone-bug={category === 'BugInUnovault'}
  class:tone-policy={category === 'PlatformPolicy'}
  role="alert"
>
  <div class="text">
    <p class="headline">{headline}</p>
    <p class="message t-meta">{message}</p>
  </div>
  {#if onDismiss}
    <Button variant="ghost" size="sm" onclick={onDismiss} ariaLabel="Dismiss error">
      Dismiss
    </Button>
  {/if}
</div>

<style>
  .banner {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--s-3);
    padding: var(--s-3) var(--s-4);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    background: var(--surface-2);
  }

  .text {
    flex: 1;
    min-width: 0;
  }

  .headline {
    margin: 0 0 var(--s-1) 0;
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
    color: var(--text);
  }

  .message {
    margin: 0;
    word-break: break-word;
  }

  .tone-user {
    border-color: var(--accent-ring);
    background: var(--accent-soft);
  }
  .tone-user .headline {
    color: var(--accent-hover);
  }

  .tone-transient,
  .tone-hardware {
    border-color: rgba(184, 120, 44, 0.28);
    background: rgba(184, 120, 44, 0.08);
  }
  .tone-transient .headline,
  .tone-hardware .headline {
    color: var(--amber-warn);
  }

  .tone-bug {
    border-color: rgba(163, 50, 50, 0.28);
    background: var(--red-error-soft);
  }
  .tone-bug .headline {
    color: var(--red-error);
  }

  .tone-policy {
    border-color: var(--border-strong);
    background: var(--surface-2);
  }
</style>
