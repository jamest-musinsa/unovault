<script lang="ts">
  // Button — the single button component the whole app uses.
  //
  // Variants:
  //   primary    terracotta fill, white text. One per screen max.
  //   secondary  outline, text color. The "default" action.
  //   ghost      text only, no border. For tertiary actions in toolbars.
  //   danger     red-tinted outline, for destructive actions.
  //
  // Sizes:
  //   md         40px tall, the default
  //   sm         28px tall, for inline toolbar actions
  //   lg         52px tall, for onboarding CTAs
  //
  // All variants honor `disabled`, show a focus-visible ring, and
  // use the house ease curve on the hover transition.

  import type { Snippet } from 'svelte';

  type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
  type Size = 'sm' | 'md' | 'lg';

  interface Props {
    variant?: Variant;
    size?: Size;
    type?: 'button' | 'submit' | 'reset';
    disabled?: boolean;
    fullWidth?: boolean;
    onclick?: (event: MouseEvent) => void;
    ariaLabel?: string;
    children: Snippet;
  }

  let {
    variant = 'secondary',
    size = 'md',
    type = 'button',
    disabled = false,
    fullWidth = false,
    onclick,
    ariaLabel,
    children,
  }: Props = $props();
</script>

<button
  {type}
  {disabled}
  {onclick}
  aria-label={ariaLabel}
  class="btn"
  class:variant-primary={variant === 'primary'}
  class:variant-secondary={variant === 'secondary'}
  class:variant-ghost={variant === 'ghost'}
  class:variant-danger={variant === 'danger'}
  class:size-sm={size === 'sm'}
  class:size-md={size === 'md'}
  class:size-lg={size === 'lg'}
  class:full-width={fullWidth}
>
  {@render children()}
</button>

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--s-2);
    border-radius: var(--r-sm);
    font-family: var(--font-ui);
    font-weight: var(--fw-medium);
    letter-spacing: -0.005em;
    transition:
      background var(--dur-micro) var(--ease-calm),
      color      var(--dur-micro) var(--ease-calm),
      border-color var(--dur-micro) var(--ease-calm),
      box-shadow var(--dur-micro) var(--ease-calm),
      transform  var(--dur-micro) var(--ease-calm);
    user-select: none;
    white-space: nowrap;
  }

  .btn:active:not(:disabled) {
    transform: translateY(1px);
  }

  .btn:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }

  /* --- sizes ------------------------------------------------------ */

  .size-sm {
    height: 28px;
    padding: 0 var(--s-3);
    font-size: var(--fs-xs);
  }

  .size-md {
    height: 40px;
    padding: 0 var(--s-5);
    font-size: var(--fs-md);
  }

  .size-lg {
    height: 52px;
    padding: 0 var(--s-6);
    font-size: var(--fs-md);
  }

  .full-width {
    width: 100%;
  }

  /* --- variants --------------------------------------------------- */

  .variant-primary {
    background: var(--accent);
    color: var(--text-inverse);
    box-shadow: var(--shadow-1),
                inset 0 1px 0 rgba(255, 255, 255, 0.12);
  }
  .variant-primary:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  .variant-primary:active:not(:disabled) {
    background: var(--accent-active);
  }

  .variant-secondary {
    background: transparent;
    color: var(--text);
    border: 1px solid var(--border-strong);
  }
  .variant-secondary:hover:not(:disabled) {
    background: var(--surface-2);
  }

  .variant-ghost {
    background: transparent;
    color: var(--text-muted);
  }
  .variant-ghost:hover:not(:disabled) {
    background: var(--surface-2);
    color: var(--text);
  }

  .variant-danger {
    background: transparent;
    color: var(--red-error);
    border: 1px solid rgba(163, 50, 50, 0.28);
  }
  .variant-danger:hover:not(:disabled) {
    background: var(--red-error-soft);
  }
</style>
