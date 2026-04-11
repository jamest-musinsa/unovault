<script lang="ts">
  // Input — text, password, and email fields.
  //
  // Wraps a plain <input> with the project's focus ring, placeholder
  // color, and transitions. The caller still controls the bound
  // value and every attribute that affects behavior.
  //
  // Why a wrapper: every view was reimplementing the same ".input"
  // CSS class in week 7-9 and drifting on spacing details. A
  // component forces one truth.

  type AutoFill =
    | 'off'
    | 'on'
    | 'current-password'
    | 'new-password'
    | 'username'
    | 'email'
    | 'one-time-code';

  interface Props {
    value: string;
    type?: 'text' | 'password' | 'email' | 'search';
    placeholder?: string;
    id?: string;
    name?: string;
    required?: boolean;
    disabled?: boolean;
    autocomplete?: AutoFill;
    autofocus?: boolean;
    ariaLabel?: string;
  }

  let {
    value = $bindable(),
    type = 'text',
    placeholder,
    id,
    name,
    required,
    disabled,
    autocomplete,
    autofocus,
    ariaLabel,
  }: Props = $props();
</script>

<!-- svelte-ignore a11y_autofocus -->
<input
  {type}
  {placeholder}
  {id}
  {name}
  {required}
  {disabled}
  {autocomplete}
  {autofocus}
  aria-label={ariaLabel}
  class="input"
  bind:value
/>

<style>
  .input {
    width: 100%;
    height: 40px;
    padding: 0 var(--s-4);
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    font-family: var(--font-ui);
    font-size: var(--fs-md);
    color: var(--text);
    transition:
      background var(--dur-micro) var(--ease-calm),
      border-color var(--dur-micro) var(--ease-calm),
      box-shadow var(--dur-micro) var(--ease-calm);
  }

  .input::placeholder {
    color: var(--text-faint);
  }

  .input:focus {
    outline: none;
    background: var(--surface);
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-ring);
  }

  .input:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  /* Password fields use slightly wider letter spacing so the dots
   * render as visibly distinct instead of a solid bar. */
  .input[type='password'] {
    letter-spacing: 0.08em;
  }
  .input[type='password']::placeholder {
    letter-spacing: 0;
  }
</style>
