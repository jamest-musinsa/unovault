<script lang="ts">
  // KindChip — the small uppercase pill showing Password / Passkey /
  // TOTP / etc. in the vault list and item detail header.
  //
  // Passkey is visually distinctive (terracotta tint) because the
  // design thesis is "passkey-first." Every other kind shares the
  // muted outline treatment.

  import type { ItemKindTag } from '../ipc';

  interface Props {
    kind: ItemKindTag;
  }

  let { kind }: Props = $props();

  const label = $derived<string>(
    {
      Password: 'Password',
      Passkey: 'Passkey',
      Totp: 'TOTP',
      SshKey: 'SSH Key',
      ApiToken: 'API Token',
      SecureNote: 'Secure Note',
    }[kind],
  );
</script>

<span
  class="chip"
  class:chip-passkey={kind === 'Passkey'}
  aria-label={`Item kind: ${label}`}
>
  {label}
</span>

<style>
  .chip {
    display: inline-flex;
    align-items: center;
    font-family: var(--font-ui);
    font-size: 10px;
    line-height: 1;
    font-weight: var(--fw-semibold);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-faint);
    padding: 4px 8px;
    border: 1px solid var(--border);
    border-radius: var(--r-full);
    background: transparent;
    user-select: none;
    white-space: nowrap;
  }

  .chip-passkey {
    color: var(--accent);
    border-color: var(--accent-ring);
    background: var(--accent-soft);
  }
</style>
