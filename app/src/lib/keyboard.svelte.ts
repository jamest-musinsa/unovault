// Global keyboard shortcut handling. One listener attached at the
// app root; every shortcut defined here maps to a callback the root
// component provides.
//
// Keyboard map (week 10-13 scope — full set in weeks 14-17):
//
//   ⌘K  focus command bar      (vault-list view only)
//   ⌘N  new item                (vault-list view only)
//   ⌘L  lock vault              (any unlocked view)
//   Esc back / close sheet      (any modal-ish view)
//
// Future (week 14+):
//   ⌘,  settings
//   ⌘F  same as ⌘K — grep familiarity
//   ⌘C  copy password of selected item
//   ⌘⇧C copy TOTP of selected item
//   ⌘R  reveal password toggle
//   ⌘/  show all shortcuts
//
// This file uses the .svelte.ts extension so we can eventually hold
// `$state` for the currently-registered handlers, though today the
// handlers are passed in explicitly via `registerShortcuts()`.

import type { View } from './store.svelte';

export interface ShortcutHandlers {
  /** Called for ⌘N in vault-list view. */
  onNewItem?: () => void;
  /** Called for ⌘L when the vault is unlocked. */
  onLock?: () => void;
  /** Called for Esc in any view that has a back/close action. */
  onEscape?: () => void;
  /** Called for ⌘K in vault-list view. Focus the command bar. */
  onFocusCommand?: () => void;
}

/// Install a window-level keydown listener and return a cleanup
/// function. The view is read on every keydown (not closed over) so
/// the shortcut map tracks the current screen automatically.
export function registerShortcuts(
  getView: () => View,
  handlers: ShortcutHandlers,
): () => void {
  function onKeyDown(event: KeyboardEvent) {
    // Only the Command key on macOS (or Ctrl on other OSes) counts
    // for the single-character shortcuts. Escape is handled
    // unconditionally.
    const isCmd = event.metaKey || event.ctrlKey;
    const view = getView();

    if (event.key === 'Escape') {
      if (handlers.onEscape && view.name !== 'locked') {
        event.preventDefault();
        handlers.onEscape();
      }
      return;
    }

    if (!isCmd) return;

    const key = event.key.toLowerCase();

    switch (key) {
      case 'k':
        if (view.name === 'vault-list' && handlers.onFocusCommand) {
          event.preventDefault();
          handlers.onFocusCommand();
        }
        break;

      case 'n':
        if (view.name === 'vault-list' && handlers.onNewItem) {
          event.preventDefault();
          handlers.onNewItem();
        }
        break;

      case 'l':
        if (view.name !== 'locked' && handlers.onLock) {
          event.preventDefault();
          handlers.onLock();
        }
        break;
    }
  }

  window.addEventListener('keydown', onKeyDown);
  return () => window.removeEventListener('keydown', onKeyDown);
}
