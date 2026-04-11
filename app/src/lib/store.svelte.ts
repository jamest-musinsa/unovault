// Top-level Svelte 5 store driving the app's view routing and vault
// state. Uses runes ($state) so any component that reads from these
// reactive variables updates automatically when they change.
//
// This is a single in-memory store (not persisted across sessions)
// because (a) the backend owns persistence via the vault file, and
// (b) Svelte 5's reactivity is clean enough that a module-level
// `$state` is idiomatic.
//
// View transitions: `setView()` wraps the state update in
// `document.startViewTransition()` when the browser supports it, so
// cross-view navigation animates through the CSS View Transitions
// API without components needing to know about the transition at all.

import type { CommandErrorShape, ItemMetadata } from './ipc';

export type View =
  | { name: 'locked' }
  | { name: 'vault-list' }
  | { name: 'item-detail'; itemId: string }
  | { name: 'add-item' };

// View Transitions API is native on Safari 18+ (macOS 15) and
// Chromium 111+. TypeScript's lib.dom has the type already. When
// the method is missing (older WKWebView builds), fall back to an
// immediate update so the transition is a no-op rather than a
// crash.
function startTransition(update: () => void) {
  if (typeof document.startViewTransition === 'function') {
    document.startViewTransition(update);
  } else {
    update();
  }
}

function makeStore() {
  let view: View = $state({ name: 'locked' });
  let items: ItemMetadata[] = $state([]);
  let error: CommandErrorShape | string | null = $state(null);
  let busy: boolean = $state(false);
  let bundlePath: string = $state('');

  return {
    get view() { return view; },
    get items() { return items; },
    get error() { return error; },
    get busy() { return busy; },
    get bundlePath() { return bundlePath; },

    setView(v: View) {
      startTransition(() => {
        view = v;
      });
    },
    setItems(list: ItemMetadata[]) { items = list; },
    setError(value: CommandErrorShape | string | null) { error = value; },
    setBusy(flag: boolean) { busy = flag; },
    setBundlePath(p: string) { bundlePath = p; },

    /// Called after a successful unlock or create. Flips the view to
    /// the vault list and clears any residual error toast.
    onUnlock(list: ItemMetadata[], path: string) {
      startTransition(() => {
        items = list;
        bundlePath = path;
        error = null;
        view = { name: 'vault-list' };
      });
    },

    /// Called by the lock button in the header / on Cmd+L.
    onLock() {
      startTransition(() => {
        items = [];
        view = { name: 'locked' };
      });
    },

    /// Clear the error banner. Called by onDismiss on ErrorBanner.
    clearError() { error = null; },
  };
}

export const app = makeStore();
