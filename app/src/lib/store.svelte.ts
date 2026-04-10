// Top-level Svelte 5 store driving the app's view routing and vault
// state. Uses runes ($state) so any component that reads from these
// reactive variables updates automatically when they change.
//
// This is a single in-memory store (not persisted across sessions)
// because (a) the backend owns persistence via the vault file, and
// (b) Svelte 5's reactivity is clean enough that a module-level
// `$state` is idiomatic.

import type { ItemMetadata } from './ipc';

export type View =
  | { name: 'locked' }
  | { name: 'vault-list' }
  | { name: 'item-detail'; itemId: string }
  | { name: 'add-item' };

function makeStore() {
  let view: View = $state({ name: 'locked' });
  let items: ItemMetadata[] = $state([]);
  let error: string | null = $state(null);
  let busy: boolean = $state(false);
  let bundlePath: string = $state('');

  return {
    get view() { return view; },
    get items() { return items; },
    get error() { return error; },
    get busy() { return busy; },
    get bundlePath() { return bundlePath; },

    setView(v: View) { view = v; },
    setItems(list: ItemMetadata[]) { items = list; },
    setError(message: string | null) { error = message; },
    setBusy(flag: boolean) { busy = flag; },
    setBundlePath(p: string) { bundlePath = p; },

    /// Called after a successful unlock or create. Flips the view to
    /// the vault list and clears any residual error toast.
    onUnlock(list: ItemMetadata[], path: string) {
      items = list;
      bundlePath = path;
      error = null;
      view = { name: 'vault-list' };
    },

    /// Called by the lock button in the header / on Cmd+L.
    onLock() {
      items = [];
      view = { name: 'locked' };
    },
  };
}

export const app = makeStore();
