<script lang="ts">
  // Root component. Routes between the four views and installs the
  // global keyboard shortcut listener. No routing library — the whole
  // app is one window and a handful of top-level view names.

  import { onMount } from 'svelte';
  import Locked from './views/Locked.svelte';
  import VaultList from './views/VaultList.svelte';
  import ItemDetail from './views/ItemDetail.svelte';
  import AddItem from './views/AddItem.svelte';
  import StatusBar from './views/StatusBar.svelte';
  import { app } from './lib/store.svelte';
  import { registerShortcuts } from './lib/keyboard.svelte';
  import { lockVault, toCommandError } from './lib/ipc';

  onMount(() => {
    return registerShortcuts(
      () => app.view,
      {
        onNewItem: () => app.setView({ name: 'add-item' }),
        onLock: async () => {
          try {
            await lockVault();
            app.onLock();
          } catch (raw) {
            app.setError(toCommandError(raw));
          }
        },
        onEscape: () => {
          const current = app.view;
          if (
            current.name === 'item-detail' ||
            current.name === 'add-item'
          ) {
            app.setView({ name: 'vault-list' });
          }
        },
        onFocusCommand: () => {
          const input = document.querySelector<HTMLInputElement>('.command-bar input');
          input?.focus();
        },
      },
    );
  });
</script>

<main class="window">
  {#if app.view.name === 'locked'}
    <Locked />
  {:else if app.view.name === 'vault-list'}
    <VaultList />
  {:else if app.view.name === 'item-detail'}
    <!-- Detail sheet slides up over the list. The list stays rendered
         underneath via fixed positioning on Sheet/scrim. -->
    <VaultList />
    <ItemDetail itemId={app.view.itemId} />
  {:else if app.view.name === 'add-item'}
    <AddItem />
  {/if}

  <StatusBar />
</main>

<style>
  .window {
    display: flex;
    flex-direction: column;
    height: 100vh;
    background: var(--bg);
    position: relative;
  }
</style>
