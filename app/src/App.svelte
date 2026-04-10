<script lang="ts">
  // Root component. Does one thing: look at `app.view` and render
  // the matching screen. No routing library — the whole app is one
  // window and a handful of top-level view names.

  import Locked from './views/Locked.svelte';
  import VaultList from './views/VaultList.svelte';
  import ItemDetail from './views/ItemDetail.svelte';
  import AddItem from './views/AddItem.svelte';
  import StatusBar from './views/StatusBar.svelte';
  import { app } from './lib/store.svelte';
</script>

<main class="window">
  {#if app.view.name === 'locked'}
    <Locked />
  {:else if app.view.name === 'vault-list'}
    <VaultList />
  {:else if app.view.name === 'item-detail'}
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
  }
</style>
