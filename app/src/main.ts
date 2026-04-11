// Entry point for the Svelte 5 frontend. Mounts the root App
// component into the #app element declared by index.html. Uses the
// Svelte 5 `mount` API (runes mode).

import { mount } from 'svelte';
import App from './App.svelte';
import './lib/styles/global.css';

const target = document.getElementById('app');
if (!target) {
  throw new Error('#app root element not found in index.html');
}

const app = mount(App, { target });

export default app;
