// Popup script. Shows a ping/status indicator plus a list of items
// matching the current tab's origin. Clicking an item triggers the
// fill flow on the active tab.

import type {
  HostResponsePayload,
  ItemRef,
  ListMatchingItemsResponse,
  PongResponse,
} from '../src/protocol';

// Origin approval helpers. Duplicated verbatim from content.ts so
// each vite entry gets a self-contained bundle — see the comment
// there for why. Keep in sync.
const APPROVAL_STORAGE_KEY = 'approvedOrigins';
interface ApprovalState {
  [origin: string]: true;
}
async function loadApprovalState(): Promise<ApprovalState> {
  return new Promise((resolve) => {
    chrome.storage.local.get(APPROVAL_STORAGE_KEY, (items) => {
      if (chrome.runtime.lastError) {
        resolve({});
        return;
      }
      const raw = items[APPROVAL_STORAGE_KEY];
      resolve(raw && typeof raw === 'object' ? (raw as ApprovalState) : {});
    });
  });
}
async function getApprovalStatus(origin: string): Promise<'approved' | 'unknown'> {
  const state = await loadApprovalState();
  return state[origin] ? 'approved' : 'unknown';
}
async function approveOrigin(origin: string): Promise<void> {
  const state = await loadApprovalState();
  state[origin] = true;
  return new Promise((resolve) => {
    chrome.storage.local.set({ [APPROVAL_STORAGE_KEY]: state }, () => resolve());
  });
}

async function ask<T extends HostResponsePayload>(payload: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(payload, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response as T);
    });
  });
}

function setStatus(connected: boolean, detail?: string) {
  const el = document.getElementById('status');
  if (!el) return;
  el.className = `status ${connected ? 'connected' : 'disconnected'}`;
  el.textContent = connected ? (detail ?? 'Connected') : (detail ?? 'Offline');
}

function renderItems(items: ItemRef[], origin: string) {
  const list = document.getElementById('items');
  if (!list) return;
  list.innerHTML = '';
  if (items.length === 0) {
    const empty = document.createElement('p');
    empty.className = 't-muted';
    empty.textContent = `No items saved for ${origin}.`;
    list.appendChild(empty);
    return;
  }
  for (const item of items) {
    const row = document.createElement('div');
    row.className = 'item-row';
    row.dataset.id = item.id;

    const left = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = item.title;
    const user = document.createElement('div');
    user.className = 'item-username';
    user.textContent = item.username ?? '';
    left.appendChild(title);
    left.appendChild(user);

    row.appendChild(left);
    row.addEventListener('click', () => triggerFill());

    list.appendChild(row);
  }
}

async function triggerFill() {
  // Delegate to the background worker, which tells the active tab's
  // content script to do the DOM work.
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  await chrome.tabs.sendMessage(tab.id, { kind: 'fill-request' }).catch(() => {
    /* content script may not be loaded on this page; ignore */
  });
  window.close();
}

function renderApprovalPrompt(origin: string) {
  const list = document.getElementById('items');
  if (!list) return;
  list.innerHTML = '';

  const card = document.createElement('div');
  card.className = 'item-row approval-prompt';

  const text = document.createElement('div');
  const title = document.createElement('div');
  title.className = 'item-title';
  title.textContent = 'First time on this site';
  const body = document.createElement('div');
  body.className = 'item-username';
  body.textContent = `Allow unovault to autofill on ${origin}?`;
  text.appendChild(title);
  text.appendChild(body);

  const allow = document.createElement('button');
  allow.className = 'btn-secondary';
  allow.textContent = 'Allow';
  allow.addEventListener('click', async () => {
    await approveOrigin(origin);
    bootstrap();
  });

  card.appendChild(text);
  card.appendChild(allow);
  list.appendChild(card);
}

async function bootstrap() {
  const originEl = document.getElementById('origin');
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url ? new URL(tab.url) : null;
  const origin = url ? url.origin : 'unknown origin';
  if (originEl) originEl.textContent = origin;

  try {
    const pong = await ask<PongResponse>({ method: 'ping' });
    if (pong.kind !== 'pong') {
      setStatus(false, 'Host error');
      return;
    }
    setStatus(true, `v${pong.version}`);
  } catch (err) {
    setStatus(false, 'Host unavailable');
    console.error('[unovault popup] ping failed', err);
    return;
  }

  // Origin approval gate. Unapproved origins show a consent
  // prompt instead of the matching items list. The user explicitly
  // clicks "Allow" before the extension queries the vault for
  // credentials on this domain.
  if (url) {
    const status = await getApprovalStatus(origin);
    if (status !== 'approved') {
      renderApprovalPrompt(origin);
      document.getElementById('refresh')?.addEventListener('click', bootstrap);
      return;
    }
  }

  try {
    const list = await ask<ListMatchingItemsResponse>({
      method: 'list_matching_items',
      origin,
    });
    if (list.kind === 'list_matching_items') {
      renderItems(list.items, origin);
    }
  } catch (err) {
    console.error('[unovault popup] list failed', err);
  }

  document.getElementById('refresh')?.addEventListener('click', () => {
    bootstrap();
  });
}

bootstrap();
