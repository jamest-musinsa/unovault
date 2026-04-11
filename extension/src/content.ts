// Content script injected into every https page. Responsible for:
//
// 1. Detecting login forms on the page.
// 2. Showing a small "Fill from unovault" inline hint next to the
//    password field (click or Cmd/Ctrl+Shift+L to open the picker).
// 3. Filling the selected credential via JS property setters that
//    emulate user input — otherwise React-controlled inputs drop
//    the paste.
//
// The actual credential lookup happens in the background worker;
// this script is just the DOM layer.

import type { HostResponsePayload, ItemRef } from './protocol';

interface FillMessage {
  kind: 'fill-request';
}

type WorkerMessage = FillMessage;

function findLoginForm(): HTMLFormElement | null {
  // Heuristic: any form that contains an <input type="password"> is
  // a login form. Good enough for v1 — a future iteration can fall
  // back to username + password pairs that live outside a form.
  const password = document.querySelector<HTMLInputElement>(
    'input[type="password"]',
  );
  if (!password) return null;
  return password.closest('form');
}

function findUsernameInput(form: HTMLFormElement): HTMLInputElement | null {
  // Common patterns: autocomplete="username", type="email",
  // name matches /user|email|login/i.
  const byAutocomplete = form.querySelector<HTMLInputElement>(
    'input[autocomplete="username"]',
  );
  if (byAutocomplete) return byAutocomplete;

  const byType = form.querySelector<HTMLInputElement>('input[type="email"]');
  if (byType) return byType;

  const candidates = form.querySelectorAll<HTMLInputElement>(
    'input[type="text"], input:not([type])',
  );
  for (const input of candidates) {
    const name = (input.name || input.id || '').toLowerCase();
    if (/user|email|login/.test(name)) return input;
  }
  return null;
}

function findPasswordInput(form: HTMLFormElement): HTMLInputElement | null {
  return form.querySelector<HTMLInputElement>('input[type="password"]');
}

/// Use the native setter so frameworks like React see the input
/// event. Direct assignment to `.value` bypasses React's synthetic
/// event handling and the new value gets reverted on the next render.
function nativeSetValue(input: HTMLInputElement, value: string) {
  const descriptor = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(input),
    'value',
  );
  descriptor?.set?.call(input, value);
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

async function askWorker<T extends HostResponsePayload>(
  payload: unknown,
): Promise<T> {
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

async function fillFromUnovault() {
  const form = findLoginForm();
  if (!form) return;
  const username = findUsernameInput(form);
  const password = findPasswordInput(form);
  if (!password) return;

  const listResponse = await askWorker<HostResponsePayload>({
    method: 'list_matching_items',
    origin: window.location.origin,
  });
  if (listResponse.kind !== 'list_matching_items') {
    console.warn('[unovault] list failed', listResponse);
    return;
  }
  const items: ItemRef[] = listResponse.items;
  if (items.length === 0) return;

  // v1 autofill policy: if exactly one item matches the origin,
  // use it silently. If multiple match, pick the first — a proper
  // picker UI lands in a later sprint.
  const chosen = items[0];

  const passwordResponse = await askWorker<HostResponsePayload>({
    method: 'get_password',
    item_id: chosen.id,
  });
  if (passwordResponse.kind !== 'get_password') {
    console.warn('[unovault] get_password failed', passwordResponse);
    return;
  }

  if (username && chosen.username) {
    nativeSetValue(username, chosen.username);
  }
  nativeSetValue(password, passwordResponse.password);
}

chrome.runtime.onMessage.addListener((message: WorkerMessage, _sender, sendResponse) => {
  if (message.kind === 'fill-request') {
    fillFromUnovault()
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }
  return false;
});
