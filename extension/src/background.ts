// Background service worker. The Chrome extension's long-lived-ish
// event handler — MV3 service workers get suspended when idle and
// woken on events, so anything held in module state is volatile.
//
// Responsibilities:
//
// 1. Own the native messaging port to the unovault desktop app.
// 2. Route requests from content scripts and the popup through the
//    port and back.
// 3. Handle the "fill from unovault" keyboard command.
//
// The native host name `com.unovault.host` must match the host
// manifest file we install on the user's machine — see the
// `unovault-native-host` crate for the generator.

import {
  HostRequest,
  HostRequestPayload,
  HostResponse,
  HostResponsePayload,
  newRequestId,
} from './protocol';

const HOST_NAME = 'com.unovault.host';

/// State held by the service worker. Intentionally minimal because
/// the worker can be terminated at any time.
interface WorkerState {
  port: chrome.runtime.Port | null;
  pending: Map<string, (payload: HostResponsePayload) => void>;
}

const state: WorkerState = {
  port: null,
  pending: new Map(),
};

function ensurePort(): chrome.runtime.Port {
  if (state.port) return state.port;
  const port = chrome.runtime.connectNative(HOST_NAME);
  port.onMessage.addListener((message: HostResponse) => {
    const resolver = state.pending.get(message.request_id);
    if (!resolver) {
      // Orphaned response — the requester is gone. Drop silently;
      // a future version could log to chrome.storage for debugging.
      return;
    }
    state.pending.delete(message.request_id);
    resolver(message.payload);
  });
  port.onDisconnect.addListener(() => {
    const error = chrome.runtime.lastError;
    // Reject every pending request with a synthetic error so
    // callers don't hang forever.
    for (const [, resolver] of state.pending) {
      resolver({
        kind: 'error',
        category: 'NativeHostDisconnected',
        message: error?.message ?? 'native messaging host disconnected',
      });
    }
    state.pending.clear();
    state.port = null;
  });
  state.port = port;
  return port;
}

/// Send a request to the native host and await its response.
function sendRequest(payload: HostRequestPayload): Promise<HostResponsePayload> {
  const request: HostRequest = {
    request_id: newRequestId(),
    payload,
  };
  return new Promise((resolve) => {
    state.pending.set(request.request_id, resolve);
    try {
      ensurePort().postMessage(request);
    } catch (err) {
      state.pending.delete(request.request_id);
      resolve({
        kind: 'error',
        category: 'NativeHostUnavailable',
        message: err instanceof Error ? err.message : String(err),
      });
    }
  });
}

// Content scripts and the popup talk to the worker via
// chrome.runtime.sendMessage. We treat every message as a
// HostRequestPayload and forward it verbatim.
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || typeof message !== 'object' || !('method' in message)) {
    sendResponse({
      kind: 'error',
      category: 'BadRequest',
      message: 'extension message missing method field',
    });
    return false;
  }

  sendRequest(message as HostRequestPayload).then(sendResponse);
  // Return true to keep the message channel open for the async
  // response. Chrome needs this or the popup's await resolves to
  // undefined.
  return true;
});

// Keyboard command handler. Triggers the fill flow on the active tab.
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== 'fill-from-unovault') return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  // The content script owns the DOM-aware half of the fill. We
  // just nudge it and let it call back into us if it needs items.
  chrome.tabs.sendMessage(tab.id, { kind: 'fill-request' }).catch(() => {
    // Tab may not have a content script (e.g. chrome://). Silent
    // failure is the right posture — the user can still open the
    // popup.
  });
});

// Dev signal: when the worker boots, log once. Useful during
// manual testing with `chrome://extensions` → "Service worker".
console.log('[unovault] background worker ready');
