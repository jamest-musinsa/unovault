# unovault Chrome extension

Manifest V3 extension that bridges the unovault desktop app to Chrome
for password autofill and (later) WebAuthn passkeys.

## Architecture

```
Chrome page
    │
    ▼
content.ts ───► background.ts ───► native messaging port ───► unovault-native-host ───► desktop app IPC
```

* **content.ts** — injected into every `https://` page. Finds login
  forms, fills credentials via native setters.
* **background.ts** — MV3 service worker. Owns the native messaging
  port, routes requests.
* **popup/** — small UI shown when the user clicks the toolbar icon.
* **src/protocol.ts** — shared request/response types.

The native messaging host lives in
`crates/unovault-native-host/` — see week 19 for its implementation.

## Building

```sh
cd extension
pnpm install
pnpm build
```

The build writes `dist/background.js`, `dist/content.js`, and
`dist/popup.js`. The manifest references those paths directly.

To load in Chrome:

1. Open `chrome://extensions`.
2. Enable Developer Mode.
3. Click "Load unpacked" and select the `extension/` directory.

## Icons

Placeholder PNGs live under `icons/`. Final icons match the desktop
app's terracotta accent and follow the design system in `design/`.

## Not yet implemented

* Passkey registration / assertion (WebAuthn intercept).
* Save-on-submit prompt.
* Origin approval flow (first-seen origin gets a one-time "allow"
  prompt before the extension will return credentials to it).
* Per-item match metadata beyond exact origin equality.
