# unovault

> A beautiful, local-first, passkey-first personal vault for macOS. Your secrets on your disk, the way they should be.

**Status:** Public beta candidate. All Rust crates build and test. Desktop app + Chrome extension functional. Format spec published.

## What this is

unovault is a Mac desktop password manager and a Chrome extension, built around an open file format (`.unovault`) that you own. Your vault is an encrypted file on your disk. Sync is iCloud Drive in v1. No account, no server, no subscription. Your data stays yours.

The product thesis: security tools should be beautiful enough that people want to open them, and open enough that nobody can lock you in.

## Features (v1)

- **Local-first encryption** — argon2id KDF, XChaCha20-Poly1305 AEAD, HMAC-SHA256 integrity. Format v2 uses a random master key wrapped under both a password-derived KEK and an optional BIP39 recovery phrase KEK.
- **LWW event log** — append-only chunks with per-item last-writer-wins merge. Deterministic fold across any delivery order.
- **iCloud sync** — chunk files live in iCloud Drive; new chunks from other devices merge on next unlock or manual sync.
- **Import wizard** — 1Password `.1pux`, Bitwarden JSON, KeePass XML. Preview step keeps plaintext on the Rust side; the UI only sees titles and kinds.
- **Recovery phrase** — BIP39 24-word mnemonic. Generated once, shown once, never stored. Unlocks the vault if the password is forgotten.
- **Password rotation** — re-wraps the master key under a new password in O(1). No chunk re-encryption.
- **Software passkey authenticator** — ECDSA P-256 credential generation, signing, and verification. CTAP2 transport deferred until Secure Enclave entitlements are available.
- **Chrome extension** — MV3 skeleton with native messaging host, content-script autofill, origin approval gate.
- **CLI** — `unovault ls`, `get`, `import`. Second reference implementation of the format.
- **IPC safety** — `IpcSafe` marker trait + `#[safe_command]` proc-macro enforce at compile time that no plaintext credential material crosses the Tauri WebView boundary.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Svelte 5 UI (Tauri WebView)                                │
│  CommandBar · VaultList · ItemDetail · ImportWizard · Settings │
└───────────────────────┬─────────────────────────────────────┘
                        │ Tauri IPC (serde JSON, IpcSafe-gated)
┌───────────────────────▼─────────────────────────────────────┐
│  unovault-app (Tauri commands + bridge socket)              │
├─────────────────────────────────────────────────────────────┤
│  unovault-core     vault engine: crypto, format, LWW, sync │
│  unovault-import   1Password / Bitwarden / KeePass parsers  │
│  unovault-passkey  ECDSA P-256 software authenticator       │
│  unovault-cli      CLI binary (second format impl)          │
│  unovault-ffi      Swift bridge via UniFFI                   │
└─────────────────────────────────────────────────────────────┘
         │                              │
   Unix socket                    iCloud Drive
         │                     ~/Library/Mobile Documents/
┌────────▼────────┐
│ unovault-native- │
│ host (Chrome     │
│ native messaging)│
└─────────────────┘
```

## Build

```sh
# Full check
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

# Svelte UI
cd app && pnpm install && pnpm svelte-check && pnpm build

# Chrome extension
cd extension && pnpm install && pnpm type-check && pnpm build

# CLI
cargo run -p unovault-cli -- version
echo "hunter2" | cargo run -p unovault-cli -- ls path/to/vault.unovault
```

## Crate layout

| Crate | Purpose |
|---|---|
| `unovault-core` | Vault engine: crypto, format, event, LWW, sync |
| `unovault-import` | 1Password, Bitwarden, KeePass parsers |
| `unovault-passkey` | ECDSA P-256 software authenticator |
| `unovault-cli` | CLI binary |
| `unovault-ffi` | Swift bridge (UniFFI) |
| `unovault-macros` | `#[safe_command]` proc-macro |
| `unovault-native-host` | Chrome native messaging host |
| `unovault-app` (app/src-tauri) | Tauri desktop shell |

## Format specification

See [`docs/SPEC.md`](docs/SPEC.md) for the full `.unovault` format specification, including the key hierarchy, chunk byte layout, event schema, and LWW ordering rules.

## Design references

- Things 3 (Cultured Code) — calmness, typography, whitespace
- Linear — keyboard-first, command bar, motion restraint
- Raycast — single-panel + command bar
- 1Password — the polish bar to beat
- Bitwarden — the OSS predecessor this product intentionally diverges from

## License

MIT
