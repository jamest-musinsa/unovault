# TESTING.md — manual test checklist

> Run before every public beta release. Each item is pass/fail with
> the date and build hash of the last verified run.

## Critical paths

- [ ] **Create vault** — File → New Vault → enter password → vault opens with 0 items.
- [ ] **Unlock vault** — close app → reopen → enter same password → items are there.
- [ ] **Wrong password** — enter wrong password → "incorrect master password" error.
- [ ] **Add item** — Add Item → fill title/username/url → Create → item appears in list.
- [ ] **Set password** — open item detail → set password field → save.
- [ ] **Lock + unlock round-trip** — add 3 items → lock → unlock → all 3 items present with fields intact.
- [ ] **Import wizard (1Password)** — import a real `.1pux` file → preview shows count + titles → commit → items appear.
- [ ] **Import wizard (Bitwarden)** — import a real `.json` file → same flow.
- [ ] **Import wizard (KeePass)** — import a real `.xml` file → same flow.

## Recovery phrase

- [ ] **Enable recovery** — Settings → Enable Recovery Phrase → 24 words shown → acknowledge checkbox → Continue.
- [ ] **Unlock with recovery** — forget password → CLI: `echo "<24 words>" | unovault ls vault.unovault` succeeds (requires recovery-unlock path in CLI — deferred to v1.0.1 if not yet wired).
- [ ] **Rotate recovery** — Settings → Rotate Recovery Phrase → new 24 words shown → old phrase no longer unlocks.

## Password rotation

- [ ] **Change password** — Settings → Change Master Password → enter current + new → success banner → lock → unlock with new password works → old password rejects.

## iCloud sync

- [ ] **Sync button visible** — when `~/Library/Mobile Documents/com~apple~CloudDocs/` exists, the Sync button appears in the vault list header.
- [ ] **Sync button hidden** — on a machine without iCloud Drive signed in, the button is absent.
- [ ] **Push + pull** — Mac A adds items → Sync → Mac B (sharing the same vault via iCloud) → Sync → items appear on Mac B.

## Chrome extension

- [ ] **Popup ping** — install the unpacked extension → click toolbar icon → popup shows "Connected v0.0.1" (requires native host + desktop app running).
- [ ] **Origin approval** — navigate to a new site → popup shows "Allow this site" → click Allow → items list appears.
- [ ] **Autofill** — Cmd+Shift+L on a login page with a matching item → username + password fields filled.

## CLI

- [ ] **`unovault version`** — prints version + format version.
- [ ] **`unovault ls`** — lists items in tab-separated format.
- [ ] **`unovault get`** — prints password to stdout (pipe to `pbcopy`).
- [ ] **`unovault import`** — imports items from an export file.

## Non-functional

- [ ] **No plaintext in IPC** — open browser devtools → Network tab → no password bytes visible in any Tauri IPC response.
- [ ] **Debug output redacts secrets** — set `RUST_LOG=debug` → no password bytes in stderr.
- [ ] **Zeroize on drop** — (requires miri or instrumented test) — ParsedItem::Drop wipes password bytes.
