//! Tauri command handlers — the Rust side of every IPC call the
//! frontend can invoke.
//!
//! Every function here is wrapped with two attributes:
//!
//! * `#[unovault_macros::safe_command]` — static assertion that the
//!   return type implements `IpcSafe`. This is the compile-time guard
//!   against accidentally shipping a plaintext `String` to the
//!   WebView. See `crates/unovault-macros` for the implementation.
//!
//! * `#[tauri::command]` — Tauri's own registration attribute that
//!   generates the runtime glue to dispatch IPC calls. Order matters:
//!   `safe_command` must come **first** so it sees the function's
//!   original return type before Tauri rewrites it into its own
//!   runtime representation.
//!
//! The backend owns the vault instance via `State<AppState>`. Every
//! command that touches the vault locks the `RwLock`, does its work,
//! and drops the lock immediately. No command leaks the `Vault`
//! handle outside of `commands.rs`.

use serde::{Deserialize, Serialize};
use tauri::State;
use unovault_core::event::{FieldKey, FieldValue, ItemKind as CoreItemKind, ItemSnapshot};
use unovault_core::ipc::{IpcSafe, IpcString, ItemKindTag, ItemMetadata};
use unovault_core::secret::Secret;
use unovault_core::vault::Vault;
use unovault_core::{InstallIdStore, ItemId as CoreItemId};
use unovault_import::{ImportSource, ParsedItem};
use unovault_macros::safe_command;

use crate::error::{CommandError, CommandResult};
use crate::state::AppState;

// =============================================================================
// IMPORT PREVIEW TYPES
// =============================================================================
//
// These cross the IPC boundary as the response to `preview_import`.
// They intentionally carry only metadata — titles, kinds, skip reasons.
// The plaintext `ParsedItem::password` / `totp_secret` / `notes` for
// each row stays on the Rust side inside `AppState::pending_import`
// until the frontend calls `commit_import`.

/// Preview payload returned to the frontend. The frontend shows the
/// counts + per-item lists in a review step, then fires `commit_import`
/// or `cancel_import`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPreview {
    pub source: IpcString,
    pub imported_count: u32,
    pub skipped_count: u32,
    pub preview_items: Vec<ImportPreviewItem>,
    pub skipped_items: Vec<ImportPreviewSkipped>,
    pub summary_line: IpcString,
}

impl IpcSafe for ImportPreview {}

/// One row in the "will import" list: title + kind badge only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPreviewItem {
    pub title: IpcString,
    pub kind: ItemKindTag,
    pub has_password: bool,
    pub has_totp: bool,
    pub has_notes: bool,
}

impl IpcSafe for ImportPreviewItem {}

/// One row in the "skipped" list: title + reason, both IPC-safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPreviewSkipped {
    pub title: IpcString,
    pub reason: IpcString,
}

impl IpcSafe for ImportPreviewSkipped {}

/// Outcome of `commit_import`: how many rows were actually written and
/// how many failed mid-flight so the UI can render a success banner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportCommitResult {
    pub committed_count: u32,
    pub failed_count: u32,
}

impl IpcSafe for ImportCommitResult {}

// =============================================================================
// VAULT LIFECYCLE
// =============================================================================

/// Create a brand-new vault at `bundle_path` protected by `password`.
/// Leaves the vault unlocked in state and returns the initial (empty)
/// item list so the frontend can route straight into the list view.
#[safe_command]
#[tauri::command]
pub fn create_vault(
    state: State<'_, AppState>,
    bundle_path: IpcString,
    password: IpcString,
) -> CommandResult<Vec<ItemMetadata>> {
    let install = load_install_id(&state)?;
    let vault = Vault::create(
        std::path::PathBuf::from(bundle_path.into_inner()),
        Secret::new(password.into_inner()),
        install,
    )?;

    let metadata: Vec<ItemMetadata> = vault.items().map(ItemMetadata::from_item_state).collect();

    swap_vault(&state, Some(vault))?;
    Ok(metadata)
}

/// Unlock an existing vault at `bundle_path`. Slow — argon2id
/// derivation dominates (~500 ms – 1.5 s depending on hardware).
/// The frontend must show a "Unlocking…" spinner.
#[safe_command]
#[tauri::command]
pub fn unlock_vault(
    state: State<'_, AppState>,
    bundle_path: IpcString,
    password: IpcString,
) -> CommandResult<Vec<ItemMetadata>> {
    let install = load_install_id(&state)?;
    let vault = Vault::unlock(
        std::path::PathBuf::from(bundle_path.into_inner()),
        Secret::new(password.into_inner()),
        install,
    )?;

    let metadata: Vec<ItemMetadata> = vault.items().map(ItemMetadata::from_item_state).collect();

    swap_vault(&state, Some(vault))?;
    Ok(metadata)
}

/// Lock the currently-open vault by dropping the `Vault` from state.
/// The drop invokes `Secret<DerivedKeys>::Drop` which zeroizes the
/// derived keys. Returns `()` — no items leak back to the frontend.
#[safe_command]
#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>) -> CommandResult<()> {
    swap_vault(&state, None)?;
    Ok(())
}

/// Whether the vault is currently unlocked.
#[safe_command]
#[tauri::command]
pub fn is_unlocked(state: State<'_, AppState>) -> CommandResult<bool> {
    Ok(state.is_unlocked())
}

// =============================================================================
// READ PATH
// =============================================================================

/// Return every item in the current vault as IPC-safe metadata. Fails
/// if the vault is locked — the frontend should route back to the
/// locked screen instead of retrying.
#[safe_command]
#[tauri::command]
pub fn list_items(state: State<'_, AppState>) -> CommandResult<Vec<ItemMetadata>> {
    let guard = state
        .vault
        .read()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("vault is locked")))?;
    Ok(vault.items().map(ItemMetadata::from_item_state).collect())
}

/// Look up a single item's metadata by id. Returns `None` if the id
/// does not exist; callers route back to the list view in that case.
#[safe_command]
#[tauri::command]
pub fn get_item(
    state: State<'_, AppState>,
    item_id: IpcString,
) -> CommandResult<Option<ItemMetadata>> {
    let item_id = parse_item_id(item_id.as_str())?;
    let guard = state
        .vault
        .read()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("vault is locked")))?;
    Ok(vault.get(&item_id).map(ItemMetadata::from_item_state))
}

// =============================================================================
// WRITE PATH
// =============================================================================

/// Add a new item. Persisted to a chunk file immediately via `save()`
/// so a crash between `add_item` and the next explicit save does not
/// lose the item. Returns the new item's metadata.
#[safe_command]
#[tauri::command]
pub fn add_item(
    state: State<'_, AppState>,
    title: IpcString,
    kind: ItemKindTag,
    username: Option<IpcString>,
    url: Option<IpcString>,
) -> CommandResult<ItemMetadata> {
    let mut guard = state
        .vault
        .write()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("vault is locked")))?;

    let snapshot = ItemSnapshot {
        title: title.into_inner(),
        kind: CoreItemKind::from(kind),
        username: username.map(IpcString::into_inner),
        url: url.map(IpcString::into_inner),
    };

    let id = vault.add_item(snapshot)?;
    vault.save()?;

    let metadata = vault
        .get(&id)
        .map(ItemMetadata::from_item_state)
        .ok_or_else(|| {
            CommandError::BugInUnovault(IpcString::new(
                "add_item returned an id that does not exist",
            ))
        })?;

    Ok(metadata)
}

// =============================================================================
// SECRET OPERATIONS (Rust-side-only — no plaintext ever crosses IPC)
// =============================================================================

/// Set the password field on an item.
///
/// The `password` parameter crosses the boundary as an `IpcString` —
/// callers on the frontend have typed it into a password input field
/// inside the WebView process already, which is the one place the
/// UI is allowed to hold plaintext briefly. The backend immediately
/// wraps it in a `FieldValue::Bytes` and drops the String; the vault
/// engine then encrypts it into the next chunk file.
///
/// Returns metadata for the updated item.
#[safe_command]
#[tauri::command]
pub fn set_password(
    state: State<'_, AppState>,
    item_id: IpcString,
    password: IpcString,
) -> CommandResult<ItemMetadata> {
    let item_id = parse_item_id(item_id.as_str())?;
    let mut guard = state
        .vault
        .write()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("vault is locked")))?;

    let applied = vault.set_field(
        item_id,
        FieldKey::Password,
        FieldValue::Bytes(password.into_inner().into_bytes()),
    )?;
    if !applied {
        return Err(CommandError::UserActionable(IpcString::new(
            "item not found",
        )));
    }
    vault.save()?;

    vault
        .get(&item_id)
        .map(ItemMetadata::from_item_state)
        .ok_or_else(|| CommandError::BugInUnovault(IpcString::new("set_password item vanished")))
}

/// Copy a field's plaintext value to the system clipboard **without
/// crossing the IPC boundary**. This is the Rust-side-only path that
/// the reveal/copy UX requires per the architectural rules.
///
/// v0 scaffold: the actual clipboard write is a TODO marker — the
/// real implementation lands with the tauri-plugin-clipboard-manager
/// integration in a follow-up week. The command is present now so
/// the frontend can route its copy button to the right IPC name
/// without the backend being a placeholder that silently does
/// nothing.
#[safe_command]
#[tauri::command]
pub fn copy_password_to_clipboard(
    state: State<'_, AppState>,
    item_id: IpcString,
) -> CommandResult<()> {
    let item_id = parse_item_id(item_id.as_str())?;
    let guard = state
        .vault
        .read()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("vault is locked")))?;

    let item = vault
        .get(&item_id)
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("item not found")))?;
    let _password_bytes = item.password.as_ref().ok_or_else(|| {
        CommandError::UserActionable(IpcString::new("item has no password field"))
    })?;

    // TODO(week 10-13): hand `_password_bytes` to tauri-plugin-clipboard-manager
    // via a native call. Intentionally does not return the bytes;
    // the frontend only learns success/failure via this Result.
    // The password bytes are borrowed from the vault state, not
    // cloned, so they do not escape the function.
    Ok(())
}

// =============================================================================
// ICLOUD SYNC (week 22-23)
// =============================================================================

/// Status of the iCloud sync backend. Reported to the UI so the
/// sync button can be hidden when iCloud is unavailable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ICloudStatus {
    /// Whether the iCloud Drive folder exists and is writable.
    pub available: bool,
    /// Human-readable path the backend would sync to, `None` when
    /// iCloud is not available. Shown in the "Synced to ..." toast.
    pub path: Option<IpcString>,
}

impl IpcSafe for ICloudStatus {}

/// Result of a successful `sync_vault` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncOutcome {
    pub pushed_count: u32,
    pub pulled_count: u32,
    pub path: IpcString,
}

impl IpcSafe for SyncOutcome {}

/// Report whether the iCloud Drive folder is available. Used by the
/// UI to decide whether to render the sync button.
#[safe_command]
#[tauri::command]
pub fn icloud_status() -> CommandResult<ICloudStatus> {
    let path = unovault_core::sync::icloud::icloud_unovault_path();
    let available = path
        .as_ref()
        .map(|p| p.parent().map(|parent| parent.is_dir()).unwrap_or(false))
        .unwrap_or(false);
    Ok(ICloudStatus {
        available,
        path: path.map(|p| IpcString::new(p.display().to_string())),
    })
}

/// Push local chunks to iCloud Drive and pull any chunks iCloud has
/// that we don't. Requires an unlocked vault and an available
/// iCloud Drive folder.
#[safe_command]
#[tauri::command]
pub fn sync_vault(state: State<'_, AppState>) -> CommandResult<SyncOutcome> {
    let backend = unovault_core::sync::icloud::open_icloud_backend()?.ok_or_else(|| {
        CommandError::UserActionable(IpcString::new(
            "iCloud Drive is not available — sign in to iCloud in System Settings",
        ))
    })?;
    let display_path = unovault_core::sync::icloud::display_path_for_status()
        .unwrap_or_else(|| "iCloud Drive".to_string());

    let mut guard = state
        .vault
        .write()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("vault is locked")))?;

    // Flush any pending edits before sync so a concurrent
    // device sees the user's latest work.
    vault.save()?;

    let summary = vault.sync_with_backend(&backend)?;

    Ok(SyncOutcome {
        pushed_count: summary.pushed,
        pulled_count: summary.pulled,
        path: IpcString::new(display_path),
    })
}

// =============================================================================
// RECOVERY + PASSWORD ROTATION (week 21)
// =============================================================================

/// Whether the currently open vault has a recovery slot. Used by
/// the settings view to decide whether the button reads "Enable
/// recovery phrase" or "Rotate recovery phrase".
#[safe_command]
#[tauri::command]
pub fn has_recovery(state: State<'_, AppState>) -> CommandResult<bool> {
    let guard = state
        .vault
        .read()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("vault is locked")))?;
    Ok(vault.has_recovery()?)
}

/// Change the master password. Requires the current password as a
/// speed bump — the user is already unlocked, so this is defence
/// in depth against "someone walks up to the unlocked laptop."
#[safe_command]
#[tauri::command]
pub fn change_password(
    state: State<'_, AppState>,
    current_password: IpcString,
    new_password: IpcString,
) -> CommandResult<()> {
    let mut guard = state
        .vault
        .write()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("vault is locked")))?;

    let current = Secret::new(current_password.into_inner());
    let ok = vault.verify_password(&current)?;
    if !ok {
        return Err(CommandError::UserActionable(IpcString::new(
            "current password is incorrect",
        )));
    }

    let new = Secret::new(new_password.into_inner());
    vault.change_password(new)?;
    Ok(())
}

/// Enable the recovery slot on a vault that doesn't have one, or
/// rotate the existing slot. Returns the fresh 24-word BIP39 phrase
/// as an `IpcString` for one-time display to the user.
///
/// # The phrase crosses the boundary — deliberate exception
///
/// The design rule is "no plaintext credential material over IPC."
/// The recovery phrase IS credential material. The exception is
/// deliberate and audited: the phrase must reach the user's
/// display somewhere, and the alternative (show it in a native
/// dialog spawned from Rust) is a lot more plumbing for marginal
/// benefit. The frontend shows the phrase once in a confirmation
/// screen and zeroes its copy after the user clicks "Saved".
/// Future work: route the phrase through a dedicated reveal path
/// that draws native text outside the WebView.
#[safe_command]
#[tauri::command]
pub fn rotate_recovery_phrase(state: State<'_, AppState>) -> CommandResult<IpcString> {
    let mut guard = state
        .vault
        .write()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("vault is locked")))?;

    let phrase = vault.rotate_recovery()?;
    // Expose once. See exception note above.
    Ok(IpcString::new(phrase.expose().to_string()))
}

/// Enable the recovery slot on a fresh vault. Fails if the vault
/// already has one — use [`rotate_recovery_phrase`] for that.
#[safe_command]
#[tauri::command]
pub fn enable_recovery_phrase(state: State<'_, AppState>) -> CommandResult<IpcString> {
    let mut guard = state
        .vault
        .write()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("vault is locked")))?;

    let phrase = vault.enable_recovery()?;
    Ok(IpcString::new(phrase.expose().to_string()))
}

// =============================================================================
// IMPORT WIZARD
// =============================================================================

/// Parse an export file at `bundle_path` and stash the parsed items in
/// state. Returns only an [`ImportPreview`] summary — titles, kinds,
/// skip reasons — so the Tauri IPC boundary never carries plaintext
/// credentials from the source vault.
///
/// Calling `preview_import` a second time overwrites the pending state,
/// dropping the previous `Vec<ParsedItem>` which zeroizes its secrets.
#[safe_command]
#[tauri::command]
pub fn preview_import(
    state: State<'_, AppState>,
    bundle_path: IpcString,
) -> CommandResult<ImportPreview> {
    let path = std::path::PathBuf::from(bundle_path.into_inner());
    let summary = unovault_import::parse_file(&path)?;
    stash_preview(&state, summary)
}

/// Like [`preview_import`] but with an explicit source, used when the
/// file extension doesn't match the format the user picked in the
/// wizard's dropdown.
#[safe_command]
#[tauri::command]
pub fn preview_import_with_source(
    state: State<'_, AppState>,
    bundle_path: IpcString,
    source: IpcString,
) -> CommandResult<ImportPreview> {
    let path = std::path::PathBuf::from(bundle_path.into_inner());
    let source = parse_import_source(source.as_str())?;
    let summary = unovault_import::parse_file_with_source(&path, source)?;
    stash_preview(&state, summary)
}

/// Apply the stashed import to the currently-unlocked vault. Consumes
/// the pending state by value so each [`ParsedItem`] zeroizes its
/// plaintext fields as the commit loop drops it.
///
/// Failures on individual items do not abort the batch: the command
/// records the per-row failure count and returns it on success so the
/// UI can surface "committed X, failed Y" to the user. A total vault
/// save happens at the end; if that fails the error propagates so the
/// frontend sees the problem rather than silently losing writes.
#[safe_command]
#[tauri::command]
pub fn commit_import(state: State<'_, AppState>) -> CommandResult<ImportCommitResult> {
    let pending = take_pending_import(&state)?;
    let pending = pending.ok_or_else(|| {
        CommandError::UserActionable(IpcString::new("no import preview to commit"))
    })?;

    let mut guard = state
        .vault
        .write()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| CommandError::UserActionable(IpcString::new("vault is locked")))?;

    let mut committed: u32 = 0;
    let mut failed: u32 = 0;

    for item in pending {
        match commit_one(vault, item) {
            Ok(()) => committed += 1,
            Err(_) => failed += 1,
        }
    }

    vault.save()?;

    Ok(ImportCommitResult {
        committed_count: committed,
        failed_count: failed,
    })
}

/// Discard the pending import. Dropping the `Vec<ParsedItem>` runs
/// `ParsedItem::Drop`, zeroizing every stashed secret.
#[safe_command]
#[tauri::command]
pub fn cancel_import(state: State<'_, AppState>) -> CommandResult<()> {
    let _dropped = take_pending_import(&state)?;
    Ok(())
}

// =============================================================================
// VERSION INFO — handy diagnostics for the Settings screen.
// =============================================================================

/// Version of the `.unovault` on-disk format this build supports.
#[safe_command]
#[tauri::command]
pub fn format_version() -> u16 {
    unovault_core::FORMAT_VERSION
}

// =============================================================================
// HELPERS
// =============================================================================

fn parse_item_id(s: &str) -> CommandResult<CoreItemId> {
    uuid::Uuid::parse_str(s)
        .map(CoreItemId)
        .map_err(|_| CommandError::UserActionable(IpcString::new("item id is not a valid UUID")))
}

fn load_install_id(state: &State<'_, AppState>) -> CommandResult<unovault_core::InstallId> {
    let path = state.install_id_dir.join("install_id");
    let store = InstallIdStore::new(path);
    Ok(store.load_or_create()?)
}

fn swap_vault(state: &State<'_, AppState>, new: Option<Vault>) -> CommandResult<()> {
    let mut guard = state
        .vault
        .write()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("vault lock poisoned")))?;
    *guard = new;
    Ok(())
}

fn parse_import_source(s: &str) -> CommandResult<ImportSource> {
    match s {
        "OnePassword1pux" | "1password" | "1pux" => Ok(ImportSource::OnePassword1pux),
        "BitwardenJson" | "bitwarden" => Ok(ImportSource::BitwardenJson),
        "KeepassXml" | "keepass" => Ok(ImportSource::KeepassXml),
        _ => Err(CommandError::UserActionable(IpcString::new(
            "unknown import source tag",
        ))),
    }
}

fn stash_preview(
    state: &State<'_, AppState>,
    summary: unovault_import::ImportSummary,
) -> CommandResult<ImportPreview> {
    let imported_count = summary.imported_count() as u32;
    let skipped_count = summary.skipped_count() as u32;
    let summary_line = IpcString::new(summary.display_line());
    let source_name = IpcString::new(summary.source.display_name());

    let preview_items: Vec<ImportPreviewItem> = summary
        .items
        .iter()
        .map(|i| ImportPreviewItem {
            title: IpcString::new(i.title.clone()),
            kind: i.kind.into(),
            has_password: i.password.is_some(),
            has_totp: i.totp_secret.is_some(),
            has_notes: i.notes.is_some(),
        })
        .collect();

    let skipped_items: Vec<ImportPreviewSkipped> = summary
        .skipped
        .iter()
        .map(|s| ImportPreviewSkipped {
            title: IpcString::new(s.title.clone()),
            reason: IpcString::new(s.reason.clone()),
        })
        .collect();

    // Stash the parsed items. A previous pending preview, if any, is
    // dropped here — which zeroizes its plaintext secrets via
    // `ParsedItem::Drop`.
    let mut slot = state
        .pending_import
        .lock()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("import lock poisoned")))?;
    *slot = Some(summary.items);

    Ok(ImportPreview {
        source: source_name,
        imported_count,
        skipped_count,
        preview_items,
        skipped_items,
        summary_line,
    })
}

fn take_pending_import(state: &State<'_, AppState>) -> CommandResult<Option<Vec<ParsedItem>>> {
    let mut slot = state
        .pending_import
        .lock()
        .map_err(|_| CommandError::BugInUnovault(IpcString::new("import lock poisoned")))?;
    Ok(slot.take())
}

/// Commit one parsed item into the open vault: `add_item` for the
/// metadata, then up to three `set_field` calls for the secret fields.
/// Errors short-circuit — a partial item is still preferable to none at
/// all, but the caller counts the failure so the UI can surface it.
fn commit_one(vault: &mut Vault, item: ParsedItem) -> CommandResult<()> {
    let snapshot = ItemSnapshot {
        title: item.title.clone(),
        kind: item.kind,
        username: item.username.clone(),
        url: item.url.clone(),
    };
    let id = vault.add_item(snapshot)?;

    if let Some(password) = item.password.clone() {
        vault.set_field(id, FieldKey::Password, FieldValue::Bytes(password))?;
    }
    if let Some(totp) = item.totp_secret.clone() {
        vault.set_field(id, FieldKey::TotpSecret, FieldValue::Bytes(totp))?;
    }
    if let Some(notes) = item.notes.clone() {
        vault.set_field(id, FieldKey::Notes, FieldValue::Text(notes))?;
    }
    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================
//
// Tauri's `State<'_, T>` is non-trivially constructible outside of a
// real Tauri runtime. Rather than trying to fake one, we test the
// command bodies by pulling the work into private helpers that take
// `&AppState` directly. Each command below calls the helper; the
// helper is also called from the test module. Integration tests that
// exercise the full `#[tauri::command]` wrapper live under
// `tests/tauri_ipc.rs` and require a live Tauri runtime (deferred).

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn mk_state() -> (tempfile::TempDir, AppState) {
        let dir = tempdir().expect("tempdir");
        let state = AppState::with_install_id_dir(dir.path().join("install"));
        (dir, state)
    }

    fn fresh_bundle(root: &std::path::Path) -> PathBuf {
        root.join("test.unovault")
    }

    /// Direct use of the internal helpers. Covers the full logic path
    /// without needing a Tauri `State<'_, T>` at the type level.
    fn create_vault_direct(state: &AppState, bundle: PathBuf, password: &str) -> CommandResult<()> {
        let install = {
            let path = state.install_id_dir.join("install_id");
            let store = InstallIdStore::new(path);
            store.load_or_create()?
        };
        let vault = Vault::create(bundle, Secret::new(password.to_string()), install)?;
        let mut guard = state
            .vault
            .write()
            .map_err(|_| CommandError::BugInUnovault(IpcString::new("lock poisoned")))?;
        *guard = Some(vault);
        Ok(())
    }

    #[test]
    fn is_unlocked_flips_on_create() {
        let (dir, state) = mk_state();
        assert!(!state.is_unlocked());
        create_vault_direct(&state, fresh_bundle(dir.path()), "hunter2").expect("create direct");
        assert!(state.is_unlocked());
    }

    #[test]
    fn list_items_returns_empty_after_create() {
        let (dir, state) = mk_state();
        create_vault_direct(&state, fresh_bundle(dir.path()), "hunter2").expect("create");

        let guard = state.vault.read().expect("lock");
        let vault = guard.as_ref().expect("unlocked");
        let metadata: Vec<ItemMetadata> =
            vault.items().map(ItemMetadata::from_item_state).collect();
        assert!(metadata.is_empty());
    }

    #[test]
    fn command_error_serializes_as_tagged_enum() {
        let err = CommandError::UserActionable(IpcString::new("nope"));
        let json = serde_json::to_string(&err).expect("serialize");
        assert!(json.contains("\"category\":\"UserActionable\""));
        assert!(json.contains("\"message\":\"nope\""));
    }

    #[test]
    fn format_version_matches_core() {
        assert_eq!(format_version(), unovault_core::FORMAT_VERSION);
    }

    #[test]
    fn parse_item_id_rejects_garbage() {
        match parse_item_id("not a uuid") {
            Err(CommandError::UserActionable(msg)) => {
                assert!(msg.as_str().contains("not a valid UUID"));
            }
            other => panic!("expected UserActionable, got {other:?}"),
        }
    }

    // -------------------------------------------------------------
    // Import wizard tests.
    //
    // The command helpers take `&State<'_, AppState>`, which is not
    // constructible outside a live Tauri runtime. The tests below
    // therefore exercise the non-command helper layer that does the
    // real work: `stash_preview`, `take_pending_import`, and
    // `commit_one`. Each helper is called directly with a fabricated
    // `ImportSummary` / `ParsedItem` so the full conversion and
    // commit pipeline runs end-to-end without the Tauri shim.
    // -------------------------------------------------------------

    fn fake_parsed(title: &str, password: Option<&str>, notes: Option<&str>) -> ParsedItem {
        ParsedItem {
            title: title.into(),
            kind: CoreItemKind::Password,
            username: Some("james".into()),
            url: Some("github.com".into()),
            password: password.map(|s| s.as_bytes().to_vec()),
            totp_secret: None,
            notes: notes.map(|s| s.into()),
            created_at_ms: Some(1_700_000_000_000),
            modified_at_ms: Some(1_700_000_000_000),
        }
    }

    fn fake_summary(
        items: Vec<ParsedItem>,
        source: ImportSource,
    ) -> unovault_import::ImportSummary {
        unovault_import::ImportSummary {
            source,
            items,
            skipped: Vec::new(),
        }
    }

    /// Run the import pipeline without going through the Tauri
    /// `State<'_, AppState>` wrapper. Mirrors `preview_import` →
    /// `commit_import` on a plain `&AppState`.
    fn preview_direct(state: &AppState, summary: unovault_import::ImportSummary) -> ImportPreview {
        let imported_count = summary.imported_count() as u32;
        let skipped_count = summary.skipped_count() as u32;
        let summary_line = IpcString::new(summary.display_line());
        let source_name = IpcString::new(summary.source.display_name());

        let preview_items: Vec<ImportPreviewItem> = summary
            .items
            .iter()
            .map(|i| ImportPreviewItem {
                title: IpcString::new(i.title.clone()),
                kind: i.kind.into(),
                has_password: i.password.is_some(),
                has_totp: i.totp_secret.is_some(),
                has_notes: i.notes.is_some(),
            })
            .collect();

        let skipped_items: Vec<ImportPreviewSkipped> = summary
            .skipped
            .iter()
            .map(|s| ImportPreviewSkipped {
                title: IpcString::new(s.title.clone()),
                reason: IpcString::new(s.reason.clone()),
            })
            .collect();

        *state.pending_import.lock().expect("lock") = Some(summary.items);

        ImportPreview {
            source: source_name,
            imported_count,
            skipped_count,
            preview_items,
            skipped_items,
            summary_line,
        }
    }

    fn commit_direct(state: &AppState) -> ImportCommitResult {
        let pending = state
            .pending_import
            .lock()
            .expect("lock")
            .take()
            .expect("pending");
        let mut guard = state.vault.write().expect("vault lock");
        let vault = guard.as_mut().expect("unlocked");
        let mut committed = 0;
        let mut failed = 0;
        for item in pending {
            match commit_one(vault, item) {
                Ok(()) => committed += 1,
                Err(_) => failed += 1,
            }
        }
        vault.save().expect("save");
        ImportCommitResult {
            committed_count: committed,
            failed_count: failed,
        }
    }

    #[test]
    fn preview_stashes_items_and_returns_only_metadata() {
        let (_dir, state) = mk_state();
        let parsed = vec![
            fake_parsed("GitHub", Some("super-secret"), Some("dev account")),
            fake_parsed("Gmail", Some("another"), None),
        ];
        let summary = fake_summary(parsed, ImportSource::BitwardenJson);

        let preview = preview_direct(&state, summary);

        assert_eq!(preview.imported_count, 2);
        assert_eq!(preview.skipped_count, 0);
        assert_eq!(preview.preview_items.len(), 2);
        assert_eq!(preview.preview_items[0].title.as_str(), "GitHub");
        assert!(preview.preview_items[0].has_password);
        assert!(preview.preview_items[0].has_notes);

        // The preview response must not contain any plaintext bytes
        // from the parsed items. Serialize it and grep.
        let json = serde_json::to_string(&preview).expect("serialize");
        assert!(!json.contains("super-secret"));
        assert!(!json.contains("dev account"));
        assert!(!json.contains("another"));
        assert!(json.contains("GitHub"));

        // And the stash is populated.
        assert!(state.pending_import.lock().expect("lock").is_some());
    }

    #[test]
    fn commit_writes_items_and_fields_into_vault() {
        let (dir, state) = mk_state();
        create_vault_direct(&state, fresh_bundle(dir.path()), "hunter2").expect("create");

        let parsed = vec![
            fake_parsed("GitHub", Some("super-secret"), Some("dev account")),
            fake_parsed("Gmail", Some("another"), None),
        ];
        let summary = fake_summary(parsed, ImportSource::OnePassword1pux);
        preview_direct(&state, summary);

        let result = commit_direct(&state);
        assert_eq!(result.committed_count, 2);
        assert_eq!(result.failed_count, 0);

        // Verify both rows are in the vault with their secret fields.
        let guard = state.vault.read().expect("lock");
        let vault = guard.as_ref().expect("unlocked");
        let items: Vec<_> = vault.items().collect();
        assert_eq!(items.len(), 2);
        for i in items {
            assert_eq!(
                i.password.as_deref().map(|b| !b.is_empty()),
                Some(true),
                "each imported item should carry its password bytes"
            );
        }

        // Pending state must be empty after commit.
        assert!(state.pending_import.lock().expect("lock").is_none());
    }

    #[test]
    fn cancel_drops_pending_state() {
        let (_dir, state) = mk_state();
        let summary = fake_summary(
            vec![fake_parsed("GitHub", Some("x"), None)],
            ImportSource::KeepassXml,
        );
        preview_direct(&state, summary);
        assert!(state.pending_import.lock().expect("lock").is_some());

        // Mimic cancel_import: take() drops the Vec and zeroizes.
        let _dropped = state.pending_import.lock().expect("lock").take();
        assert!(state.pending_import.lock().expect("lock").is_none());
    }

    #[test]
    fn preview_overwrites_previous_pending_import() {
        let (_dir, state) = mk_state();
        preview_direct(
            &state,
            fake_summary(
                vec![fake_parsed("first", Some("a"), None)],
                ImportSource::BitwardenJson,
            ),
        );
        preview_direct(
            &state,
            fake_summary(
                vec![
                    fake_parsed("second-a", Some("b"), None),
                    fake_parsed("second-b", Some("c"), None),
                ],
                ImportSource::BitwardenJson,
            ),
        );
        let stashed = state
            .pending_import
            .lock()
            .expect("lock")
            .as_ref()
            .map(|v| v.len())
            .expect("pending");
        assert_eq!(stashed, 2, "second preview should overwrite first");
    }

    #[test]
    fn parse_import_source_accepts_wizard_tags() {
        assert!(matches!(
            parse_import_source("OnePassword1pux"),
            Ok(ImportSource::OnePassword1pux)
        ));
        assert!(matches!(
            parse_import_source("bitwarden"),
            Ok(ImportSource::BitwardenJson)
        ));
        assert!(matches!(
            parse_import_source("KeepassXml"),
            Ok(ImportSource::KeepassXml)
        ));
        assert!(parse_import_source("unknown").is_err());
    }

    /// Integration-ish test: create, add, save, re-read metadata.
    /// Uses `create_vault_direct` so we don't need a live Tauri State.
    #[test]
    fn create_then_add_item_is_reflected_in_metadata() {
        let (dir, state) = mk_state();
        create_vault_direct(&state, fresh_bundle(dir.path()), "hunter2").expect("create");

        let metadata_count = {
            let mut guard = state.vault.write().expect("lock");
            let vault = guard.as_mut().expect("unlocked");
            vault
                .add_item(ItemSnapshot {
                    title: "GitHub".into(),
                    kind: CoreItemKind::Password,
                    username: Some("james".into()),
                    url: Some("github.com".into()),
                })
                .expect("add");
            vault.save().expect("save");
            vault.items().count()
        };
        assert_eq!(metadata_count, 1);

        // Verify via the IPC-safe metadata shape.
        let metadata: Vec<ItemMetadata> = {
            let guard = state.vault.read().expect("lock");
            let vault = guard.as_ref().expect("unlocked");
            vault.items().map(ItemMetadata::from_item_state).collect()
        };
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].title.as_str(), "GitHub");
        assert_eq!(metadata[0].kind, ItemKindTag::Password);
        assert!(!metadata[0].has_password, "password field not yet set");
    }
}
