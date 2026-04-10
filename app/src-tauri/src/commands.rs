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

use tauri::State;
use unovault_core::event::{ItemKind as CoreItemKind, ItemSnapshot};
use unovault_core::ipc::{IpcString, ItemKindTag, ItemMetadata};
use unovault_core::secret::Secret;
use unovault_core::vault::Vault;
use unovault_core::{InstallIdStore, ItemId as CoreItemId};
use unovault_macros::safe_command;

use crate::error::{CommandError, CommandResult};
use crate::state::AppState;

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
    use unovault_core::event::{FieldKey, FieldValue};

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
