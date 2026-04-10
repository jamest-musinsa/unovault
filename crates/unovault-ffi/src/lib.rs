// Test code in this crate uses `expect` for brevity; production code
// goes through explicit `Result` paths per the workspace panic policy.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! # unovault-ffi
//!
//! The Rust ↔ Swift FFI shim for unovault. Exposes a thin, stable API
//! surface that the Swift side of the app (Tauri sidecar, macOS menu bar
//! helper, or full Cocoa app in later weeks) can call without knowing
//! anything about the internals of `unovault-core`.
//!
//! ## Design goals
//!
//! 1. **Every call is synchronous.** UniFFI async support on Swift 6 has
//!    known `Sendable` constraints; we avoid the issue entirely by keeping
//!    the boundary synchronous. Long work (argon2id unlock) blocks the
//!    caller, which is a Swift concern to schedule off the main thread.
//!
//! 2. **All errors map to `FfiError`**, a flat enum. The 5-category
//!    `VaultError` taxonomy in `unovault-core` is collapsed to a flat
//!    structure at the boundary because UniFFI does not model nested
//!    enums for Swift as ergonomically as a flat enum. Callers pattern-
//!    match on the category tag; the original category is preserved in
//!    the variant name.
//!
//! 3. **No plaintext credentials cross the boundary in `String`/`Vec<u8>`
//!    form yet.** This v0 surface only exposes vault lifecycle and item
//!    metadata. Reveal/copy operations live behind a future callback-
//!    based surface (see `unovault-ffi/src/reveal.rs` once it exists);
//!    for now Swift can list items but cannot read secrets. This keeps
//!    week 5-6 focused on "does the bridge even work" and defers the
//!    hard "native overlay draw" work to week 7-9 UI integration.
//!
//! 4. **Vault instances are held on the Rust side behind a handle.**
//!    UniFFI's `#[derive(Object)]` emits a Swift class whose methods
//!    call through to the Rust struct. Dropping the Swift handle drops
//!    the Rust `Vault`, which zeroizes the derived keys.
//!
//! ## What's intentionally missing in this spike
//!
//! * **No password reveal / copy yet.** The reveal path requires a Swift
//!   callback to draw a native `NSTextField` overlay on top of the
//!   Tauri window. That callback interface lands next week.
//! * **No iCloud `NSMetadataQuery` integration.** Blocked by Apple
//!   Developer entitlement. v0 uses a local directory the caller picks.
//! * **No Secure Enclave wrap.** Blocked by code signing. The fast-path
//!   unlock falls back to recomputing argon2id in this spike.
//! * **No Touch ID (`LAContext`) bridging.** Needs a Swift-side helper
//!   that calls `LAContext.evaluatePolicy` and hands the success back
//!   to Rust. Sketched in `swift/UnovaultFFISwift/Sources/UnovaultFFISwift/TouchID.swift`
//!   as design documentation; real wiring needs entitlements.

use std::path::PathBuf;
use std::sync::Mutex;

use unovault_core::event::{FieldKey, FieldValue, ItemKind, ItemSnapshot};
use unovault_core::install_id::{InstallId, InstallIdStore};
use unovault_core::secret::Secret;
use unovault_core::vault::Vault as CoreVault;
use unovault_core::{ItemId as CoreItemId, VaultError};

uniffi::setup_scaffolding!();

// =============================================================================
// ERROR TYPE
// =============================================================================

/// Flat error enum exposed to Swift. The 5-category `VaultError` taxonomy
/// collapses to this shape because UniFFI renders nested enums less
/// ergonomically in Swift than a flat category-tagged enum.
///
/// Swift code should pattern-match on the variant and show the
/// category-appropriate headline from its own copy tables — the `message`
/// field is log text, not UI copy.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// Something the user can fix by retrying with different input.
    #[error("user-actionable: {message}")]
    UserActionable { message: String },

    /// Temporary environmental failure. Retry later.
    #[error("network-transient: {message}")]
    NetworkTransient { message: String },

    /// Device hardware state prevents the operation.
    #[error("hardware-issue: {message}")]
    HardwareIssue { message: String },

    /// A bug inside unovault. The user should see "copy diagnostics".
    #[error("bug-in-unovault: {message}")]
    BugInUnovault { message: String },

    /// The OS sandbox or permission system refused the operation.
    #[error("platform-policy: {message}")]
    PlatformPolicy { message: String },
}

impl From<VaultError> for FfiError {
    fn from(err: VaultError) -> Self {
        let message = err.to_string();
        match err {
            VaultError::UserActionable(_) => Self::UserActionable { message },
            VaultError::NetworkTransient(_) => Self::NetworkTransient { message },
            VaultError::HardwareIssue(_) => Self::HardwareIssue { message },
            VaultError::BugInUnovault(_) => Self::BugInUnovault { message },
            VaultError::PlatformPolicy(_) => Self::PlatformPolicy { message },
        }
    }
}

type FfiResult<T> = Result<T, FfiError>;

// =============================================================================
// VALUE TYPES (records exposed to Swift)
// =============================================================================

/// Kind of a vault item. Mirrors `unovault_core::event::ItemKind` but as
/// a UniFFI-compatible enum (no `#[non_exhaustive]`; UniFFI needs full
/// enumeration at binding time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiItemKind {
    Password,
    Passkey,
    Totp,
    SshKey,
    ApiToken,
    SecureNote,
}

impl From<FfiItemKind> for ItemKind {
    fn from(k: FfiItemKind) -> Self {
        match k {
            FfiItemKind::Password => ItemKind::Password,
            FfiItemKind::Passkey => ItemKind::Passkey,
            FfiItemKind::Totp => ItemKind::Totp,
            FfiItemKind::SshKey => ItemKind::SshKey,
            FfiItemKind::ApiToken => ItemKind::ApiToken,
            FfiItemKind::SecureNote => ItemKind::SecureNote,
        }
    }
}

impl From<ItemKind> for FfiItemKind {
    fn from(k: ItemKind) -> Self {
        match k {
            ItemKind::Password => FfiItemKind::Password,
            ItemKind::Passkey => FfiItemKind::Passkey,
            ItemKind::Totp => FfiItemKind::Totp,
            ItemKind::SshKey => FfiItemKind::SshKey,
            ItemKind::ApiToken => FfiItemKind::ApiToken,
            ItemKind::SecureNote => FfiItemKind::SecureNote,
            // The core enum is `#[non_exhaustive]` — fall through for any
            // future variant we don't yet know about. Mapping to Password
            // is the least-surprising default until the FFI is updated.
            _ => FfiItemKind::Password,
        }
    }
}

/// Item summary exposed to Swift. No secret material — callers use a
/// separate (future) API to request copy/reveal for a specific field.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiItemSummary {
    /// Stable item identifier as a hyphenated UUID string. Swift keeps
    /// this opaque and passes it back to Rust for further operations.
    pub id: String,
    pub title: String,
    pub kind: FfiItemKind,
    pub username: Option<String>,
    pub url: Option<String>,
    pub has_password: bool,
    pub has_totp: bool,
    pub created_at_ms: u64,
    pub modified_at_ms: u64,
}

// =============================================================================
// VAULT OBJECT
// =============================================================================

/// Swift-visible vault handle. Wraps a `CoreVault` behind a mutex so Swift
/// can hold the object across multiple method calls. The mutex also makes
/// the object `Sync + Send`, which UniFFI requires for objects that are
/// passed around on the Swift side.
///
/// `Debug` is implemented manually so test-code that formats
/// `Result<Arc<FfiVault>, _>` compiles without exposing internal state.
#[derive(uniffi::Object)]
pub struct FfiVault {
    inner: Mutex<CoreVault>,
}

impl std::fmt::Debug for FfiVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiVault")
            .field("inner", &"<locked>")
            .finish()
    }
}

#[uniffi::export]
impl FfiVault {
    /// Create a brand-new vault at `bundle_path` with the given master
    /// password. Returns a handle the caller uses for subsequent ops.
    ///
    /// `install_id_dir` is the directory where the v0 install-id store
    /// persists its UUID (one file inside the directory). Swift should
    /// pass `~/Library/Application Support/unovault` or similar.
    #[uniffi::constructor]
    pub fn create(
        bundle_path: String,
        password: String,
        install_id_dir: String,
    ) -> FfiResult<std::sync::Arc<Self>> {
        let install = load_or_create_install_id(&install_id_dir)?;
        let vault = CoreVault::create(PathBuf::from(bundle_path), Secret::new(password), install)?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(vault),
        }))
    }

    /// Unlock an existing vault. Slow — argon2id derivation is the
    /// dominating cost, typically 500ms–1.5s depending on hardware.
    /// Swift must call this off the main thread to avoid beachballing.
    #[uniffi::constructor]
    pub fn unlock(
        bundle_path: String,
        password: String,
        install_id_dir: String,
    ) -> FfiResult<std::sync::Arc<Self>> {
        let install = load_or_create_install_id(&install_id_dir)?;
        let vault = CoreVault::unlock(PathBuf::from(bundle_path), Secret::new(password), install)?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(vault),
        }))
    }

    /// Add a new item to the vault. Returns the new item's ID as a string.
    ///
    /// The vault is mutated in memory immediately; call `save()` to flush
    /// the pending event queue to a chunk file on disk.
    pub fn add_item(
        &self,
        title: String,
        kind: FfiItemKind,
        username: Option<String>,
        url: Option<String>,
    ) -> FfiResult<String> {
        let snapshot = ItemSnapshot {
            title,
            kind: kind.into(),
            username,
            url,
        };
        let mut vault = self.lock_inner()?;
        let id = vault.add_item(snapshot)?;
        Ok(id.0.hyphenated().to_string())
    }

    /// Set the password field on an existing item.
    ///
    /// NOTE: plaintext crosses the FFI boundary as a String. That is
    /// acceptable from the Swift host process (UniFFI is in-process, not
    /// remote) but it IS a departure from the WebView-side rule that
    /// says "UI never sees plaintext." The Swift layer between UniFFI
    /// and the WebView must never forward this string into JavaScript.
    /// A future iteration will replace this with a callback-based
    /// "input password" flow that obtains the plaintext from a native
    /// overlay and drops it immediately.
    pub fn set_password(&self, item_id: String, password: String) -> FfiResult<bool> {
        let item_id = parse_item_id(&item_id)?;
        let mut vault = self.lock_inner()?;
        Ok(vault.set_field(
            item_id,
            FieldKey::Password,
            FieldValue::Bytes(password.into_bytes()),
        )?)
    }

    /// Set the notes field. Notes are not considered secret material but
    /// the API still goes through the same event log to keep the LWW
    /// merge path consistent.
    pub fn set_notes(&self, item_id: String, notes: String) -> FfiResult<bool> {
        let item_id = parse_item_id(&item_id)?;
        let mut vault = self.lock_inner()?;
        Ok(vault.set_field(item_id, FieldKey::Notes, FieldValue::Text(notes))?)
    }

    /// Flush the pending event queue to a chunk file. No-op if empty.
    pub fn save(&self) -> FfiResult<()> {
        let mut vault = self.lock_inner()?;
        Ok(vault.save()?)
    }

    /// Number of items currently in the vault.
    pub fn item_count(&self) -> FfiResult<u64> {
        let vault = self.lock_inner()?;
        Ok(vault.len() as u64)
    }

    /// List every item as a metadata-only summary. No secret material
    /// is returned — `has_password` / `has_totp` are booleans, not the
    /// actual values.
    pub fn list_items(&self) -> FfiResult<Vec<FfiItemSummary>> {
        let vault = self.lock_inner()?;
        let summaries = vault
            .items()
            .map(|item| FfiItemSummary {
                id: item.id.0.hyphenated().to_string(),
                title: item.title.clone(),
                kind: item.kind.into(),
                username: item.username.clone(),
                url: item.url.clone(),
                has_password: item.password.is_some(),
                has_totp: item.totp_secret.is_some(),
                created_at_ms: item.created_at_ms,
                modified_at_ms: item.modified_at_ms,
            })
            .collect();
        Ok(summaries)
    }

    /// Path of the vault bundle on disk. Useful for UI status bars.
    pub fn bundle_path(&self) -> FfiResult<String> {
        let vault = self.lock_inner()?;
        Ok(vault.bundle_path().to_string_lossy().into_owned())
    }

    /// Install identifier in hyphenated UUID form. Matches the chunk
    /// filename suffix written by this vault handle.
    pub fn install_id(&self) -> FfiResult<String> {
        let vault = self.lock_inner()?;
        Ok(vault.install().as_uuid().hyphenated().to_string())
    }
}

impl FfiVault {
    fn lock_inner(&self) -> FfiResult<std::sync::MutexGuard<'_, CoreVault>> {
        self.inner.lock().map_err(|_| FfiError::BugInUnovault {
            message: "vault mutex poisoned by a previous panic".into(),
        })
    }
}

// =============================================================================
// PRIVATE HELPERS
// =============================================================================

fn parse_item_id(s: &str) -> FfiResult<CoreItemId> {
    uuid::Uuid::parse_str(s)
        .map(CoreItemId)
        .map_err(|_| FfiError::UserActionable {
            message: format!("item id {s:?} is not a valid UUID"),
        })
}

fn load_or_create_install_id(dir: &str) -> FfiResult<InstallId> {
    let path = PathBuf::from(dir).join("install_id");
    let store = InstallIdStore::new(path);
    Ok(store.load_or_create()?)
}

// =============================================================================
// UNIFFI-VISIBLE FREE FUNCTIONS
// =============================================================================

/// Semantic version of the `unovault-ffi` crate. Exposed so Swift can log
/// the bridge version separately from the app version.
#[uniffi::export]
pub fn ffi_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Semantic version of the `.unovault` on-disk format this bridge speaks.
/// Swift UI should display this in a diagnostics view.
#[uniffi::export]
pub fn format_version() -> u16 {
    unovault_core::FORMAT_VERSION
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_paths() -> (tempfile::TempDir, String, String) {
        let dir = tempdir().expect("tempdir");
        let bundle = dir
            .path()
            .join("test.unovault")
            .to_string_lossy()
            .into_owned();
        let install_dir = dir.path().join("install").to_string_lossy().into_owned();
        (dir, bundle, install_dir)
    }

    #[test]
    fn create_vault_and_list_items_roundtrip() {
        let (_guard, bundle, install_dir) = fresh_paths();
        let vault = FfiVault::create(bundle.clone(), "hunter2".into(), install_dir.clone())
            .expect("create");

        assert_eq!(vault.item_count().expect("count"), 0);

        let id = vault
            .add_item(
                "GitHub".into(),
                FfiItemKind::Password,
                Some("james".into()),
                Some("github.com".into()),
            )
            .expect("add");

        // The ID is a parseable UUID string.
        uuid::Uuid::parse_str(&id).expect("id is a uuid");

        vault
            .set_password(id.clone(), "correct horse battery staple".into())
            .expect("set password");

        assert_eq!(vault.item_count().expect("count"), 1);
        let summaries = vault.list_items().expect("list");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].title, "GitHub");
        assert_eq!(summaries[0].kind, FfiItemKind::Password);
        assert_eq!(summaries[0].username.as_deref(), Some("james"));
        assert!(summaries[0].has_password, "password field should be set");
        assert!(!summaries[0].has_totp);
    }

    #[test]
    fn save_and_reopen_via_ffi() {
        let (_guard, bundle, install_dir) = fresh_paths();

        let id = {
            let vault = FfiVault::create(bundle.clone(), "hunter2".into(), install_dir.clone())
                .expect("create");
            let id = vault
                .add_item(
                    "Linear".into(),
                    FfiItemKind::Passkey,
                    Some("james@personal".into()),
                    Some("linear.app".into()),
                )
                .expect("add");
            vault.save().expect("save");
            id
        };
        // vault drops, keys zeroize

        let reopened = FfiVault::unlock(bundle, "hunter2".into(), install_dir).expect("unlock");
        assert_eq!(reopened.item_count().expect("count"), 1);

        let summaries = reopened.list_items().expect("list");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].id, id);
        assert_eq!(summaries[0].title, "Linear");
        assert_eq!(summaries[0].kind, FfiItemKind::Passkey);
    }

    #[test]
    fn wrong_password_returns_user_actionable_error() {
        let (_guard, bundle, install_dir) = fresh_paths();
        {
            let vault = FfiVault::create(bundle.clone(), "correct".into(), install_dir.clone())
                .expect("create");
            vault
                .add_item("x".into(), FfiItemKind::Password, None, None)
                .expect("add");
            vault.save().expect("save");
        }

        match FfiVault::unlock(bundle, "wrong".into(), install_dir) {
            Err(FfiError::UserActionable { .. }) => {}
            other => panic!("expected UserActionable, got {other:?}"),
        }
    }

    #[test]
    fn parse_item_id_rejects_garbage() {
        match parse_item_id("not a uuid") {
            Err(FfiError::UserActionable { message }) => {
                assert!(message.contains("not a uuid"));
            }
            other => panic!("expected UserActionable, got {other:?}"),
        }
    }

    #[test]
    fn ffi_version_matches_crate_version() {
        assert_eq!(ffi_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn format_version_matches_core() {
        assert_eq!(format_version(), unovault_core::FORMAT_VERSION);
    }
}
