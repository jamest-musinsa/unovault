//! Shared mutable state held by the Tauri runtime.
//!
//! Tauri injects a `State<T>` into every command handler. We use a
//! single state type, [`AppState`], that owns:
//!
//! * The optional live `Vault` — `None` when locked, `Some` when
//!   unlocked. Swapping between the two happens through
//!   `create_vault`, `unlock_vault`, and `lock_vault` commands.
//! * The install-ID directory path, resolved once at startup from
//!   the user's data directory.
//!
//! The vault sits behind an `RwLock` because reads (list items,
//! lookup by id) are much more frequent than writes (add, set_field,
//! save) and multiple frontend requests can overlap during a single
//! render pass.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use unovault_core::vault::Vault;
use unovault_import::ParsedItem;

/// The one thing every Tauri command reaches for: a shared handle to
/// the current vault plus the paths the backend needs to persist
/// auxiliary state.
///
/// # Cross-thread access
///
/// `vault` lives behind `Arc<RwLock<_>>` so two unrelated owners can
/// share it: the Tauri command handlers (via `State<'_, AppState>`)
/// and the bridge socket thread spawned from `lib.rs::run()`. The
/// `Arc` is cloned once at startup; all subsequent callers deref
/// through it transparently.
///
/// [`AppState::pending_import`] holds the parsed items from the most
/// recent `preview_import` call. Keeping them here means the plaintext
/// secrets never cross the IPC boundary — the frontend gets counts and
/// titles in the preview response, and `commit_import` consumes the
/// stashed items by value so a committed or cancelled import zeroizes
/// through [`ParsedItem::Drop`].
pub struct AppState {
    pub vault: Arc<RwLock<Option<Vault>>>,
    pub pending_import: Mutex<Option<Vec<ParsedItem>>>,
    pub install_id_dir: PathBuf,
}

impl AppState {
    /// Build fresh app state with no vault loaded. The install-id
    /// directory defaults to the platform's data directory; tests
    /// override it via [`AppState::with_install_id_dir`].
    pub fn new() -> Self {
        let install_id_dir = default_install_id_dir();
        Self {
            vault: Arc::new(RwLock::new(None)),
            pending_import: Mutex::new(None),
            install_id_dir,
        }
    }

    /// Build app state with an explicit install-id directory. Used
    /// by unit tests that want to point every install-id read and
    /// write at a tempdir.
    pub fn with_install_id_dir(install_id_dir: PathBuf) -> Self {
        Self {
            vault: Arc::new(RwLock::new(None)),
            pending_import: Mutex::new(None),
            install_id_dir,
        }
    }

    /// Clone the vault handle for a thread that needs independent
    /// ownership of the `Arc`. Used by the bridge socket server in
    /// [`crate::bridge`].
    pub fn vault_handle(&self) -> Arc<RwLock<Option<Vault>>> {
        Arc::clone(&self.vault)
    }

    /// Whether a vault is currently unlocked in this state.
    pub fn is_unlocked(&self) -> bool {
        self.vault.read().map(|v| v.is_some()).unwrap_or(false)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve the platform-specific default path where the install-id
/// file is stored. Falls back to the temp directory when `dirs` cannot
/// determine a data directory, which should never happen on macOS but
/// prevents the command path from panicking in edge environments.
fn default_install_id_dir() -> PathBuf {
    dirs::data_dir()
        .map(|d| d.join("unovault"))
        .unwrap_or_else(std::env::temp_dir)
}
