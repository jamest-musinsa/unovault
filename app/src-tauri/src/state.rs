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
use std::sync::RwLock;
use unovault_core::vault::Vault;

/// The one thing every Tauri command reaches for: a shared handle to
/// the current vault plus the paths the backend needs to persist
/// auxiliary state.
pub struct AppState {
    pub vault: RwLock<Option<Vault>>,
    pub install_id_dir: PathBuf,
}

impl AppState {
    /// Build fresh app state with no vault loaded. The install-id
    /// directory defaults to the platform's data directory; tests
    /// override it via [`AppState::with_install_id_dir`].
    pub fn new() -> Self {
        let install_id_dir = default_install_id_dir();
        Self {
            vault: RwLock::new(None),
            install_id_dir,
        }
    }

    /// Build app state with an explicit install-id directory. Used
    /// by unit tests that want to point every install-id read and
    /// write at a tempdir.
    pub fn with_install_id_dir(install_id_dir: PathBuf) -> Self {
        Self {
            vault: RwLock::new(None),
            install_id_dir,
        }
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
