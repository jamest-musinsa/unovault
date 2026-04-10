//! Install identifier — a stable per-install UUID that shards the chunk
//! namespace so two devices writing to the same iCloud vault never collide
//! on filenames.
//!
//! # Storage
//!
//! In the shipped product, the install ID lives in the macOS Keychain so it
//! survives uninstall+reinstall only if the user explicitly keeps the
//! Keychain entry, and is preserved across Time Machine restores. That
//! integration lands in week 5-6 alongside the Swift bridge work.
//!
//! **This module is the v0 fallback**: a plain file on disk under
//! `~/.local/state/unovault/install_id` (or its macOS equivalent). It lets
//! `unovault-core` be built, tested, and dogfooded before the Swift bridge
//! exists. The file-based implementation is:
//!
//! * `InstallIdStore::load_or_create(path)` — reads the file if present,
//!   otherwise generates a fresh UUID, writes it, and returns it.
//! * Atomic write via temp file + rename, so a crash mid-write cannot
//!   produce a corrupt ID file.
//! * No locking. Two concurrent calls to `load_or_create` on the same path
//!   may race and produce different IDs; only one will be persisted. For
//!   v0 this is acceptable because the vault engine is single-process.
//!
//! Once `unovault-biometric` exposes the Keychain API, `InstallIdStore`
//! gains a second impl (or the trait goes polymorphic) and the file path
//! becomes a test-only backdoor.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{BugInUnovaultError, PlatformPolicyError, UserActionableError, VaultError};

/// Sharding identifier stored in chunk filenames as
/// `NNNNNNNN-<install_id>.chunk`. Not a secret, has no crypto role —
/// its only purpose is ensuring two devices writing to the same iCloud
/// directory cannot create colliding filenames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InstallId(pub Uuid);

impl InstallId {
    /// Generate a fresh install ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Short display form for UI status bars (`mbp-xxxxxxxx`). The UI is
    /// free to replace the `mbp` prefix with a user-chosen device name in a
    /// future iteration.
    pub fn display_short(&self) -> String {
        let hex = self.0.simple().to_string();
        format!("mbp-{}", &hex[..8.min(hex.len())])
    }

    /// Raw UUID access for chunk filename construction and serialization.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for InstallId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for InstallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// File-based install ID store. This is the v0 implementation; a Keychain
/// backend will replace it in week 5-6 when the Swift bridge lands.
#[derive(Debug)]
pub struct InstallIdStore {
    path: PathBuf,
}

impl InstallIdStore {
    /// Create a store that reads/writes the install ID at `path`.
    ///
    /// The path does not need to exist yet; it will be created on first
    /// `load_or_create` call. The parent directory will be created
    /// recursively if missing.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Load the install ID from disk. If the file does not exist, generate
    /// a fresh ID and persist it. Subsequent calls return the same ID.
    pub fn load_or_create(&self) -> Result<InstallId, VaultError> {
        match self.load() {
            Ok(id) => Ok(id),
            Err(VaultError::UserActionable(UserActionableError::VaultNotFound)) => {
                let fresh = InstallId::new();
                self.persist(&fresh)?;
                Ok(fresh)
            }
            Err(other) => Err(other),
        }
    }

    /// Load an existing install ID or return `VaultNotFound` if the file
    /// does not exist. Other IO failures become `PlatformPolicy::SandboxDenied`
    /// because the most likely cause is permissions.
    fn load(&self) -> Result<InstallId, VaultError> {
        let contents = match fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(UserActionableError::VaultNotFound.into());
            }
            Err(_) => {
                return Err(PlatformPolicyError::SandboxDenied.into());
            }
        };

        let trimmed = contents.trim();
        let uuid = Uuid::parse_str(trimmed).map_err(|_| {
            BugInUnovaultError::InvariantViolation("install_id file contents are not a valid UUID")
        })?;
        Ok(InstallId(uuid))
    }

    /// Atomic write: temp file + rename. Avoids leaving a corrupt ID file
    /// on a mid-write crash.
    fn persist(&self, id: &InstallId) -> Result<(), VaultError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|_| PlatformPolicyError::SandboxDenied)?;
        }

        let tmp_path = self.path.with_extension("tmp");
        {
            let mut f =
                fs::File::create(&tmp_path).map_err(|_| PlatformPolicyError::SandboxDenied)?;
            f.write_all(id.0.hyphenated().to_string().as_bytes())
                .map_err(|_| PlatformPolicyError::SandboxDenied)?;
            f.sync_all()
                .map_err(|_| PlatformPolicyError::SandboxDenied)?;
        }

        fs::rename(&tmp_path, &self.path).map_err(|_| PlatformPolicyError::SandboxDenied)?;

        Ok(())
    }

    /// Return the path this store reads from. Useful for test assertions
    /// and diagnostics.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn new_generates_unique_install_ids() {
        let a = InstallId::new();
        let b = InstallId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn display_short_starts_with_prefix() {
        let id = InstallId::new();
        let s = id.display_short();
        assert!(s.starts_with("mbp-"));
        assert_eq!(s.len(), 12); // "mbp-" + 8 hex chars
    }

    #[test]
    fn load_or_create_generates_on_first_call() {
        let dir = tempdir().expect("tempdir");
        let store = InstallIdStore::new(dir.path().join("install_id"));
        let id = store.load_or_create().expect("first load_or_create");
        assert!(store.path().exists(), "file should exist after first call");
        // Sanity: file contents parse back to the same UUID.
        let reloaded = store.load_or_create().expect("second load_or_create");
        assert_eq!(id, reloaded);
    }

    #[test]
    fn load_or_create_is_stable_across_calls() {
        let dir = tempdir().expect("tempdir");
        let store = InstallIdStore::new(dir.path().join("install_id"));
        let a = store.load_or_create().expect("a");
        let b = store.load_or_create().expect("b");
        let c = store.load_or_create().expect("c");
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn two_different_stores_produce_different_ids() {
        let dir = tempdir().expect("tempdir");
        let store_a = InstallIdStore::new(dir.path().join("a"));
        let store_b = InstallIdStore::new(dir.path().join("b"));
        let id_a = store_a.load_or_create().expect("a");
        let id_b = store_b.load_or_create().expect("b");
        assert_ne!(
            id_a, id_b,
            "distinct store paths should generate distinct IDs"
        );
    }

    #[test]
    fn load_or_create_creates_parent_directories() {
        let dir = tempdir().expect("tempdir");
        let nested = dir.path().join("deeply/nested/dir/install_id");
        let store = InstallIdStore::new(&nested);
        let _ = store.load_or_create().expect("nested load_or_create");
        assert!(nested.exists());
    }

    #[test]
    fn corrupt_install_id_file_returns_invariant_violation() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("install_id");
        fs::write(&path, "this is not a uuid").expect("write corrupt file");
        let store = InstallIdStore::new(&path);
        match store.load_or_create() {
            Err(VaultError::BugInUnovault(BugInUnovaultError::InvariantViolation(_))) => {}
            other => panic!("expected InvariantViolation, got {other:?}"),
        }
    }

    #[test]
    fn persisted_file_is_parseable_hyphenated_uuid() {
        let dir = tempdir().expect("tempdir");
        let store = InstallIdStore::new(dir.path().join("install_id"));
        store.load_or_create().expect("create");
        let contents = fs::read_to_string(store.path()).expect("read");
        // Hyphenated UUIDs are 36 characters.
        assert_eq!(contents.trim().len(), 36);
        assert!(Uuid::parse_str(contents.trim()).is_ok());
    }
}
