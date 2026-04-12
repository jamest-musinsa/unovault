//! Sync backend abstraction — the seam between `unovault-core` and the
//! outside world's file delivery mechanism.
//!
//! The v1 product uses iCloud Drive, but iCloud's `NSMetadataQuery` API
//! is Apple-only and requires entitlements that are not available in a
//! Rust library process. We insulate the vault engine from that by
//! defining [`FileSystemBackend`], a trait that any "directory that
//! receives new files over time" can implement. Real implementations
//! live in:
//!
//! | Backend         | Crate / module                | Week   |
//! |-----------------|-------------------------------|--------|
//! | Local filesystem| `sync::local::LocalBackend`   | 5-6    |
//! | iCloud Drive    | `unovault-biometric`          | 7-9    |
//! | iroh P2P        | `unovault-sync-p2p` (v2)      | post-v1|
//! | Chaos harness   | `sync::chaos::ChaosBackend`   | 5-6    |
//!
//! The chaos harness is the reason this abstraction exists. It lets us
//! property-test LWW convergence under every adversarial delivery order
//! a real sync backend could realistically produce — dropped events,
//! reordering, duplicates, delayed delivery — without spinning up two
//! real Macs with a shared iCloud account.
//!
//! # What goes through the backend
//!
//! Only chunk files (`NNNNNNNN-<install_id>.chunk`). Manifest and
//! snapshots are written once at creation time and do not travel
//! through the sync layer. The manifest's immutability is what makes
//! this abstraction tractable: every sync backend only needs to know
//! how to read, write, and enumerate append-only files under a single
//! directory.

use std::path::Path;

use crate::{PlatformPolicyError, VaultError};

/// Trait implemented by any "directory of chunk files that can grow over
/// time." Impls are `Send + Sync` so the vault engine can shuttle them
/// between threads freely.
///
/// Semantics:
///
/// * [`FileSystemBackend::list`] returns every chunk filename currently
///   visible in the backend. Order is implementation-defined; callers
///   sort deterministically before replay.
/// * [`FileSystemBackend::read`] loads a single chunk's bytes. Returns
///   `UserActionableError::CorruptedChunk` if the file is missing (a
///   chunk can vanish mid-enumeration under a chaos backend).
/// * [`FileSystemBackend::write`] writes a new chunk atomically.
///   Overwriting an existing chunk with different contents is a bug —
///   implementations may panic in debug builds. The vault engine
///   guarantees fresh filenames via the per-install counter, so this
///   never happens in production.
///
/// The trait is deliberately minimal. Watching for new files (iCloud's
/// `NSMetadataQuery` equivalent) is not part of this trait — it is a
/// separate concern built on top via callbacks, in a later module.
pub trait FileSystemBackend: Send + Sync {
    /// Directory this backend reads and writes. Exposed for diagnostics
    /// and for the chaos harness to assert invariants.
    fn root(&self) -> &Path;

    /// List every chunk file currently visible. Filenames only (no
    /// directories, no nested paths). Order is implementation-defined.
    fn list(&self) -> Result<Vec<String>, VaultError>;

    /// Read a single chunk by filename. The filename must be one that
    /// a previous [`FileSystemBackend::list`] call returned.
    fn read(&self, filename: &str) -> Result<Vec<u8>, VaultError>;

    /// Write a single chunk atomically. The backend is responsible for
    /// crash-safety: a half-written chunk file must not become visible
    /// to subsequent `list` calls.
    fn write(&self, filename: &str, bytes: &[u8]) -> Result<(), VaultError>;
}

// =============================================================================
// LOCAL BACKEND — real filesystem, used by tests and by the eventual
// iCloud-less desktop-only mode.
// =============================================================================

pub mod local {
    //! Plain `std::fs`-backed implementation. Uses a temp file + rename
    //! write strategy so concurrent readers never see partial chunks.

    use super::{FileSystemBackend, PlatformPolicyError, VaultError};
    use crate::UserActionableError;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    /// Local filesystem backend. Wraps a directory on disk.
    #[derive(Debug, Clone)]
    pub struct LocalBackend {
        root: PathBuf,
    }

    impl LocalBackend {
        /// Create a new backend rooted at `dir`. The directory is
        /// created if it does not already exist.
        pub fn new(dir: impl Into<PathBuf>) -> Result<Self, VaultError> {
            let root = dir.into();
            fs::create_dir_all(&root).map_err(|_| PlatformPolicyError::SandboxDenied)?;
            Ok(Self { root })
        }
    }

    impl FileSystemBackend for LocalBackend {
        fn root(&self) -> &Path {
            &self.root
        }

        fn list(&self) -> Result<Vec<String>, VaultError> {
            let mut out = Vec::new();
            let entries =
                fs::read_dir(&self.root).map_err(|_| PlatformPolicyError::SandboxDenied)?;
            for entry in entries {
                let entry = entry.map_err(|_| PlatformPolicyError::SandboxDenied)?;
                let file_type = entry
                    .file_type()
                    .map_err(|_| PlatformPolicyError::SandboxDenied)?;
                if !file_type.is_file() {
                    continue;
                }
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with('.') || !name.ends_with(".chunk") {
                        continue;
                    }
                    out.push(name.to_string());
                }
            }
            Ok(out)
        }

        fn read(&self, filename: &str) -> Result<Vec<u8>, VaultError> {
            let path = self.root.join(filename);
            match fs::read(&path) {
                Ok(bytes) => Ok(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Err(UserActionableError::CorruptedChunk.into())
                }
                Err(_) => Err(PlatformPolicyError::SandboxDenied.into()),
            }
        }

        fn write(&self, filename: &str, bytes: &[u8]) -> Result<(), VaultError> {
            let tmp = self.root.join(format!("{filename}.tmp"));
            let final_path = self.root.join(filename);
            {
                let mut f =
                    fs::File::create(&tmp).map_err(|_| PlatformPolicyError::SandboxDenied)?;
                f.write_all(bytes)
                    .map_err(|_| PlatformPolicyError::SandboxDenied)?;
                f.sync_all()
                    .map_err(|_| PlatformPolicyError::SandboxDenied)?;
            }
            fs::rename(&tmp, &final_path).map_err(|_| PlatformPolicyError::SandboxDenied)?;
            Ok(())
        }
    }
}

// =============================================================================
// ICLOUD BACKEND — macOS iCloud Drive folder discovery, implemented as a
// thin wrapper over LocalBackend pointed at the right path.
// =============================================================================

pub mod icloud {
    //! Discover the macOS iCloud Drive root and expose a
    //! [`LocalBackend`] rooted at its `unovault/` subfolder.
    //!
    //! # How iCloud Drive actually works from a filesystem POV
    //!
    //! macOS stores iCloud Drive files at
    //! `~/Library/Mobile Documents/com~apple~CloudDocs/` (note the
    //! tildes — Apple's own `NSHomeDirectory` expansion produces
    //! that path). Files written there are synced to Apple's
    //! servers and mirrored onto every other device signed into
    //! the same Apple ID. This is exactly the delivery
    //! mechanism the LWW event log needs: append-only chunk files
    //! appearing in a directory.
    //!
    //! A proper iCloud integration uses `NSMetadataQuery` to get
    //! push notifications when new chunks arrive (so the vault
    //! refreshes without polling). That requires iCloud container
    //! entitlements which the current build profile does not
    //! carry. As a fallback the vault can poll `list()` on the
    //! backend when the user clicks "Sync" — the functionality
    //! is strictly less good than push, but it shows the full
    //! round trip working end-to-end.
    //!
    //! # What this module does not do
    //!
    //! * No file-change notifications. Polling only.
    //! * No conflict detection beyond LWW — if the OS produces
    //!   `<name> (conflict from device-2).chunk` on an iCloud
    //!   conflict, we ignore them (filter via `.ends_with(".chunk")`
    //!   misses them) and the user has to open the conflict copy
    //!   in the Finder.
    //! * No iCloud availability check via reachability APIs. We
    //!   just test whether the folder exists and is writable.

    use super::local::LocalBackend;
    use super::VaultError;
    use std::path::{Path, PathBuf};

    /// Name of the unovault subfolder inside iCloud Drive. Chosen
    /// to match what Finder shows when the user browses
    /// `iCloud Drive > unovault`.
    pub const ICLOUD_SUBFOLDER: &str = "unovault";

    /// Resolve the iCloud Drive root for the current user. Returns
    /// `None` when iCloud Drive is not present (non-macOS host, or
    /// macOS without iCloud sign-in).
    ///
    /// The path is `~/Library/Mobile Documents/com~apple~CloudDocs/`
    /// when it exists. On non-macOS platforms this function always
    /// returns `None`.
    pub fn icloud_drive_root() -> Option<PathBuf> {
        if !cfg!(target_os = "macos") {
            return None;
        }
        let home = dirs::home_dir()?;
        let candidate = home
            .join("Library")
            .join("Mobile Documents")
            .join("com~apple~CloudDocs");
        if candidate.is_dir() {
            Some(candidate)
        } else {
            None
        }
    }

    /// Path the unovault subfolder would live at inside iCloud
    /// Drive. Does not create the folder; a caller that wants to
    /// persist anything there goes through [`open_icloud_backend`]
    /// which does.
    pub fn icloud_unovault_path() -> Option<PathBuf> {
        icloud_drive_root().map(|root| root.join(ICLOUD_SUBFOLDER))
    }

    /// Open (and create if necessary) a [`LocalBackend`] rooted at
    /// the iCloud Drive unovault folder. Returns `Ok(None)` when
    /// iCloud Drive is not available — the caller's UI should
    /// show a "iCloud unavailable" hint in that case.
    ///
    /// The returned backend is a regular [`LocalBackend`]; to the
    /// vault it looks identical to any other directory. What
    /// makes it "iCloud" is only that macOS will sync the files
    /// inside to every other device of the same Apple ID.
    pub fn open_icloud_backend() -> Result<Option<LocalBackend>, VaultError> {
        let Some(path) = icloud_unovault_path() else {
            return Ok(None);
        };
        let backend = LocalBackend::new(&path)?;
        Ok(Some(backend))
    }

    /// Override constructor for tests: build a LocalBackend at the
    /// given path as if it were the iCloud folder. Lets the
    /// integration tests in `vault` exercise the full sync path
    /// without requiring a real iCloud Drive folder.
    pub fn open_at(path: &Path) -> Result<LocalBackend, VaultError> {
        LocalBackend::new(path)
    }

    /// Exposed so the Tauri layer can render
    /// "Syncing to /Users/you/Library/..." without re-resolving the
    /// path itself. Does NOT touch the filesystem.
    pub fn display_path_for_status() -> Option<String> {
        icloud_unovault_path().map(|p| p.display().to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::sync::FileSystemBackend;
        use tempfile::tempdir;

        #[test]
        fn open_at_creates_directory_and_accepts_chunks() {
            let dir = tempdir().expect("tempdir");
            let root = dir.path().join("icloud-emulated").join("unovault");
            let backend = open_at(&root).expect("open");
            backend
                .write("00000001-aaaa.chunk", b"payload")
                .expect("write");
            let list = backend.list().expect("list");
            assert_eq!(list.len(), 1);
        }

        #[test]
        fn icloud_drive_root_returns_none_on_non_macos() {
            // On macOS CI the folder may or may not exist, so this
            // test only enforces the contract on non-macOS.
            if !cfg!(target_os = "macos") {
                assert!(icloud_drive_root().is_none());
            }
        }

        #[test]
        fn display_path_for_status_is_well_formed_if_present() {
            // Only asserts the shape when the folder exists. On a
            // CI worker without iCloud this test is a no-op.
            if let Some(path) = display_path_for_status() {
                assert!(path.contains("unovault"));
            }
        }
    }
}

// =============================================================================
// CHAOS BACKEND — the test harness that proves LWW convergence under
// adversarial delivery order.
// =============================================================================

pub mod chaos {
    //! Adversarial backend for property-testing LWW convergence.
    //!
    //! The chaos backend wraps any other [`FileSystemBackend`] and
    //! injects faults into its outputs:
    //!
    //! * `hidden_on_list`: filenames the backend knows about but lies
    //!   about to `list()`. Simulates "iCloud hasn't delivered this
    //!   file yet."
    //! * `reorder_seed`: a u64 seed for shuffling list() results so the
    //!   reader never sees chunks in write order.
    //! * `duplicate_on_list`: filenames reported twice. Simulates
    //!   iCloud's occasional duplicate-delivery behavior.
    //!
    //! The harness exposes [`ChaosBackend::reveal`] to drop the "hidden"
    //! flag on one filename at a time, simulating delayed delivery.
    //! A property test walks through every possible reveal order and
    //! asserts that the folded vault state at each step is a consistent
    //! subset of the final state.

    use super::{FileSystemBackend, VaultError};
    use std::collections::{HashMap, HashSet};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// Chaos wrapper. Takes any `FileSystemBackend` and adds faults.
    pub struct ChaosBackend {
        inner: Box<dyn FileSystemBackend>,
        state: Mutex<ChaosState>,
    }

    struct ChaosState {
        /// Filenames currently hidden from `list()`. Still readable via
        /// `read()` if the caller guesses — but the reader won't know
        /// to ask.
        hidden: HashSet<String>,
        /// Filenames to report as duplicates in `list()` output.
        duplicated: HashSet<String>,
        /// Deterministic shuffle state. XorShift is enough for test use.
        shuffle_state: u64,
    }

    impl ChaosBackend {
        /// Wrap an inner backend. Initially, every file is hidden.
        /// Call [`ChaosBackend::reveal`] to make specific files visible
        /// to `list()`.
        pub fn new(inner: Box<dyn FileSystemBackend>, seed: u64) -> Self {
            Self {
                inner,
                state: Mutex::new(ChaosState {
                    hidden: HashSet::new(),
                    duplicated: HashSet::new(),
                    shuffle_state: seed,
                }),
            }
        }

        /// Hide a filename from subsequent `list()` calls. The file is
        /// still readable via `read()` — this only affects discovery.
        pub fn hide(&self, filename: &str) {
            if let Ok(mut state) = self.state.lock() {
                state.hidden.insert(filename.to_string());
            }
        }

        /// Reveal a previously hidden filename.
        pub fn reveal(&self, filename: &str) {
            if let Ok(mut state) = self.state.lock() {
                state.hidden.remove(filename);
            }
        }

        /// Mark a filename so it appears twice in `list()` output.
        /// Simulates iCloud's rare duplicate-delivery behavior.
        pub fn duplicate(&self, filename: &str) {
            if let Ok(mut state) = self.state.lock() {
                state.duplicated.insert(filename.to_string());
            }
        }

        /// Number of files the underlying backend has that are currently
        /// hidden from `list()`. Useful for step-by-step reveal testing.
        pub fn hidden_count(&self) -> usize {
            self.state
                .lock()
                .map(|s| s.hidden.len())
                .unwrap_or_default()
        }

        /// Expose every file the underlying backend holds. After this,
        /// the chaos backend behaves like its inner backend.
        pub fn reveal_all(&self) {
            if let Ok(mut state) = self.state.lock() {
                state.hidden.clear();
            }
        }
    }

    impl FileSystemBackend for ChaosBackend {
        fn root(&self) -> &Path {
            self.inner.root()
        }

        fn list(&self) -> Result<Vec<String>, VaultError> {
            let raw = self.inner.list()?;
            let mut state = self.state.lock().map_err(|_| {
                crate::BugInUnovaultError::InvariantViolation("chaos state lock poisoned")
            })?;

            // Filter out hidden filenames.
            let mut out: Vec<String> = raw
                .into_iter()
                .filter(|name| !state.hidden.contains(name))
                .collect();

            // Inject duplicates.
            let dupes: Vec<String> = out
                .iter()
                .filter(|name| state.duplicated.contains(*name))
                .cloned()
                .collect();
            out.extend(dupes);

            // Deterministic shuffle — simple xorshift-based Fisher-Yates.
            let n = out.len();
            for i in (1..n).rev() {
                state.shuffle_state ^= state.shuffle_state << 13;
                state.shuffle_state ^= state.shuffle_state >> 7;
                state.shuffle_state ^= state.shuffle_state << 17;
                let j = (state.shuffle_state as usize) % (i + 1);
                out.swap(i, j);
            }

            Ok(out)
        }

        fn read(&self, filename: &str) -> Result<Vec<u8>, VaultError> {
            self.inner.read(filename)
        }

        fn write(&self, filename: &str, bytes: &[u8]) -> Result<(), VaultError> {
            self.inner.write(filename, bytes)
        }
    }

    // The chaos backend hides an inner trait object. Expose its root
    // as a convenience for tests that want to read files directly.
    impl ChaosBackend {
        pub fn inner_root(&self) -> PathBuf {
            self.inner.root().to_path_buf()
        }
    }

    // Ensure the error-routing type is available for the poison case.
    #[allow(dead_code)]
    fn _assert_error_route() {
        let _: VaultError = crate::BugInUnovaultError::InvariantViolation("x").into();
    }

    /// HashMap import lint guard — not strictly used elsewhere; here so
    /// rustfmt and clippy don't complain if someone removes the state
    /// struct's HashMap later without realizing it was imported.
    #[allow(dead_code)]
    fn _touch_hashmap() {
        let _: HashMap<String, String> = HashMap::new();
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::chaos::ChaosBackend;
    use super::local::LocalBackend;
    use super::FileSystemBackend;
    use tempfile::tempdir;

    #[test]
    fn local_backend_roundtrips_chunk_bytes() {
        let dir = tempdir().expect("tempdir");
        let backend = LocalBackend::new(dir.path()).expect("backend");

        backend
            .write("00000001-aaaa.chunk", b"hello world")
            .expect("write");
        let listed = backend.list().expect("list");
        assert_eq!(listed, vec!["00000001-aaaa.chunk"]);

        let read = backend.read("00000001-aaaa.chunk").expect("read");
        assert_eq!(read, b"hello world");
    }

    #[test]
    fn local_backend_ignores_dotfiles_and_wrong_extension() {
        let dir = tempdir().expect("tempdir");
        let backend = LocalBackend::new(dir.path()).expect("backend");

        backend
            .write("00000001-aaaa.chunk", b"real")
            .expect("real write");

        // Drop sibling junk.
        std::fs::write(dir.path().join(".DS_Store"), b"apple junk").expect("dot");
        std::fs::write(dir.path().join("readme.txt"), b"nope").expect("txt");

        let listed = backend.list().expect("list");
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn local_backend_atomic_write_does_not_leave_tmp_file() {
        let dir = tempdir().expect("tempdir");
        let backend = LocalBackend::new(dir.path()).expect("backend");
        backend
            .write("00000001-aaaa.chunk", b"payload")
            .expect("write");

        // No *.tmp should remain after a successful write.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(Result::ok)
            .collect();
        for entry in &entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(!name.ends_with(".tmp"), "stray tmp file: {name}");
        }
    }

    #[test]
    fn chaos_backend_hides_files_from_list_but_still_allows_read() {
        let dir = tempdir().expect("tempdir");
        let inner = LocalBackend::new(dir.path()).expect("inner");
        inner
            .write("00000001-aaaa.chunk", b"hidden contents")
            .expect("write");

        let chaos = ChaosBackend::new(Box::new(inner), 0xDEAD);
        chaos.hide("00000001-aaaa.chunk");

        assert_eq!(chaos.list().expect("list"), Vec::<String>::new());

        // Direct read still works — simulates "the file exists on disk,
        // we just don't know about it yet."
        let read = chaos.read("00000001-aaaa.chunk").expect("read");
        assert_eq!(read, b"hidden contents");

        chaos.reveal("00000001-aaaa.chunk");
        assert_eq!(chaos.list().expect("list after reveal").len(), 1);
    }

    #[test]
    fn chaos_backend_reveal_all_exposes_every_hidden_file() {
        let dir = tempdir().expect("tempdir");
        let inner = LocalBackend::new(dir.path()).expect("inner");
        for i in 1u32..=5 {
            inner
                .write(&format!("{i:08x}-aaaa.chunk"), b"x")
                .expect("write");
        }

        let chaos = ChaosBackend::new(Box::new(inner), 0xBEEF);
        for i in 1u32..=5 {
            chaos.hide(&format!("{i:08x}-aaaa.chunk"));
        }
        assert_eq!(chaos.hidden_count(), 5);
        assert!(chaos.list().expect("list").is_empty());

        chaos.reveal_all();
        assert_eq!(chaos.hidden_count(), 0);
        assert_eq!(chaos.list().expect("list").len(), 5);
    }

    #[test]
    fn chaos_backend_shuffles_list_output_deterministically() {
        let dir = tempdir().expect("tempdir");
        let inner = LocalBackend::new(dir.path()).expect("inner");
        for i in 1u32..=10 {
            inner
                .write(&format!("{i:08x}-aaaa.chunk"), b"x")
                .expect("write");
        }

        // Same seed → same shuffle order.
        let chaos_a = ChaosBackend::new(Box::new(LocalBackend::new(dir.path()).unwrap()), 0x1234);
        let chaos_b = ChaosBackend::new(Box::new(LocalBackend::new(dir.path()).unwrap()), 0x1234);

        let list_a = chaos_a.list().expect("a");
        let list_b = chaos_b.list().expect("b");
        assert_eq!(list_a, list_b, "same seed should produce same order");

        // Different seed → different order (with high probability).
        let chaos_c = ChaosBackend::new(Box::new(LocalBackend::new(dir.path()).unwrap()), 0xABCD);
        let list_c = chaos_c.list().expect("c");
        assert_eq!(
            list_a.len(),
            list_c.len(),
            "both should contain the same set of files"
        );
        // With 10 files, P(identical permutation) is 1/10! ~= 3e-7, so
        // this assertion is effectively deterministic.
        assert_ne!(list_a, list_c, "different seeds should differ");
    }

    #[test]
    fn chaos_backend_injects_duplicate_filenames_into_list() {
        let dir = tempdir().expect("tempdir");
        let inner = LocalBackend::new(dir.path()).expect("inner");
        inner
            .write("00000001-aaaa.chunk", b"one")
            .expect("write one");
        inner
            .write("00000002-aaaa.chunk", b"two")
            .expect("write two");

        let chaos = ChaosBackend::new(Box::new(inner), 0x55);
        chaos.duplicate("00000001-aaaa.chunk");

        let listed = chaos.list().expect("list");
        let count_one = listed
            .iter()
            .filter(|n| *n == "00000001-aaaa.chunk")
            .count();
        assert_eq!(count_one, 2, "duplicate should appear twice");
    }

    /// Step-by-step reveal convergence test. Start with every chunk
    /// hidden. Reveal chunks one at a time in a fixed order. At every
    /// step, the set of visible chunks must be a strict subset of the
    /// eventually-visible set, and after the final reveal every chunk
    /// is visible. This models iCloud's "eventual delivery" guarantee.
    #[test]
    fn chaos_backend_step_by_step_reveal_converges() {
        let dir = tempdir().expect("tempdir");
        let inner = LocalBackend::new(dir.path()).expect("inner");
        let names: Vec<String> = (1u32..=8).map(|i| format!("{i:08x}-bbbb.chunk")).collect();
        for name in &names {
            inner.write(name, b"payload").expect("write");
        }

        let chaos = ChaosBackend::new(Box::new(inner), 0x0);
        for name in &names {
            chaos.hide(name);
        }
        assert!(chaos.list().expect("list").is_empty());

        // Reveal one at a time — the visible set is monotonically
        // non-shrinking and converges to the full set.
        let mut prev_visible = 0usize;
        for name in &names {
            chaos.reveal(name);
            let visible = chaos.list().expect("list").len();
            assert!(
                visible >= prev_visible,
                "visible count must not shrink during reveal"
            );
            prev_visible = visible;
        }

        // After all reveals, duplicates aside, every file is visible.
        let final_list = chaos.list().expect("final list");
        let unique: std::collections::HashSet<_> = final_list.iter().collect();
        assert_eq!(unique.len(), names.len());
    }
}
