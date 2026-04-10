//! The `.unovault` on-disk format — bundle directory layout, manifest
//! serialization, and chunk file IO.
//!
//! # Directory layout
//!
//! ```text
//! default.unovault/               ← macOS bundle (registered via CFBundlePackageType)
//! ├── manifest.json               ← immutable after creation, HMAC-protected
//! └── chunks/                     ← append-only encrypted event chunks
//!     ├── 00000001-<install>.chunk
//!     ├── 00000002-<install>.chunk
//!     └── ...
//! ```
//!
//! `manifest.json` is written **once at vault creation** and never modified
//! again. Why: iCloud Drive does not merge concurrent writes to JSON files;
//! if two devices rewrote the manifest they would produce `manifest 2.json`
//! conflict copies. Making it immutable sidesteps the problem entirely, and
//! the HMAC protects against tampering.
//!
//! Dynamic state (total chunk count, latest snapshot id, etc.) is **derived
//! at read time** by scanning `chunks/` — not stored in the manifest.
//!
//! # Chunk file naming
//!
//! `NNNNNNNN-<install_id>.chunk` where:
//!
//! * `NNNNNNNN` is the per-install zero-padded counter (8 hex digits in
//!   this v0; will expand to 16 if needed at format v2).
//! * `<install_id>` is the owning install's UUID in hyphenated form.
//!
//! The counter is per-install. Two devices can legitimately hold
//! `00000001-aaaa....chunk` and `00000001-bbbb....chunk` side by side —
//! their full filenames differ by install_id so there is no collision.
//! Sort order on disk is therefore install-grouped, not globally monotonic;
//! the [`Event`](crate::Event) ordering rules inside the payloads handle
//! cross-device total order.
//!
//! # Chunk file byte layout
//!
//! Each chunk file is a single [`encrypt_chunk`](crate::crypto::encrypt_chunk)
//! output with the magic header prepended for format identification:
//!
//! ```text
//! [0..4]     magic "UVLT"
//! [4..6]     format_version u16 little-endian
//! [6..30]    XChaCha20 nonce (24 bytes)
//! [30..]     ciphertext + Poly1305 tag (encrypted Vec<Event>)
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::{
    self, mac_from_base64, mac_to_base64, salt_from_base64, salt_to_base64, DerivedKeys, KdfParams,
    NONCE_LEN, SALT_LEN, TAG_LEN,
};
use crate::event::Event;
use crate::{
    BugInUnovaultError, InstallId, PlatformPolicyError, Secret, UserActionableError, VaultError,
    FORMAT_VERSION,
};

/// Magic bytes at the start of every chunk file. Lets us distinguish a
/// real unovault chunk from a random file that happens to be in the
/// `chunks/` directory.
pub const CHUNK_MAGIC: &[u8; 4] = b"UVLT";

/// Total chunk file header overhead: magic + version + nonce. The AEAD tag
/// is counted as part of the ciphertext body.
pub const CHUNK_HEADER_LEN: usize = 4 + 2 + NONCE_LEN;

/// Minimum possible chunk file size — header + empty ciphertext + tag.
pub const CHUNK_MIN_LEN: usize = CHUNK_HEADER_LEN + TAG_LEN;

/// The immutable manifest written once at vault creation.
///
/// The `manifest_mac` field is the HMAC-SHA256 over the JSON encoding of
/// the manifest **with `manifest_mac` set to an empty string**. This lets
/// us serialize the manifest twice: once to compute the MAC over the
/// canonical body, and a second time to actually write to disk with the
/// MAC filled in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultManifest {
    /// On-disk format version. Matches [`crate::FORMAT_VERSION`] at write
    /// time; a stored value higher than the reader's constant means the
    /// vault was produced by a newer build and we refuse to open it.
    pub format_version: u16,

    /// Schema version for item types and field shapes. Distinct from
    /// format_version so we can evolve item data without touching the
    /// crypto envelope.
    pub schema_version: u16,

    /// argon2id parameters used to derive the master key from the password.
    /// Stored in the manifest so older vaults keep working when we tune
    /// parameters for newer hardware.
    pub kdf: KdfParams,

    /// argon2id salt, unpadded URL-safe base64.
    pub salt_b64: String,

    /// HMAC-SHA256 over the canonical manifest JSON (with this field empty),
    /// unpadded URL-safe base64.
    pub manifest_mac_b64: String,
}

impl VaultManifest {
    /// Build a fresh manifest for a new vault. The caller must have already
    /// computed the derived keys from the password + fresh salt; this
    /// function writes the MAC over the canonical form.
    pub fn new(
        keys: &Secret<DerivedKeys>,
        salt: &[u8; SALT_LEN],
        kdf: KdfParams,
    ) -> Result<Self, VaultError> {
        let mut manifest = Self {
            format_version: FORMAT_VERSION,
            schema_version: 1,
            kdf,
            salt_b64: salt_to_base64(salt),
            manifest_mac_b64: String::new(),
        };

        let canonical = manifest.canonical_bytes()?;
        let mac = crypto::compute_mac(keys, &canonical)?;
        manifest.manifest_mac_b64 = mac_to_base64(&mac);

        Ok(manifest)
    }

    /// Serialize the manifest into its canonical "body" bytes — the shape
    /// the MAC is computed over. Temporarily clears the MAC field so the
    /// encoding is reproducible.
    fn canonical_bytes(&self) -> Result<Vec<u8>, VaultError> {
        let mut clone = self.clone();
        clone.manifest_mac_b64 = String::new();
        serde_json::to_vec_pretty(&clone)
            .map_err(|_| BugInUnovaultError::SelfSerializationFailure.into())
    }

    /// Verify the manifest MAC using a known-good set of derived keys.
    pub fn verify(&self, keys: &Secret<DerivedKeys>) -> Result<(), VaultError> {
        let expected = mac_from_base64(&self.manifest_mac_b64)?;
        let canonical = self.canonical_bytes()?;
        crypto::verify_mac(keys, &canonical, &expected)
    }

    /// Decode the stored salt from base64 back into a fixed-length array.
    pub fn salt(&self) -> Result<[u8; SALT_LEN], VaultError> {
        salt_from_base64(&self.salt_b64)
    }

    /// Reject vaults produced by a newer format version than this build
    /// supports. Equal or older versions are accepted — older formats can
    /// still be read within the same major version.
    pub fn check_format_version(&self) -> Result<(), VaultError> {
        if self.format_version > FORMAT_VERSION {
            return Err(UserActionableError::UnsupportedFormatVersion {
                found: self.format_version,
                supported: FORMAT_VERSION,
            }
            .into());
        }
        Ok(())
    }
}

/// Paths inside a `.unovault` bundle directory.
#[derive(Debug, Clone)]
pub struct VaultPaths {
    /// The bundle directory itself (e.g. `default.unovault`).
    pub bundle: PathBuf,
    /// `{bundle}/manifest.json`.
    pub manifest: PathBuf,
    /// `{bundle}/chunks/` directory.
    pub chunks_dir: PathBuf,
}

impl VaultPaths {
    /// Compute the canonical paths for a vault bundle. Does not touch the
    /// filesystem.
    pub fn for_bundle(bundle: impl Into<PathBuf>) -> Self {
        let bundle: PathBuf = bundle.into();
        let manifest = bundle.join("manifest.json");
        let chunks_dir = bundle.join("chunks");
        Self {
            bundle,
            manifest,
            chunks_dir,
        }
    }

    /// Filename for the Nth chunk written by the given install. The format
    /// is `NNNNNNNN-<install_hyphenated>.chunk`.
    pub fn chunk_filename(counter: u32, install: &InstallId) -> String {
        format!("{:08x}-{}.chunk", counter, install.as_uuid().hyphenated())
    }

    /// Full path for the Nth chunk produced by `install`.
    pub fn chunk_path(&self, counter: u32, install: &InstallId) -> PathBuf {
        self.chunks_dir.join(Self::chunk_filename(counter, install))
    }
}

/// Create the bundle directory, write the manifest, and create the empty
/// chunks directory. Caller has already derived the keys from the password.
///
/// Returns the canonical [`VaultPaths`]. Errors out if the bundle path
/// already exists to avoid accidentally overwriting a user's real vault.
pub fn create_bundle(
    bundle_path: &Path,
    keys: &Secret<DerivedKeys>,
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
) -> Result<VaultPaths, VaultError> {
    if bundle_path.exists() {
        return Err(UserActionableError::VaultAlreadyExists.into());
    }

    let paths = VaultPaths::for_bundle(bundle_path);

    fs::create_dir_all(&paths.chunks_dir).map_err(|_| PlatformPolicyError::SandboxDenied)?;

    let manifest = VaultManifest::new(keys, salt, kdf)?;
    write_manifest(&paths, &manifest)?;

    Ok(paths)
}

/// Write the manifest atomically: serialize, write to `manifest.tmp`,
/// fsync, rename. Crash-safe.
fn write_manifest(paths: &VaultPaths, manifest: &VaultManifest) -> Result<(), VaultError> {
    let body = serde_json::to_vec_pretty(manifest)
        .map_err(|_| BugInUnovaultError::SelfSerializationFailure)?;

    let tmp = paths.manifest.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(|_| PlatformPolicyError::SandboxDenied)?;
        f.write_all(&body)
            .map_err(|_| PlatformPolicyError::SandboxDenied)?;
        f.sync_all()
            .map_err(|_| PlatformPolicyError::SandboxDenied)?;
    }
    fs::rename(&tmp, &paths.manifest).map_err(|_| PlatformPolicyError::SandboxDenied)?;
    Ok(())
}

/// Load and parse `manifest.json` for an existing vault bundle.
///
/// Does **not** verify the MAC — the caller must derive keys from the
/// password first, then call [`VaultManifest::verify`] on the returned
/// manifest. Separating the two steps lets unlock surface the correct error
/// (wrong password vs. tampered manifest).
pub fn load_manifest(bundle_path: &Path) -> Result<VaultManifest, VaultError> {
    let paths = VaultPaths::for_bundle(bundle_path);
    if !paths.bundle.exists() || !paths.manifest.exists() {
        return Err(UserActionableError::VaultNotFound.into());
    }
    let bytes = fs::read(&paths.manifest).map_err(|_| PlatformPolicyError::SandboxDenied)?;
    let manifest: VaultManifest =
        serde_json::from_slice(&bytes).map_err(|_| UserActionableError::CorruptedManifest)?;
    manifest.check_format_version()?;
    Ok(manifest)
}

/// Serialize a batch of events, encrypt them, wrap in the chunk magic
/// header, and return the bytes ready to be written to a chunk file.
pub fn encode_chunk_bytes(
    keys: &Secret<DerivedKeys>,
    events: &[Event],
) -> Result<Vec<u8>, VaultError> {
    // Serialize the events as a single postcard `Vec<Event>`.
    let plaintext =
        postcard::to_allocvec(events).map_err(|_| BugInUnovaultError::SelfSerializationFailure)?;

    // Encrypt → [nonce | ciphertext | tag]
    let encrypted = crypto::encrypt_chunk(keys, &plaintext)?;

    // Chunk file layout: [magic (4)] [version (2)] [encrypted body]
    let mut buf = Vec::with_capacity(CHUNK_HEADER_LEN + encrypted.len() - NONCE_LEN);
    buf.extend_from_slice(CHUNK_MAGIC);
    buf.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf.extend_from_slice(&encrypted);

    // Best-effort zeroize of the intermediate plaintext buffer. The original
    // events still live in the caller's memory; this only wipes our local
    // postcard buffer.
    let mut plaintext = plaintext;
    use zeroize::Zeroize;
    plaintext.zeroize();

    Ok(buf)
}

/// Inverse of [`encode_chunk_bytes`]. Validates magic + version, decrypts,
/// and deserializes back into a `Vec<Event>`.
pub fn decode_chunk_bytes(
    keys: &Secret<DerivedKeys>,
    bytes: &[u8],
) -> Result<Vec<Event>, VaultError> {
    if bytes.len() < CHUNK_MIN_LEN {
        return Err(UserActionableError::CorruptedChunk.into());
    }
    if &bytes[..4] != CHUNK_MAGIC {
        return Err(UserActionableError::CorruptedChunk.into());
    }
    let mut version_bytes = [0u8; 2];
    version_bytes.copy_from_slice(&bytes[4..6]);
    let version = u16::from_le_bytes(version_bytes);
    if version > FORMAT_VERSION {
        return Err(UserActionableError::UnsupportedFormatVersion {
            found: version,
            supported: FORMAT_VERSION,
        }
        .into());
    }

    let encrypted_body = &bytes[CHUNK_HEADER_LEN - NONCE_LEN..]; // skip magic + version
    let plaintext = crypto::decrypt_chunk(keys, encrypted_body)?;

    let events: Vec<Event> =
        postcard::from_bytes(&plaintext).map_err(|_| UserActionableError::CorruptedChunk)?;
    Ok(events)
}

/// Write a chunk file atomically: serialize, encrypt, write to `.tmp`,
/// fsync, rename. Crash-safe.
pub fn write_chunk(
    paths: &VaultPaths,
    install: &InstallId,
    counter: u32,
    keys: &Secret<DerivedKeys>,
    events: &[Event],
) -> Result<PathBuf, VaultError> {
    let final_path = paths.chunk_path(counter, install);
    let tmp_path = final_path.with_extension("chunk.tmp");

    let bytes = encode_chunk_bytes(keys, events)?;

    {
        let mut f = fs::File::create(&tmp_path).map_err(|_| PlatformPolicyError::SandboxDenied)?;
        f.write_all(&bytes)
            .map_err(|_| PlatformPolicyError::SandboxDenied)?;
        f.sync_all()
            .map_err(|_| PlatformPolicyError::SandboxDenied)?;
    }

    fs::rename(&tmp_path, &final_path).map_err(|_| PlatformPolicyError::SandboxDenied)?;

    Ok(final_path)
}

/// Scan the chunks directory and return every valid chunk file path,
/// filtered by extension. Ignores hidden files, temp files, and files that
/// do not end in `.chunk`.
pub fn list_chunk_files(paths: &VaultPaths) -> Result<Vec<PathBuf>, VaultError> {
    if !paths.chunks_dir.exists() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for entry in fs::read_dir(&paths.chunks_dir).map_err(|_| PlatformPolicyError::SandboxDenied)? {
        let entry = entry.map_err(|_| PlatformPolicyError::SandboxDenied)?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        if !name.ends_with(".chunk") {
            continue;
        }
        out.push(path);
    }

    // Sort lexicographically so tests are deterministic. LWW ordering is
    // applied per-event inside the payloads, so on-disk order does not
    // affect merge correctness.
    out.sort();
    Ok(out)
}

/// Read every chunk file in the bundle, decrypt, and return the flattened
/// event stream. Sorting into LWW order is the caller's job — see
/// [`crate::event::sort_events`].
pub fn read_all_events(
    paths: &VaultPaths,
    keys: &Secret<DerivedKeys>,
) -> Result<Vec<Event>, VaultError> {
    let files = list_chunk_files(paths)?;
    let mut all = Vec::new();
    for path in files {
        let bytes = fs::read(&path).map_err(|_| PlatformPolicyError::SandboxDenied)?;
        let mut events = decode_chunk_bytes(keys, &bytes)?;
        all.append(&mut events);
    }
    Ok(all)
}

/// Return the highest counter value already written to disk by this
/// `install_id`. A fresh install returns 0.
///
/// Used by the vault layer to assign the next counter when writing new
/// chunks — we must never reuse a counter value since doing so would
/// overwrite an existing chunk file.
pub fn max_counter_for_install(paths: &VaultPaths, install: &InstallId) -> Result<u32, VaultError> {
    let suffix = format!("-{}.chunk", install.as_uuid().hyphenated());
    let files = list_chunk_files(paths)?;
    let mut max = 0u32;
    for path in files {
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(prefix) = name.strip_suffix(&suffix) else {
            continue;
        };
        if prefix.len() != 8 {
            continue;
        }
        if let Ok(counter) = u32::from_str_radix(prefix, 16) {
            if counter > max {
                max = counter;
            }
        }
    }
    Ok(max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_master_key, derive_sub_keys, generate_salt};
    use crate::event::{ItemId, ItemKind, ItemSnapshot, Op};
    use crate::Secret;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn test_keys(password: &str) -> (Secret<DerivedKeys>, [u8; SALT_LEN]) {
        let salt = generate_salt().expect("salt");
        let pw = Secret::new(String::from(password));
        let master = derive_master_key(&pw, &salt, &KdfParams::TEST_ONLY).expect("master");
        let keys = derive_sub_keys(&master).expect("sub keys");
        (keys, salt)
    }

    fn make_event(timestamp_ms: u64, install: Uuid, lamport: u64) -> Event {
        Event::new(
            install,
            lamport,
            timestamp_ms,
            Op::CreateItem {
                item_id: ItemId::new(),
                initial: ItemSnapshot {
                    title: format!("Item@{timestamp_ms}"),
                    kind: ItemKind::Password,
                    username: None,
                    url: None,
                },
            },
        )
    }

    #[test]
    fn create_bundle_writes_manifest_and_chunks_dir() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("test.unovault");
        let (keys, salt) = test_keys("hunter2");
        let paths =
            create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create bundle");

        assert!(paths.bundle.exists());
        assert!(paths.manifest.exists());
        assert!(paths.chunks_dir.exists());
        assert!(paths.chunks_dir.is_dir());
    }

    #[test]
    fn create_bundle_rejects_existing_path() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("existing");
        fs::create_dir_all(&bundle).expect("mkdir");
        let (keys, salt) = test_keys("hunter2");
        match create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY) {
            Err(VaultError::UserActionable(UserActionableError::VaultAlreadyExists)) => {}
            other => panic!("expected VaultAlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn manifest_roundtrip_preserves_fields() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("mf.unovault");
        let (keys, salt) = test_keys("hunter2");
        create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create");

        let loaded = load_manifest(&bundle).expect("load");
        assert_eq!(loaded.format_version, FORMAT_VERSION);
        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.kdf, KdfParams::TEST_ONLY);
        assert_eq!(loaded.salt().expect("salt decode"), salt);
    }

    #[test]
    fn manifest_verify_accepts_correct_keys() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("v.unovault");
        let (keys, salt) = test_keys("hunter2");
        create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create");
        let manifest = load_manifest(&bundle).expect("load");
        manifest.verify(&keys).expect("verify should succeed");
    }

    #[test]
    fn manifest_verify_rejects_tampered_body() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("t.unovault");
        let (keys, salt) = test_keys("hunter2");
        create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create");

        // Tamper with the on-disk manifest: flip the schema_version from 1 to 2.
        let manifest_path = bundle.join("manifest.json");
        let mut contents = fs::read_to_string(&manifest_path).expect("read");
        contents = contents.replace("\"schema_version\": 1", "\"schema_version\": 2");
        fs::write(&manifest_path, contents).expect("write");

        let manifest = load_manifest(&bundle).expect("load");
        match manifest.verify(&keys) {
            Err(VaultError::UserActionable(UserActionableError::CorruptedManifest)) => {}
            other => panic!("expected CorruptedManifest, got {other:?}"),
        }
    }

    #[test]
    fn load_manifest_rejects_missing_bundle() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("does-not-exist.unovault");
        match load_manifest(&bundle) {
            Err(VaultError::UserActionable(UserActionableError::VaultNotFound)) => {}
            other => panic!("expected VaultNotFound, got {other:?}"),
        }
    }

    #[test]
    fn load_manifest_rejects_corrupted_json() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("corrupt.unovault");
        fs::create_dir_all(bundle.join("chunks")).expect("mkdir");
        fs::write(bundle.join("manifest.json"), "{ not valid json").expect("write");
        match load_manifest(&bundle) {
            Err(VaultError::UserActionable(UserActionableError::CorruptedManifest)) => {}
            other => panic!("expected CorruptedManifest, got {other:?}"),
        }
    }

    #[test]
    fn chunk_filename_is_deterministic() {
        let install = InstallId(Uuid::from_bytes([0xAB; 16]));
        let name = VaultPaths::chunk_filename(42, &install);
        assert!(name.starts_with("0000002a-"));
        assert!(name.ends_with(".chunk"));
        assert!(name.contains(&install.as_uuid().hyphenated().to_string()));
    }

    #[test]
    fn write_and_read_single_chunk_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("rt.unovault");
        let (keys, salt) = test_keys("hunter2");
        let paths = create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create");

        let install = InstallId::new();
        let events = vec![
            make_event(1, install.as_uuid(), 0),
            make_event(2, install.as_uuid(), 1),
        ];

        write_chunk(&paths, &install, 1, &keys, &events).expect("write");

        let loaded = read_all_events(&paths, &keys).expect("read");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded, events);
    }

    #[test]
    fn read_all_events_merges_multiple_chunks() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("multi.unovault");
        let (keys, salt) = test_keys("hunter2");
        let paths = create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create");

        let install = InstallId::new();
        let events_a = vec![make_event(1, install.as_uuid(), 0)];
        let events_b = vec![make_event(2, install.as_uuid(), 1)];
        let events_c = vec![make_event(3, install.as_uuid(), 2)];

        write_chunk(&paths, &install, 1, &keys, &events_a).expect("a");
        write_chunk(&paths, &install, 2, &keys, &events_b).expect("b");
        write_chunk(&paths, &install, 3, &keys, &events_c).expect("c");

        let loaded = read_all_events(&paths, &keys).expect("read");
        assert_eq!(loaded.len(), 3);
    }

    #[test]
    fn list_chunk_files_ignores_dotfiles_and_wrong_extension() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("noise.unovault");
        let (keys, salt) = test_keys("hunter2");
        let paths = create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create");

        let install = InstallId::new();
        write_chunk(&paths, &install, 1, &keys, &[]).expect("real chunk");

        // Junk files that should be ignored.
        fs::write(paths.chunks_dir.join(".DS_Store"), b"mac junk").expect("ds");
        fs::write(paths.chunks_dir.join("README.txt"), b"hi").expect("readme");
        fs::write(paths.chunks_dir.join("garbage.bin"), b"nope").expect("garbage");

        let files = list_chunk_files(&paths).expect("list");
        assert_eq!(files.len(), 1, "only the real chunk should be listed");
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let (keys, _) = test_keys("hunter2");
        let mut bad = vec![0u8; CHUNK_MIN_LEN];
        bad[..4].copy_from_slice(b"XXXX");
        match decode_chunk_bytes(&keys, &bad) {
            Err(VaultError::UserActionable(UserActionableError::CorruptedChunk)) => {}
            other => panic!("expected CorruptedChunk on wrong magic, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_future_format_version() {
        let (keys, _) = test_keys("hunter2");
        let mut bad = Vec::new();
        bad.extend_from_slice(CHUNK_MAGIC);
        bad.extend_from_slice(&(FORMAT_VERSION + 10).to_le_bytes());
        bad.resize(CHUNK_MIN_LEN, 0);
        match decode_chunk_bytes(&keys, &bad) {
            Err(VaultError::UserActionable(UserActionableError::UnsupportedFormatVersion {
                found,
                supported,
            })) => {
                assert!(found > supported);
            }
            other => panic!("expected UnsupportedFormatVersion, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_truncated_bytes() {
        let (keys, _) = test_keys("hunter2");
        let short = vec![0u8; 10];
        match decode_chunk_bytes(&keys, &short) {
            Err(VaultError::UserActionable(UserActionableError::CorruptedChunk)) => {}
            other => panic!("expected CorruptedChunk on short, got {other:?}"),
        }
    }

    #[test]
    fn max_counter_for_install_is_zero_when_fresh() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("fresh.unovault");
        let (keys, salt) = test_keys("hunter2");
        let paths = create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create");

        let install = InstallId::new();
        let max = max_counter_for_install(&paths, &install).expect("max");
        assert_eq!(max, 0);
    }

    #[test]
    fn max_counter_for_install_tracks_highest_written_counter() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("count.unovault");
        let (keys, salt) = test_keys("hunter2");
        let paths = create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create");

        let install = InstallId::new();
        write_chunk(&paths, &install, 1, &keys, &[]).expect("1");
        write_chunk(&paths, &install, 2, &keys, &[]).expect("2");
        write_chunk(&paths, &install, 7, &keys, &[]).expect("7");
        // Out-of-order writes are allowed — max returns 7.
        let max = max_counter_for_install(&paths, &install).expect("max");
        assert_eq!(max, 7);
    }

    #[test]
    fn max_counter_for_install_is_per_install() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("shard.unovault");
        let (keys, salt) = test_keys("hunter2");
        let paths = create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create");

        let a = InstallId::new();
        let b = InstallId::new();
        write_chunk(&paths, &a, 1, &keys, &[]).expect("a1");
        write_chunk(&paths, &a, 2, &keys, &[]).expect("a2");
        write_chunk(&paths, &b, 1, &keys, &[]).expect("b1");

        assert_eq!(max_counter_for_install(&paths, &a).expect("a max"), 2);
        assert_eq!(max_counter_for_install(&paths, &b).expect("b max"), 1);
    }

    /// QA gap fill: a stray `.chunk.tmp` file from a crash mid-write must
    /// not trip up the reader. `list_chunk_files` filters by `.ends_with(".chunk")`
    /// which excludes `.chunk.tmp`, and this test proves it.
    #[test]
    fn dangling_chunk_tmp_file_is_ignored_by_reader() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("crash.unovault");
        let (keys, salt) = test_keys("hunter2");
        let paths = create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create");

        let install = InstallId::new();
        write_chunk(
            &paths,
            &install,
            1,
            &keys,
            &[make_event(1, install.as_uuid(), 0)],
        )
        .expect("write real");

        // Simulate a crash-before-rename: drop a .chunk.tmp file with junk.
        fs::write(
            paths.chunks_dir.join("00000002-crashed.chunk.tmp"),
            b"partial junk",
        )
        .expect("write tmp");

        let files = list_chunk_files(&paths).expect("list");
        assert_eq!(files.len(), 1, "only the real .chunk file should appear");

        let events = read_all_events(&paths, &keys).expect("read");
        assert_eq!(events.len(), 1);
    }

    /// QA gap fill: fuzz-style test that `decode_chunk_bytes` never panics
    /// on arbitrary input. Runs a fast hand-rolled fuzz loop because we
    /// already verify crypto-level panic-safety in the crypto module's
    /// proptests.
    #[test]
    fn decode_chunk_bytes_never_panics_on_adversarial_input() {
        let (keys, _) = test_keys("hunter2");
        // Use a deterministic PRNG seed so failures are reproducible.
        let mut state: u64 = 0xDEAD_BEEF_CAFE_BABE;
        for iteration in 0..256 {
            // Simple xorshift for test-only deterministic randomness.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state as usize) % 512;
            let mut buf = vec![0u8; len];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = ((state.wrapping_add(i as u64)) & 0xFF) as u8;
            }
            // Some iterations: plant the magic so we exercise the decrypt path.
            if iteration % 3 == 0 && len >= 4 {
                buf[..4].copy_from_slice(CHUNK_MAGIC);
            }
            let _ = decode_chunk_bytes(&keys, &buf); // must not panic
        }
    }

    #[test]
    fn two_installs_write_side_by_side_without_collision() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path().join("concurrent.unovault");
        let (keys, salt) = test_keys("hunter2");
        let paths = create_bundle(&bundle, &keys, &salt, KdfParams::TEST_ONLY).expect("create");

        let install_a = InstallId::new();
        let install_b = InstallId::new();

        // Both installs pick counter=1, but the filenames differ by install_id.
        write_chunk(
            &paths,
            &install_a,
            1,
            &keys,
            &[make_event(1, install_a.as_uuid(), 0)],
        )
        .expect("a");
        write_chunk(
            &paths,
            &install_b,
            1,
            &keys,
            &[make_event(2, install_b.as_uuid(), 0)],
        )
        .expect("b");

        let files = list_chunk_files(&paths).expect("list");
        assert_eq!(files.len(), 2);

        let events = read_all_events(&paths, &keys).expect("read");
        assert_eq!(events.len(), 2);
    }
}
