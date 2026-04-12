//! The integrated vault — the module where every other module meets.
//!
//! [`Vault`] owns the in-memory state (items folded from the LWW event log)
//! and the derived keys needed to write new chunks. It is the API surface
//! the Tauri layer will eventually depend on: create, unlock, add items,
//! read items, save.
//!
//! # Lifecycle
//!
//! ```text
//!   Vault::create(path, password)
//!        │  generates salt, derives keys,
//!        │  writes manifest, empty chunks/
//!        ▼
//!   Vault (in-memory, 0 items)
//!        │  add_item, set_field, delete_item
//!        │    each call appends to `pending` queue
//!        ▼
//!   Vault.save()
//!        │  writes `pending` as a single chunk file, clears queue
//!        ▼
//!   drop → zeroize derived keys
//!
//!   Vault::unlock(path, password)
//!        │  loads manifest, derives keys, verifies MAC,
//!        │  reads every chunk, decodes, sorts, folds into state
//!        ▼
//!   Vault (in-memory, N items)
//! ```
//!
//! # Week 4 gate
//!
//! The end-to-end `save_and_reopen_round_trip` test in this module is the
//! Week 4 Go/No-Go gate from the CEO plan. If it passes on the builder's
//! Mac at week 4, week 5-6 bridge work starts on schedule. If it fails, the
//! plan pivots to Approach E (menu bar launcher).
//!
//! # What this module deliberately does not do yet
//!
//! * **Secret<T> wrapping for in-memory item state.** The current MVP holds
//!   item fields as plain `Vec<u8>` / `String`. A follow-up pass wraps the
//!   sensitive fields in `Secret` and adds a compile-time check that
//!   `ItemState::password` cannot leak via `Debug`.
//! * **Search index.** Built in weeks 7-9 when the UI starts calling it.
//! * **Rotation and recovery phrase re-wrap.** Week 16-17.
//! * **Compaction.** Not needed until vaults grow large.
//! * **Deletion.** Tombstone semantics are specified in `event::Op::DeleteItem`
//!   but not yet exposed through the `Vault` API. Added when the UI needs it.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{self, DerivedKeys, KdfParams, KEY_LEN, SALT_LEN};
use crate::event::{sort_events, Event, FieldKey, FieldValue, ItemId, ItemKind, ItemSnapshot, Op};
use crate::format::{
    create_bundle, list_chunk_filenames, load_manifest, max_counter_for_install, read_all_events,
    read_chunk_raw, write_chunk, write_chunk_raw, NewManifestInputs, RecoverySlot, VaultPaths,
};
use crate::install_id::InstallId;
use crate::recovery::RecoveryPhrase;
use crate::secret::Secret;
use crate::sync::FileSystemBackend;
use crate::{BugInUnovaultError, UserActionableError, VaultError};

/// Folded, in-memory representation of a single vault item. Produced by
/// replaying the LWW event log through [`fold_events`]. Contains only the
/// data the application layer needs — no event history.
///
/// `Debug` is implemented manually to redact the password and TOTP secret
/// bytes. Deriving `Debug` would leak `"password": Some([0x68, ...])`
/// into any log statement that formats an enclosing struct via `{:?}`.
/// The manual impl prints `<redacted N bytes>` for secret fields and the
/// real values for non-secret metadata.
///
/// `PartialEq`/`Eq` are behind `cfg(test)` only. Byte-wise equality on a
/// secret is a timing side channel; tests can tolerate it, production code
/// uses `subtle::ConstantTimeEq` or equivalent.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ItemState {
    pub id: ItemId,
    pub title: String,
    pub kind: ItemKind,
    pub username: Option<String>,
    pub url: Option<String>,
    pub password: Option<Vec<u8>>,
    pub totp_secret: Option<Vec<u8>>,
    pub notes: Option<String>,
    pub created_at_ms: u64,
    pub modified_at_ms: u64,
}

impl fmt::Debug for ItemState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemState")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("kind", &self.kind)
            .field("username", &self.username)
            .field("url", &self.url)
            .field(
                "password",
                &self
                    .password
                    .as_ref()
                    .map(|b| format!("<redacted {} bytes>", b.len())),
            )
            .field(
                "totp_secret",
                &self
                    .totp_secret
                    .as_ref()
                    .map(|b| format!("<redacted {} bytes>", b.len())),
            )
            .field("notes", &self.notes.as_ref().map(|_| "<redacted>"))
            .field("created_at_ms", &self.created_at_ms)
            .field("modified_at_ms", &self.modified_at_ms)
            .finish()
    }
}

impl ItemState {
    pub(crate) fn from_snapshot(id: ItemId, snapshot: ItemSnapshot, timestamp_ms: u64) -> Self {
        Self {
            id,
            title: snapshot.title,
            kind: snapshot.kind,
            username: snapshot.username,
            url: snapshot.url,
            password: None,
            totp_secret: None,
            notes: None,
            created_at_ms: timestamp_ms,
            modified_at_ms: timestamp_ms,
        }
    }

    fn apply_field_update(&mut self, field: &FieldKey, value: FieldValue, timestamp_ms: u64) {
        self.modified_at_ms = timestamp_ms;
        match (field, value) {
            (FieldKey::Title, FieldValue::Text(t)) => self.title = t,
            (FieldKey::Username, FieldValue::Text(t)) => self.username = Some(t),
            (FieldKey::Username, FieldValue::Tombstone) => self.username = None,
            (FieldKey::Url, FieldValue::Text(t)) => self.url = Some(t),
            (FieldKey::Url, FieldValue::Tombstone) => self.url = None,
            (FieldKey::Password, FieldValue::Bytes(b)) => self.password = Some(b),
            (FieldKey::Password, FieldValue::Tombstone) => self.password = None,
            (FieldKey::TotpSecret, FieldValue::Bytes(b)) => self.totp_secret = Some(b),
            (FieldKey::TotpSecret, FieldValue::Tombstone) => self.totp_secret = None,
            (FieldKey::Notes, FieldValue::Text(t)) => self.notes = Some(t),
            (FieldKey::Notes, FieldValue::Tombstone) => self.notes = None,
            (FieldKey::Kind, FieldValue::Kind(k)) => self.kind = k,
            // Unknown combinations (e.g. Text on a Bytes field) are dropped
            // rather than crashed. A later format version may reject these,
            // but v1 prefers forward-compat over strictness.
            _ => {}
        }
    }
}

/// Fold a sorted slice of events into a map of item state.
///
/// Caller must have already sorted events via [`sort_events`]. This function
/// assumes LWW-ordered input; a later `UpdateField` overwrites an earlier one
/// for the same (item_id, field_key) tuple.
///
/// `DeleteItem` tombstones the entry. Subsequent events for the same item_id
/// are dropped. (Resurrection requires a fresh item_id, which is the design
/// doc's documented rule.)
pub fn fold_events(events: &[Event]) -> HashMap<ItemId, ItemState> {
    let mut state: HashMap<ItemId, ItemState> = HashMap::new();
    let mut tombstoned: std::collections::HashSet<ItemId> = std::collections::HashSet::new();

    for event in events {
        match &event.op {
            Op::CreateItem { item_id, initial } => {
                if tombstoned.contains(item_id) {
                    continue;
                }
                // A later CreateItem with the same id is rare (client error).
                // LWW says "last writer wins" — we respect that and replace.
                state.insert(
                    *item_id,
                    ItemState::from_snapshot(*item_id, initial.clone(), event.timestamp_ms),
                );
            }
            Op::UpdateField {
                item_id,
                field,
                value,
            } => {
                if tombstoned.contains(item_id) {
                    continue;
                }
                if let Some(item) = state.get_mut(item_id) {
                    item.apply_field_update(field, value.clone(), event.timestamp_ms);
                }
                // UpdateField for an item we have never seen is dropped.
                // This can happen if chunks arrive out of order and the
                // CreateItem event has not landed yet; later sorted replays
                // from the same chunk set will handle it correctly.
            }
            Op::DeleteItem { item_id } => {
                tombstoned.insert(*item_id);
                state.remove(item_id);
            }
        }
    }

    state
}

/// Summary of a [`Vault::sync_with_backend`] call. Used by the UI
/// layer to surface "synced 3 new chunks from iCloud" toasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSummary {
    /// How many local chunks were uploaded to the backend.
    pub pushed: u32,
    /// How many backend chunks were downloaded to local.
    pub pulled: u32,
}

/// The integrated vault — owns in-memory state, derived keys, and the
/// append buffer for unsaved changes.
pub struct Vault {
    paths: VaultPaths,
    /// The 32-byte master key. Kept in memory because password/recovery
    /// rotation needs to re-wrap it under a new KEK without asking the
    /// user to re-derive the sub-keys. Zeroizes on drop via `Secret`.
    master: Secret<[u8; KEY_LEN]>,
    /// Sub-keys (encryption + MAC) derived from the master via HKDF.
    /// Held separately so chunk encrypt/decrypt and manifest MAC don't
    /// re-run HKDF on every call.
    keys: Secret<DerivedKeys>,
    install: InstallId,
    items: HashMap<ItemId, ItemState>,
    /// Events produced by mutating methods that have not yet been flushed
    /// to a chunk file. [`Vault::save`] writes them as one chunk and clears
    /// the buffer.
    pending: Vec<Event>,
    /// Monotonic per-install counter. Seeded from the on-disk state at
    /// open time so we never reuse a filename.
    next_chunk_counter: u32,
    /// Monotonic per-install Lamport counter for ordering events within
    /// the same millisecond window.
    next_lamport: u64,
}

impl Vault {
    /// Create a fresh vault at `bundle_path` with only a master password.
    /// No recovery phrase is generated; to add one later call
    /// [`Vault::enable_recovery`].
    ///
    /// Generates a random master key, wraps it under a password-derived
    /// KEK, writes the manifest, and creates the empty chunks directory.
    /// Returns an unlocked in-memory vault with zero items.
    pub fn create(
        bundle_path: impl AsRef<Path>,
        password: Secret<String>,
        install: InstallId,
    ) -> Result<Self, VaultError> {
        Self::create_inner(bundle_path, password, None, install, KdfParams::V1)
    }

    /// Create a fresh vault with both a master password **and** a BIP39
    /// 24-word recovery phrase. The phrase is returned once — the caller
    /// MUST show it to the user and warn them to store it securely; it is
    /// the only way to recover the vault if they forget the password.
    /// The phrase is not stored anywhere on disk.
    pub fn create_with_recovery(
        bundle_path: impl AsRef<Path>,
        password: Secret<String>,
        install: InstallId,
    ) -> Result<(Self, RecoveryPhrase), VaultError> {
        let phrase = RecoveryPhrase::generate()?;
        let vault =
            Self::create_inner(bundle_path, password, Some(&phrase), install, KdfParams::V1)?;
        Ok((vault, phrase))
    }

    /// Like [`Vault::create`], but uses [`KdfParams::TEST_ONLY`] so
    /// the test suite finishes in milliseconds.
    ///
    /// **Never call this from production code.** Exposed publicly
    /// so downstream crates (`unovault-app`, `unovault-passkey`,
    /// the integration test harnesses) can spin up fast in-memory
    /// vaults in their own test suites.
    pub fn create_for_tests(
        bundle_path: impl AsRef<Path>,
        password: Secret<String>,
        install: InstallId,
    ) -> Result<Self, VaultError> {
        Self::create_inner(bundle_path, password, None, install, KdfParams::TEST_ONLY)
    }

    /// Like [`Vault::create_with_recovery`], but uses
    /// [`KdfParams::TEST_ONLY`]. Same production warning as
    /// [`Vault::create_for_tests`].
    pub fn create_with_recovery_for_tests(
        bundle_path: impl AsRef<Path>,
        password: Secret<String>,
        install: InstallId,
    ) -> Result<(Self, RecoveryPhrase), VaultError> {
        let phrase = RecoveryPhrase::generate()?;
        let vault = Self::create_inner(
            bundle_path,
            password,
            Some(&phrase),
            install,
            KdfParams::TEST_ONLY,
        )?;
        Ok((vault, phrase))
    }

    /// Shared implementation of create + create_with_recovery. Generates
    /// a random master key, wraps under the password KEK (and optionally
    /// the recovery KEK), and writes the manifest.
    fn create_inner(
        bundle_path: impl AsRef<Path>,
        password: Secret<String>,
        recovery: Option<&RecoveryPhrase>,
        install: InstallId,
        kdf: KdfParams,
    ) -> Result<Self, VaultError> {
        // Generate all key material up front so the create_bundle call
        // is the only fallible I/O step and a crash between "wrap" and
        // "write" still leaves the filesystem untouched.
        let master = crypto::generate_master_key()?;

        let password_salt = crypto::generate_salt()?;
        let password_kek = crypto::derive_kek(&password, &password_salt, &kdf)?;

        // Recovery slot, if requested. Uses an independent salt so the
        // two KEKs are cryptographically unrelated even though they both
        // wrap the same master.
        let (recovery_salt, recovery_kek) = match recovery {
            Some(phrase) => {
                let salt = crypto::generate_salt()?;
                let kek = crypto::derive_kek(phrase.as_secret_string(), &salt, &kdf)?;
                (Some(salt), Some(kek))
            }
            None => (None, None),
        };

        let recovery_slot = match (&recovery_salt, &recovery_kek) {
            (Some(salt), Some(kek)) => Some(RecoverySlot {
                recovery_kek: kek,
                recovery_salt: salt,
                recovery_kdf: kdf,
            }),
            _ => None,
        };

        let inputs = NewManifestInputs {
            master: &master,
            password_kek: &password_kek,
            password_salt: &password_salt,
            password_kdf: kdf,
            recovery: recovery_slot,
        };

        let paths = create_bundle(bundle_path.as_ref(), inputs)?;

        let keys = crypto::derive_sub_keys(&master)?;

        Ok(Self {
            paths,
            keys,
            master,
            install,
            items: HashMap::new(),
            pending: Vec::new(),
            next_chunk_counter: 1,
            next_lamport: 1,
        })
    }

    /// Unlock an existing vault bundle at `bundle_path` with `password`.
    ///
    /// Flow:
    ///
    /// 1. Load `manifest.json`. Malformed JSON or a missing bundle
    ///    surface as [`UserActionableError::CorruptedManifest`] or
    ///    [`UserActionableError::VaultNotFound`] respectively — these
    ///    errors fire before the password is even touched, so they
    ///    cleanly distinguish tamper from wrong-password.
    /// 2. Reject unsupported format versions.
    /// 3. Derive the password KEK from `password` and the manifest's
    ///    password salt + KDF params. This is the slow step (argon2id).
    /// 4. Unwrap the stored master key with the KEK. An AEAD failure
    ///    here is what surfaces as `WrongPassword`.
    /// 5. Derive the encryption + MAC sub-keys from the master.
    /// 6. Verify the manifest MAC over the canonical body. Mismatch
    ///    here means a field outside the wrapped-key blob was tampered.
    /// 7. Read every chunk, decrypt, sort, fold into item state.
    /// 8. Seed the next-chunk counter from the highest counter already
    ///    on disk for this install.
    pub fn unlock(
        bundle_path: impl AsRef<Path>,
        password: Secret<String>,
        install: InstallId,
    ) -> Result<Self, VaultError> {
        let bundle = bundle_path.as_ref();
        let manifest = load_manifest(bundle)?;
        let salt = manifest.password_salt()?;
        let wrapped = manifest.password_wrapped_key()?;

        let kek = crypto::derive_kek(&password, &salt, &manifest.password_kdf)?;
        let master = crypto::unwrap_master_key(&kek, &wrapped)?;
        let keys = crypto::derive_sub_keys(&master)?;

        if manifest.verify(&keys).is_err() {
            return Err(UserActionableError::CorruptedManifest.into());
        }

        let paths = VaultPaths::for_bundle(bundle);
        Self::assemble_from_disk(paths, master, keys, install)
    }

    /// Unlock an existing vault using its BIP39 recovery phrase instead
    /// of the master password. The vault must have been created with
    /// recovery enabled; otherwise this returns
    /// [`UserActionableError::InvalidRecoveryPhrase`] (the recovery
    /// slot is empty, so there is nothing to unwrap).
    ///
    /// A correct phrase that doesn't match the stored wrap (e.g. the
    /// wrong vault) surfaces as `WrongPassword` — the two are
    /// cryptographically symmetric and the UI shows the right message
    /// based on which entry point the user took.
    pub fn unlock_with_recovery(
        bundle_path: impl AsRef<Path>,
        phrase: &RecoveryPhrase,
        install: InstallId,
    ) -> Result<Self, VaultError> {
        let bundle = bundle_path.as_ref();
        let manifest = load_manifest(bundle)?;

        let recovery_salt = manifest
            .recovery_salt()?
            .ok_or(UserActionableError::InvalidRecoveryPhrase)?;
        let wrapped = manifest
            .recovery_wrapped_key()?
            .ok_or(UserActionableError::InvalidRecoveryPhrase)?;
        let kdf = manifest
            .recovery_kdf
            .ok_or(UserActionableError::InvalidRecoveryPhrase)?;

        let kek = crypto::derive_kek(phrase.as_secret_string(), &recovery_salt, &kdf)?;
        let master = crypto::unwrap_master_key(&kek, &wrapped)?;
        let keys = crypto::derive_sub_keys(&master)?;

        if manifest.verify(&keys).is_err() {
            return Err(UserActionableError::CorruptedManifest.into());
        }

        let paths = VaultPaths::for_bundle(bundle);
        Self::assemble_from_disk(paths, master, keys, install)
    }

    /// Shared tail of unlock / unlock_with_recovery: read chunks,
    /// fold events, compute counters, build the Vault.
    fn assemble_from_disk(
        paths: VaultPaths,
        master: Secret<[u8; KEY_LEN]>,
        keys: Secret<DerivedKeys>,
        install: InstallId,
    ) -> Result<Self, VaultError> {
        let mut events = read_all_events(&paths, &keys)?;
        sort_events(&mut events);
        let items = fold_events(&events);

        let max_counter = max_counter_for_install(&paths, &install)?;
        let max_lamport = events
            .iter()
            .filter(|e| e.install_id == install.as_uuid())
            .map(|e| e.lamport)
            .max()
            .unwrap_or(0);

        Ok(Self {
            paths,
            master,
            keys,
            install,
            items,
            pending: Vec::new(),
            next_chunk_counter: max_counter
                .checked_add(1)
                .ok_or(BugInUnovaultError::ChunkCounterOverflow)?,
            next_lamport: max_lamport
                .checked_add(1)
                .ok_or(BugInUnovaultError::ChunkCounterOverflow)?,
        })
    }

    /// Verify that `password` is the current master password by
    /// re-deriving the KEK and attempting to unwrap the stored
    /// wrapped master key. Returns `Ok(true)` on success,
    /// `Ok(false)` on a mismatch, and `Err` on a bug or I/O
    /// failure reading the manifest.
    ///
    /// Used by the settings UI to gate rotation flows — the user
    /// proves they know the current password before we overwrite
    /// the password slot.
    pub fn verify_password(&self, password: &Secret<String>) -> Result<bool, VaultError> {
        let manifest = load_manifest(&self.paths.bundle)?;
        let salt = manifest.password_salt()?;
        let wrapped = manifest.password_wrapped_key()?;
        let kek = crypto::derive_kek(password, &salt, &manifest.password_kdf)?;
        match crypto::unwrap_master_key(&kek, &wrapped) {
            Ok(_) => Ok(true),
            Err(VaultError::UserActionable(UserActionableError::WrongPassword)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Whether this vault has a recovery slot.
    pub fn has_recovery(&self) -> Result<bool, VaultError> {
        let manifest = load_manifest(&self.paths.bundle)?;
        Ok(manifest.has_recovery())
    }

    /// Change the master password on an unlocked vault. Re-derives a
    /// new password KEK from `new_password`, re-wraps the existing
    /// master key, and rewrites `manifest.json` atomically. If the
    /// vault has a recovery slot it is preserved unchanged.
    ///
    /// The chunks directory is untouched — changing the password does
    /// NOT re-encrypt any existing chunk files. This is what makes
    /// rotation O(1) regardless of vault size.
    pub fn change_password(&mut self, new_password: Secret<String>) -> Result<(), VaultError> {
        let old_manifest = load_manifest(&self.paths.bundle)?;
        let kdf = old_manifest.password_kdf;

        let password_salt = crypto::generate_salt()?;
        let password_kek = crypto::derive_kek(&new_password, &password_salt, &kdf)?;

        let inputs = NewManifestInputs {
            master: &self.master,
            password_kek: &password_kek,
            password_salt: &password_salt,
            password_kdf: kdf,
            // change_password always drops the recovery slot from the
            // NewManifestInputs path — we splice the old slot back in
            // below if it existed.
            recovery: None,
        };

        let mut manifest = crate::format::VaultManifest::new(inputs)?;

        if old_manifest.has_recovery() {
            manifest.recovery_kdf = old_manifest.recovery_kdf;
            manifest.recovery_salt_b64 = old_manifest.recovery_salt_b64.clone();
            manifest.recovery_wrapped_key_b64 = old_manifest.recovery_wrapped_key_b64.clone();

            // Re-MAC over the canonical body with the recovery slot
            // restored.
            let sub_keys = crypto::derive_sub_keys(&self.master)?;
            manifest.manifest_mac_b64 = String::new();
            let canonical = serde_json::to_vec_pretty(&manifest)
                .map_err(|_| BugInUnovaultError::SelfSerializationFailure)?;
            let mac = crypto::compute_mac(&sub_keys, &canonical)?;
            manifest.manifest_mac_b64 = crypto::mac_to_base64(&mac);
        }

        crate::format::write_manifest_public(&self.paths, &manifest)
    }

    /// Add a fresh recovery phrase or rotate the existing one.
    /// Returns the new BIP39 phrase. Any prior recovery slot is
    /// replaced by this call.
    ///
    /// The master password slot is unchanged.
    pub fn rotate_recovery(&mut self) -> Result<RecoveryPhrase, VaultError> {
        let old_manifest = load_manifest(&self.paths.bundle)?;
        let kdf = old_manifest.password_kdf;

        let phrase = RecoveryPhrase::generate()?;
        let recovery_salt = crypto::generate_salt()?;
        let recovery_kek = crypto::derive_kek(phrase.as_secret_string(), &recovery_salt, &kdf)?;

        // Decode the existing password-wrapped key so we can write it
        // back into the new manifest unchanged — we don't have the
        // password here, so we can't re-wrap.
        let old_password_wrapped = old_manifest.password_wrapped_key_b64.clone();
        let old_password_salt = old_manifest.password_salt_b64.clone();
        let old_password_kdf = old_manifest.password_kdf;

        // Build a manifest from scratch with the new recovery slot but
        // copy the password slot verbatim (the helper wants a
        // password_kek even though we won't use its wrap).
        let throwaway_kek = Secret::new([0u8; KEY_LEN]);
        let mut manifest = crate::format::VaultManifest::new(NewManifestInputs {
            master: &self.master,
            password_kek: &throwaway_kek,
            password_salt: &[0u8; SALT_LEN],
            password_kdf: old_password_kdf,
            recovery: Some(RecoverySlot {
                recovery_kek: &recovery_kek,
                recovery_salt: &recovery_salt,
                recovery_kdf: kdf,
            }),
        })?;

        // Overwrite the password slot with the original wrap + salt.
        manifest.password_wrapped_key_b64 = old_password_wrapped;
        manifest.password_salt_b64 = old_password_salt;

        // Re-MAC over the canonical body after the splice.
        let sub_keys = crypto::derive_sub_keys(&self.master)?;
        manifest.manifest_mac_b64 = String::new();
        let canonical = serde_json::to_vec_pretty(&manifest)
            .map_err(|_| BugInUnovaultError::SelfSerializationFailure)?;
        let mac = crypto::compute_mac(&sub_keys, &canonical)?;
        manifest.manifest_mac_b64 = crypto::mac_to_base64(&mac);

        crate::format::write_manifest_public(&self.paths, &manifest)?;
        Ok(phrase)
    }

    /// Add a recovery slot to a vault that was created without one.
    /// Returns the fresh phrase. This is just [`Vault::rotate_recovery`]
    /// with a guard that refuses to clobber an existing slot.
    pub fn enable_recovery(&mut self) -> Result<RecoveryPhrase, VaultError> {
        let manifest = load_manifest(&self.paths.bundle)?;
        if manifest.has_recovery() {
            return Err(BugInUnovaultError::InvariantViolation(
                "enable_recovery called on a vault that already has a recovery slot",
            )
            .into());
        }
        self.rotate_recovery()
    }

    /// Add a new item to the vault. Returns its fresh ID.
    ///
    /// The change is queued in `pending` — call [`Vault::save`] to persist
    /// to disk. Fails with [`BugInUnovaultError::ChunkCounterOverflow`]
    /// if the lamport counter has been exhausted.
    pub fn add_item(&mut self, snapshot: ItemSnapshot) -> Result<ItemId, VaultError> {
        let id = ItemId::new();
        let timestamp_ms = current_timestamp_ms()?;
        let lamport = self.alloc_lamport()?;
        let event = Event::new(
            self.install.as_uuid(),
            lamport,
            timestamp_ms,
            Op::CreateItem {
                item_id: id,
                initial: snapshot.clone(),
            },
        );

        // Apply to in-memory state immediately so readers see the new item
        // without waiting for save().
        self.items
            .insert(id, ItemState::from_snapshot(id, snapshot, timestamp_ms));

        self.pending.push(event);
        Ok(id)
    }

    /// Update a single field on an existing item.
    ///
    /// Returns `Ok(false)` if the item does not exist (the call was a
    /// no-op), `Ok(true)` if the update was queued. A future version may
    /// prefer a dedicated `ItemNotFound` error variant; for now the bool
    /// return is the explicit "was this change actually recorded" signal
    /// callers need.
    pub fn set_field(
        &mut self,
        item_id: ItemId,
        field: FieldKey,
        value: FieldValue,
    ) -> Result<bool, VaultError> {
        if !self.items.contains_key(&item_id) {
            return Ok(false);
        }

        let timestamp_ms = current_timestamp_ms()?;
        let lamport = self.alloc_lamport()?;

        if let Some(item) = self.items.get_mut(&item_id) {
            item.apply_field_update(&field, value.clone(), timestamp_ms);
        }

        self.pending.push(Event::new(
            self.install.as_uuid(),
            lamport,
            timestamp_ms,
            Op::UpdateField {
                item_id,
                field,
                value,
            },
        ));
        Ok(true)
    }

    /// Iterate over every item currently in the vault. Order is arbitrary;
    /// the UI is responsible for sorting.
    pub fn items(&self) -> impl Iterator<Item = &ItemState> {
        self.items.values()
    }

    /// Number of items currently in the vault.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the vault has zero items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Look up a single item by id.
    pub fn get(&self, id: &ItemId) -> Option<&ItemState> {
        self.items.get(id)
    }

    /// Persist the pending event queue to a single chunk file. No-op if
    /// `pending` is empty.
    ///
    /// After a successful save the buffer is cleared and the chunk counter
    /// is advanced.
    pub fn save(&mut self) -> Result<(), VaultError> {
        if self.pending.is_empty() {
            return Ok(());
        }

        let counter = self.next_chunk_counter;
        write_chunk(
            &self.paths,
            &self.install,
            counter,
            &self.keys,
            &self.pending,
        )?;

        self.pending.clear();
        self.next_chunk_counter = counter
            .checked_add(1)
            .ok_or(BugInUnovaultError::ChunkCounterOverflow)?;

        Ok(())
    }

    /// Re-read every chunk file on disk and refold the in-memory
    /// item state. Pending (unsaved) events are preserved and folded
    /// on top of the re-read disk events, so a caller that was in
    /// the middle of edits does not lose them.
    ///
    /// Used by the sync path: after pulling new chunks from a
    /// backend, `refresh()` picks them up without requiring a full
    /// relock + reunlock cycle (which would re-run argon2id).
    ///
    /// Counters are re-seeded from whatever is on disk so a future
    /// `save()` continues numbering correctly even if the backend
    /// pulled chunks that advance our own install's max counter
    /// (normally it won't — our install only writes from this
    /// process — but we seed defensively).
    pub fn refresh(&mut self) -> Result<(), VaultError> {
        let mut disk_events = read_all_events(&self.paths, &self.keys)?;
        // Fold in the pending events so an in-flight edit survives
        // the refresh. Cloning is necessary because sort + fold
        // consume the list, and we need to keep `self.pending`
        // intact for a later save().
        disk_events.extend(self.pending.iter().cloned());
        sort_events(&mut disk_events);
        self.items = fold_events(&disk_events);

        // Re-seed the counters. `max_counter_for_install` scans the
        // chunks dir and only considers this install's filenames, so
        // pulling in someone else's chunks doesn't bump our counter.
        let max_counter = max_counter_for_install(&self.paths, &self.install)?;
        let next_counter = max_counter
            .checked_add(1)
            .ok_or(BugInUnovaultError::ChunkCounterOverflow)?;
        if next_counter > self.next_chunk_counter {
            self.next_chunk_counter = next_counter;
        }

        // Lamport counter tracks the max value we have ever seen
        // produced by our own install, not the merged stream. A
        // pulled chunk from another install cannot advance our
        // lamport because its events carry that other install's
        // lamport values; our tiebreaker rule in `Event::cmp`
        // handles cross-install ordering via install_id.
        let max_lamport = disk_events
            .iter()
            .filter(|e| e.install_id == self.install.as_uuid())
            .map(|e| e.lamport)
            .max()
            .unwrap_or(0);
        let next_lamport = max_lamport
            .checked_add(1)
            .ok_or(BugInUnovaultError::ChunkCounterOverflow)?;
        if next_lamport > self.next_lamport {
            self.next_lamport = next_lamport;
        }

        Ok(())
    }

    /// Push local chunks to the backend and pull missing backend
    /// chunks to local. Then call [`Vault::refresh`] so the
    /// in-memory state reflects anything that was pulled.
    ///
    /// Returns a summary of how many chunks moved in each direction.
    ///
    /// # Conflict model
    ///
    /// Chunks are content-addressed by filename: the per-install
    /// sharding key makes any two installs' filenames disjoint, so
    /// "push local to backend" and "pull backend to local" never
    /// overwrite anything. A file with the same name on both sides
    /// is assumed to be byte-identical and is skipped.
    ///
    /// # Failure semantics
    ///
    /// Errors short-circuit. A push that fails partway leaves the
    /// already-pushed chunks on the backend; a pull that fails
    /// partway leaves the already-pulled chunks on disk. Both
    /// states are valid restart points — the next sync picks up
    /// where the previous one left off because the comparison is
    /// by filename.
    ///
    /// # What chunks are valid to push
    ///
    /// The caller must call [`Vault::save`] first if there are
    /// pending edits — we do not implicitly save here because
    /// callers may want to batch rotations and sync separately.
    /// An `Err(InvariantViolation)` would be a loud way to catch
    /// the forgotten-save case; for now we silently sync only what
    /// is on disk and trust the caller.
    pub fn sync_with_backend(
        &mut self,
        backend: &dyn FileSystemBackend,
    ) -> Result<SyncSummary, VaultError> {
        let local_names = list_chunk_filenames(&self.paths)?;
        let remote_names = backend.list()?;

        let local_set: std::collections::HashSet<String> = local_names.iter().cloned().collect();
        let remote_set: std::collections::HashSet<String> = remote_names.iter().cloned().collect();

        // Push: every local filename not already on the backend.
        let mut pushed = 0u32;
        for name in &local_names {
            if !remote_set.contains(name) {
                let bytes = read_chunk_raw(&self.paths, name)?;
                backend.write(name, &bytes)?;
                pushed = pushed.saturating_add(1);
            }
        }

        // Pull: every backend filename not already local.
        let mut pulled = 0u32;
        for name in &remote_names {
            if !local_set.contains(name) {
                let bytes = backend.read(name)?;
                write_chunk_raw(&self.paths, name, &bytes)?;
                pulled = pulled.saturating_add(1);
            }
        }

        if pulled > 0 {
            self.refresh()?;
        }

        Ok(SyncSummary { pushed, pulled })
    }

    /// Path of the vault bundle on disk.
    pub fn bundle_path(&self) -> &Path {
        &self.paths.bundle
    }

    /// Path of the vault bundle as an owned [`PathBuf`]. Convenience for
    /// callers that need to store the path after the vault has been moved
    /// or dropped.
    pub fn bundle_path_owned(&self) -> PathBuf {
        self.paths.bundle.clone()
    }

    /// Number of unsaved events in the pending queue. Exposed for tests
    /// and diagnostics; callers should generally treat this as an internal
    /// detail and call [`Vault::save`] rather than depend on the count.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Install identifier used for writing new chunks.
    pub fn install(&self) -> &InstallId {
        &self.install
    }

    /// Allocate the next lamport counter value for this install.
    ///
    /// Returns `Err(BugInUnovaultError::ChunkCounterOverflow)` if the
    /// counter has reached `u64::MAX` — at ~1.8×10^19 writes this is
    /// effectively impossible, but checking rather than saturating keeps
    /// the invariant that two events from the same install never share a
    /// lamport value. Saturation would silently produce equal lamports
    /// and break the LWW tiebreaker in [`Event::cmp`](crate::Event::cmp).
    fn alloc_lamport(&mut self) -> Result<u64, VaultError> {
        let v = self.next_lamport;
        self.next_lamport = self
            .next_lamport
            .checked_add(1)
            .ok_or(BugInUnovaultError::ChunkCounterOverflow)?;
        Ok(v)
    }
}

/// Manual `Debug` impl that never leaks derived key material. `Vault`
/// deliberately does not derive `Debug` because it holds `Secret<DerivedKeys>`,
/// and we want the formatted representation to be informative for diagnostics
/// without ever rendering the keys.
impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("bundle_path", &self.paths.bundle)
            .field("install", &self.install)
            .field("items", &self.items.len())
            .field("pending", &self.pending.len())
            .field("next_chunk_counter", &self.next_chunk_counter)
            .field("keys", &"<redacted>")
            .finish()
    }
}

/// Current wall-clock time as milliseconds since Unix epoch.
///
/// Returns [`BugInUnovaultError::InvariantViolation`] if the system clock
/// is before the epoch — this indicates a badly misconfigured machine and
/// would previously have produced silent `timestamp_ms = 0` events, which
/// an attacker with clock control could exploit to pin every new event's
/// `created_at_ms` to 0. Failing loudly is safer.
///
/// The `u128 -> u64` cast is safe until year 584_556_019; no validation
/// added for that.
fn current_timestamp_ms() -> Result<u64, VaultError> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BugInUnovaultError::InvariantViolation("system clock is before Unix epoch"))?
        .as_millis();
    // Saturating cast is fine here: u128 → u64 only overflows in year
    // 584_556_019, which is not a realistic failure mode.
    Ok(u64::try_from(ms).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format;
    use tempfile::tempdir;

    fn snap(title: &str) -> ItemSnapshot {
        ItemSnapshot {
            title: title.into(),
            kind: ItemKind::Password,
            username: Some(format!("user-{title}")),
            url: Some(format!("https://{title}.test")),
        }
    }

    #[test]
    fn create_empty_vault_has_zero_items() {
        let dir = tempdir().expect("tempdir");
        let vault = Vault::create_for_tests(
            dir.path().join("empty.unovault"),
            Secret::new(String::from("hunter2")),
            InstallId::new(),
        )
        .expect("create");

        assert!(vault.is_empty());
        assert_eq!(vault.len(), 0);
        assert_eq!(vault.pending_count(), 0);
    }

    #[test]
    fn add_item_appears_in_items_iterator_and_queues_event() {
        let dir = tempdir().expect("tempdir");
        let mut vault = Vault::create_for_tests(
            dir.path().join("add.unovault"),
            Secret::new(String::from("hunter2")),
            InstallId::new(),
        )
        .expect("create");

        let id = vault.add_item(snap("GitHub")).expect("add");
        assert_eq!(vault.len(), 1);
        assert_eq!(vault.pending_count(), 1);

        let item = vault.get(&id).expect("item should exist");
        assert_eq!(item.title, "GitHub");
        assert_eq!(item.kind, ItemKind::Password);
    }

    #[test]
    fn save_flushes_pending_and_clears_queue() {
        let dir = tempdir().expect("tempdir");
        let mut vault = Vault::create_for_tests(
            dir.path().join("save.unovault"),
            Secret::new(String::from("hunter2")),
            InstallId::new(),
        )
        .expect("create");

        vault.add_item(snap("A")).expect("add a");
        vault.add_item(snap("B")).expect("add b");
        assert_eq!(vault.pending_count(), 2);

        vault.save().expect("save");
        assert_eq!(vault.pending_count(), 0);
        assert_eq!(vault.len(), 2, "save should not drop in-memory state");
    }

    #[test]
    fn save_with_empty_pending_is_noop() {
        let dir = tempdir().expect("tempdir");
        let mut vault = Vault::create_for_tests(
            dir.path().join("noop.unovault"),
            Secret::new(String::from("hunter2")),
            InstallId::new(),
        )
        .expect("create");

        vault.save().expect("first save");
        vault.save().expect("second save");
        assert_eq!(vault.pending_count(), 0);
    }

    #[test]
    fn set_field_updates_in_memory_state() {
        let dir = tempdir().expect("tempdir");
        let mut vault = Vault::create_for_tests(
            dir.path().join("setfield.unovault"),
            Secret::new(String::from("hunter2")),
            InstallId::new(),
        )
        .expect("create");

        let id = vault.add_item(snap("GitHub")).expect("add");
        let set_password = vault
            .set_field(
                id,
                FieldKey::Password,
                FieldValue::Bytes(b"hunter2".to_vec()),
            )
            .expect("set password");
        assert!(
            set_password,
            "set_field should report success for existing item"
        );
        vault
            .set_field(id, FieldKey::Notes, FieldValue::Text("main dev".into()))
            .expect("set notes");

        let item = vault.get(&id).expect("item");
        assert_eq!(item.password.as_deref(), Some(b"hunter2".as_slice()));
        assert_eq!(item.notes.as_deref(), Some("main dev"));
    }

    #[test]
    fn set_field_on_unknown_item_returns_false_and_is_noop() {
        let dir = tempdir().expect("tempdir");
        let mut vault = Vault::create_for_tests(
            dir.path().join("noop2.unovault"),
            Secret::new(String::from("hunter2")),
            InstallId::new(),
        )
        .expect("create");

        let fake_id = ItemId::new();
        let applied = vault
            .set_field(fake_id, FieldKey::Title, FieldValue::Text("ghost".into()))
            .expect("set_field");
        assert!(!applied, "set_field should report false for unknown item");
        assert_eq!(vault.pending_count(), 0);
        assert!(vault.is_empty());
    }

    #[test]
    fn unlock_with_wrong_password_returns_wrong_password_error() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("wrongpw.unovault");
        let install = InstallId::new();

        {
            let mut vault =
                Vault::create_for_tests(&path, Secret::new(String::from("correct")), install)
                    .expect("create");
            vault.add_item(snap("anything")).expect("add");
            vault.save().expect("save");
        }

        match Vault::unlock(&path, Secret::new(String::from("wrong")), install) {
            Err(VaultError::UserActionable(UserActionableError::WrongPassword)) => {}
            other => panic!("expected WrongPassword, got {other:?}"),
        }
    }

    #[test]
    fn unlock_missing_vault_returns_vault_not_found() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist.unovault");
        let install = InstallId::new();
        match Vault::unlock(&missing, Secret::new(String::from("hunter2")), install) {
            Err(VaultError::UserActionable(UserActionableError::VaultNotFound)) => {}
            other => panic!("expected VaultNotFound, got {other:?}"),
        }
    }

    /// The Week 4 Go/No-Go gate test.
    ///
    /// Create a vault, add three items, save, close. Open with the same
    /// password and verify all three items come back with their fields
    /// intact. If this passes on the builder's M-series Mac, week 4 is
    /// go. If not, pivot to Approach E (menu bar launcher).
    #[test]
    fn week_4_gate_save_and_reopen_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("week4.unovault");
        let install = InstallId::new();
        let password = String::from("correct horse battery staple");

        // Phase 1: create, populate, save.
        let ids = {
            let mut vault = Vault::create_for_tests(&path, Secret::new(password.clone()), install)
                .expect("create");

            let github = vault.add_item(snap("GitHub")).expect("add github");
            vault
                .set_field(
                    github,
                    FieldKey::Password,
                    FieldValue::Bytes(b"gh-secret-42".to_vec()),
                )
                .expect("set github password");
            vault
                .set_field(
                    github,
                    FieldKey::Notes,
                    FieldValue::Text("main dev account".into()),
                )
                .expect("set github notes");

            let google = vault.add_item(snap("Google")).expect("add google");
            vault
                .set_field(
                    google,
                    FieldKey::Password,
                    FieldValue::Bytes(b"g00gl3-secret".to_vec()),
                )
                .expect("set google password");

            let toss = vault.add_item(snap("Toss")).expect("add toss");
            vault
                .set_field(
                    toss,
                    FieldKey::Username,
                    FieldValue::Text("010-1234".into()),
                )
                .expect("set toss username");

            vault.save().expect("save");
            assert_eq!(vault.len(), 3);
            assert_eq!(vault.pending_count(), 0);

            (github, google, toss)
        };
        // Vault dropped here — keys are zeroized.

        // Phase 2: reopen with the same password.
        let reopened =
            Vault::unlock(&path, Secret::new(password), install).expect("unlock should succeed");

        assert_eq!(reopened.len(), 3);

        let gh = reopened.get(&ids.0).expect("GitHub item");
        assert_eq!(gh.title, "GitHub");
        assert_eq!(gh.password.as_deref(), Some(b"gh-secret-42".as_slice()));
        assert_eq!(gh.notes.as_deref(), Some("main dev account"));

        let g = reopened.get(&ids.1).expect("Google item");
        assert_eq!(g.title, "Google");
        assert_eq!(g.password.as_deref(), Some(b"g00gl3-secret".as_slice()));

        let t = reopened.get(&ids.2).expect("Toss item");
        assert_eq!(t.title, "Toss");
        assert_eq!(t.username.as_deref(), Some("010-1234"));
    }

    #[test]
    fn second_save_writes_a_second_chunk() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("twochunks.unovault");
        let install = InstallId::new();

        let mut vault =
            Vault::create_for_tests(&path, Secret::new(String::from("hunter2")), install)
                .expect("create");
        vault.add_item(snap("first")).expect("add first");
        vault.save().expect("save 1");
        vault.add_item(snap("second")).expect("add second");
        vault.save().expect("save 2");

        let paths = VaultPaths::for_bundle(&path);
        let files = format::list_chunk_files(&paths).expect("list");
        assert_eq!(files.len(), 2);

        // Reopen and verify both items come back.
        drop(vault);
        let reopened =
            Vault::unlock(&path, Secret::new(String::from("hunter2")), install).expect("unlock");
        assert_eq!(reopened.len(), 2);
    }

    #[test]
    fn reopen_after_many_field_updates_sees_latest_value() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("lww.unovault");
        let install = InstallId::new();

        let id = {
            let mut vault =
                Vault::create_for_tests(&path, Secret::new(String::from("hunter2")), install)
                    .expect("create");

            let id = vault.add_item(snap("Twitter")).expect("add");
            vault
                .set_field(id, FieldKey::Notes, FieldValue::Text("first".into()))
                .expect("notes 1");
            vault
                .set_field(id, FieldKey::Notes, FieldValue::Text("second".into()))
                .expect("notes 2");
            vault
                .set_field(id, FieldKey::Notes, FieldValue::Text("third".into()))
                .expect("notes 3");
            vault.save().expect("save");
            id
        };

        let reopened =
            Vault::unlock(&path, Secret::new(String::from("hunter2")), install).expect("unlock");
        let item = reopened.get(&id).expect("item");
        assert_eq!(
            item.notes.as_deref(),
            Some("third"),
            "LWW should preserve only the latest UpdateField value"
        );
    }

    /// QA gap fill: unlock a vault that has a manifest but zero chunk
    /// files. This happens any time a vault is created and closed before
    /// the first `save()`. The unlock must succeed and yield zero items.
    #[test]
    fn unlock_empty_vault_without_chunks() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("empty-roundtrip.unovault");
        let install = InstallId::new();

        {
            let _vault =
                Vault::create_for_tests(&path, Secret::new(String::from("hunter2")), install)
                    .expect("create");
            // Drop without saving — no chunks written.
        }

        let reopened =
            Vault::unlock(&path, Secret::new(String::from("hunter2")), install).expect("unlock");
        assert!(reopened.is_empty());
        assert_eq!(reopened.len(), 0);
    }

    /// QA gap fill: two separate installs write items to the same vault
    /// bundle. After unlock on either install, LWW merge must include all
    /// items from both sources. This exercises the multi-device story
    /// end-to-end through the real `Vault` API, not just the sort layer.
    #[test]
    fn cross_install_lww_merge_end_to_end() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("cross-install.unovault");
        let install_a = InstallId::new();
        let install_b = InstallId::new();
        let password = String::from("hunter2");

        // Install A creates the vault and adds two items.
        let (a1, a2) = {
            let mut vault_a =
                Vault::create_for_tests(&path, Secret::new(password.clone()), install_a)
                    .expect("create a");
            let a1 = vault_a.add_item(snap("GitHub")).expect("a1");
            let a2 = vault_a.add_item(snap("Google")).expect("a2");
            vault_a.save().expect("save a");
            (a1, a2)
        };

        // Install B opens the same bundle (simulating iCloud delivery of
        // install_a's chunk) and adds its own item + updates one of A's.
        let b1 = {
            let mut vault_b =
                Vault::unlock(&path, Secret::new(password.clone()), install_b).expect("unlock b");
            assert_eq!(vault_b.len(), 2, "install B should see install A's items");

            let b1 = vault_b.add_item(snap("Toss")).expect("b1");
            vault_b
                .set_field(
                    a1,
                    FieldKey::Notes,
                    FieldValue::Text("from install B".into()),
                )
                .expect("set notes from b");
            vault_b.save().expect("save b");
            b1
        };

        // Install A re-opens and sees all three items plus the note added
        // by install B.
        let vault_a = Vault::unlock(&path, Secret::new(password), install_a).expect("reopen a");
        assert_eq!(
            vault_a.len(),
            3,
            "install A should see all three items after merge"
        );
        assert!(vault_a.get(&a1).is_some());
        assert!(vault_a.get(&a2).is_some());
        assert!(vault_a.get(&b1).is_some());

        let gh = vault_a.get(&a1).expect("github item");
        assert_eq!(
            gh.notes.as_deref(),
            Some("from install B"),
            "install A must see the note that install B wrote"
        );
    }

    /// QA gap fill: prove the manual ItemState::Debug impl redacts both
    /// password and totp_secret. This is the compile-time-ish guarantee
    /// that a future `tracing::debug!("{item:?}")` will not leak secrets.
    #[test]
    fn item_state_debug_impl_redacts_secrets() {
        let mut item = ItemState::from_snapshot(
            ItemId::new(),
            ItemSnapshot {
                title: "GitHub".into(),
                kind: ItemKind::Password,
                username: Some("james".into()),
                url: Some("github.com".into()),
            },
            0,
        );
        item.password = Some(b"hunter2".to_vec());
        item.totp_secret = Some(b"JBSWY3DPEHPK3PXP".to_vec());
        item.notes = Some("main dev account".into());

        let debug = format!("{item:?}");
        assert!(!debug.contains("hunter2"), "password leaked: {debug}");
        assert!(!debug.contains("JBSWY3DPEHPK3PXP"), "totp leaked: {debug}");
        assert!(!debug.contains("main dev account"), "notes leaked: {debug}");
        assert!(debug.contains("redacted"));
        // Non-secret fields are still visible for diagnostics.
        assert!(debug.contains("GitHub"));
        assert!(debug.contains("james"));
    }

    /// QA gap fill: prove the manual FieldValue::Debug impl redacts Bytes
    /// while leaving Text visible.
    #[test]
    fn field_value_debug_impl_redacts_bytes_only() {
        let bytes = FieldValue::Bytes(b"super secret".to_vec());
        let text = FieldValue::Text("public-username".into());
        assert!(!format!("{bytes:?}").contains("super secret"));
        assert!(format!("{bytes:?}").contains("redacted"));
        assert!(format!("{text:?}").contains("public-username"));
    }

    #[test]
    fn fold_events_drops_updates_to_tombstoned_items() {
        let install = InstallId::new();
        let id = ItemId::new();
        let events = vec![
            Event::new(
                install.as_uuid(),
                1,
                1,
                Op::CreateItem {
                    item_id: id,
                    initial: snap("gone"),
                },
            ),
            Event::new(
                install.as_uuid(),
                2,
                2,
                Op::UpdateField {
                    item_id: id,
                    field: FieldKey::Notes,
                    value: FieldValue::Text("before delete".into()),
                },
            ),
            Event::new(install.as_uuid(), 3, 3, Op::DeleteItem { item_id: id }),
            Event::new(
                install.as_uuid(),
                4,
                4,
                Op::UpdateField {
                    item_id: id,
                    field: FieldKey::Notes,
                    value: FieldValue::Text("after delete".into()),
                },
            ),
        ];

        let state = fold_events(&events);
        assert!(
            !state.contains_key(&id),
            "tombstoned item must not appear in folded state"
        );
    }

    // =========================================================================
    // Week 17 — recovery kit + password rotation tests
    // =========================================================================

    #[test]
    fn create_with_recovery_returns_a_24_word_phrase_and_opens() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("recovery.unovault");
        let install = InstallId::new();
        let (mut vault, phrase) = Vault::create_with_recovery_for_tests(
            &path,
            Secret::new(String::from("hunter2")),
            install,
        )
        .expect("create with recovery");
        assert_eq!(phrase.word_count(), 24);
        vault.save().expect("save empty");
    }

    #[test]
    fn recovery_phrase_unlocks_the_vault_when_password_unknown() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("recovery-unlock.unovault");
        let install = InstallId::new();

        let (phrase, original_id) = {
            let (mut vault, phrase) = Vault::create_with_recovery_for_tests(
                &path,
                Secret::new(String::from("the-password-we-will-forget")),
                install,
            )
            .expect("create");
            let id = vault.add_item(snap("GitHub")).expect("add");
            vault
                .set_field(
                    id,
                    FieldKey::Password,
                    FieldValue::Bytes(b"gh-secret".to_vec()),
                )
                .expect("set pw");
            vault.save().expect("save");
            (phrase, id)
        };

        // Unlock via the recovery phrase instead of the forgotten
        // password. The item should come back intact.
        let recovered =
            Vault::unlock_with_recovery(&path, &phrase, install).expect("recovery unlock");
        let item = recovered.get(&original_id).expect("item");
        assert_eq!(item.title, "GitHub");
        assert_eq!(item.password.as_deref(), Some(b"gh-secret".as_slice()));
    }

    #[test]
    fn recovery_unlock_rejects_wrong_phrase_as_wrong_password() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("wrong-phrase.unovault");
        let install = InstallId::new();
        let (_vault, _phrase) = Vault::create_with_recovery_for_tests(
            &path,
            Secret::new(String::from("hunter2")),
            install,
        )
        .expect("create");

        let other = crate::recovery::RecoveryPhrase::generate().expect("other phrase");
        match Vault::unlock_with_recovery(&path, &other, install) {
            Err(VaultError::UserActionable(UserActionableError::WrongPassword)) => {}
            other_err => panic!("expected WrongPassword, got {other_err:?}"),
        }
    }

    #[test]
    fn recovery_unlock_on_vault_without_recovery_errors() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("no-recovery.unovault");
        let install = InstallId::new();
        let _vault = Vault::create_for_tests(&path, Secret::new(String::from("hunter2")), install)
            .expect("create");

        let phrase = crate::recovery::RecoveryPhrase::generate().expect("phrase");
        match Vault::unlock_with_recovery(&path, &phrase, install) {
            Err(VaultError::UserActionable(UserActionableError::InvalidRecoveryPhrase)) => {}
            other => panic!("expected InvalidRecoveryPhrase, got {other:?}"),
        }
    }

    #[test]
    fn change_password_lets_the_new_password_unlock() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("rotate-pw.unovault");
        let install = InstallId::new();

        {
            let mut vault =
                Vault::create_for_tests(&path, Secret::new(String::from("old-password")), install)
                    .expect("create");
            vault
                .change_password(Secret::new(String::from("new-password")))
                .expect("change password");
        }

        // New password works.
        let ok = Vault::unlock(&path, Secret::new(String::from("new-password")), install);
        assert!(ok.is_ok(), "new password must unlock: {ok:?}");

        // Old password no longer works.
        match Vault::unlock(&path, Secret::new(String::from("old-password")), install) {
            Err(VaultError::UserActionable(UserActionableError::WrongPassword)) => {}
            other => panic!("expected WrongPassword, got {other:?}"),
        }
    }

    #[test]
    fn change_password_preserves_the_existing_recovery_slot() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("rotate-keep-recovery.unovault");
        let install = InstallId::new();

        let phrase = {
            let (mut vault, phrase) = Vault::create_with_recovery_for_tests(
                &path,
                Secret::new(String::from("old-password")),
                install,
            )
            .expect("create");
            vault
                .change_password(Secret::new(String::from("new-password")))
                .expect("change password");
            phrase
        };

        // The recovery phrase must still work after the rotation.
        let recovered = Vault::unlock_with_recovery(&path, &phrase, install);
        assert!(
            recovered.is_ok(),
            "recovery slot should survive password change: {recovered:?}"
        );
    }

    #[test]
    fn rotate_recovery_replaces_the_phrase() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("rotate-recovery.unovault");
        let install = InstallId::new();

        let (old_phrase, new_phrase) = {
            let (mut vault, old_phrase) = Vault::create_with_recovery_for_tests(
                &path,
                Secret::new(String::from("hunter2")),
                install,
            )
            .expect("create");
            let new_phrase = vault.rotate_recovery().expect("rotate recovery");
            (old_phrase, new_phrase)
        };

        assert_ne!(old_phrase.expose(), new_phrase.expose());

        // Old phrase no longer works.
        match Vault::unlock_with_recovery(&path, &old_phrase, install) {
            Err(VaultError::UserActionable(UserActionableError::WrongPassword)) => {}
            other => panic!("expected WrongPassword on old phrase, got {other:?}"),
        }

        // New phrase works.
        let ok = Vault::unlock_with_recovery(&path, &new_phrase, install);
        assert!(ok.is_ok(), "new recovery phrase must unlock: {ok:?}");
    }

    #[test]
    fn rotate_recovery_preserves_the_password_slot() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("rotate-recovery-keeps-pw.unovault");
        let install = InstallId::new();

        {
            let (mut vault, _phrase) = Vault::create_with_recovery_for_tests(
                &path,
                Secret::new(String::from("hunter2")),
                install,
            )
            .expect("create");
            let _new_phrase = vault.rotate_recovery().expect("rotate");
        }

        let ok = Vault::unlock(&path, Secret::new(String::from("hunter2")), install);
        assert!(
            ok.is_ok(),
            "password slot must survive recovery rotation: {ok:?}"
        );
    }

    #[test]
    fn enable_recovery_on_a_vault_without_one_adds_a_slot() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("enable-recovery.unovault");
        let install = InstallId::new();

        let phrase = {
            let mut vault =
                Vault::create_for_tests(&path, Secret::new(String::from("hunter2")), install)
                    .expect("create");
            vault.enable_recovery().expect("enable")
        };

        let ok = Vault::unlock_with_recovery(&path, &phrase, install);
        assert!(ok.is_ok(), "newly-added recovery must unlock: {ok:?}");
    }

    #[test]
    fn enable_recovery_refuses_when_slot_already_exists() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("double-enable.unovault");
        let install = InstallId::new();

        let (mut vault, _phrase) = Vault::create_with_recovery_for_tests(
            &path,
            Secret::new(String::from("hunter2")),
            install,
        )
        .expect("create");

        match vault.enable_recovery() {
            Err(VaultError::BugInUnovault(_)) => {}
            other => panic!("expected BugInUnovault, got {other:?}"),
        }
    }

    // =========================================================================
    // Week 22-23 — sync with FileSystemBackend
    // =========================================================================

    use crate::sync::local::LocalBackend;

    #[test]
    fn sync_pushes_local_chunks_to_an_empty_backend() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("push.unovault");
        let install = InstallId::new();

        let mut vault =
            Vault::create_for_tests(&path, Secret::new("hunter2".into()), install).expect("create");
        vault.add_item(snap("GitHub")).expect("add");
        vault.save().expect("save");
        vault.add_item(snap("Gmail")).expect("add 2");
        vault.save().expect("save 2");

        // Two local chunks, empty backend.
        let backend_dir = tempdir().expect("backend tempdir");
        let backend = LocalBackend::new(backend_dir.path()).expect("backend");
        assert!(backend.list().expect("list").is_empty());

        let summary = vault.sync_with_backend(&backend).expect("sync");
        assert_eq!(summary.pushed, 2);
        assert_eq!(summary.pulled, 0);

        // Both chunks should now live on the backend.
        let remote = backend.list().expect("list post-push");
        assert_eq!(remote.len(), 2);
    }

    #[test]
    fn sync_is_idempotent_when_both_sides_already_agree() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("idem.unovault");
        let install = InstallId::new();

        let mut vault =
            Vault::create_for_tests(&path, Secret::new("hunter2".into()), install).expect("create");
        vault.add_item(snap("Item")).expect("add");
        vault.save().expect("save");

        let backend_dir = tempdir().expect("backend tempdir");
        let backend = LocalBackend::new(backend_dir.path()).expect("backend");
        let first = vault.sync_with_backend(&backend).expect("first sync");
        assert_eq!(first.pushed, 1);

        // Second sync is a no-op.
        let second = vault.sync_with_backend(&backend).expect("second sync");
        assert_eq!(second.pushed, 0);
        assert_eq!(second.pulled, 0);
    }

    #[test]
    fn sync_pulls_chunks_from_backend_that_another_install_wrote() {
        // Install A writes items, pushes to a shared backend.
        // Install B starts with an empty vault, pulls from the
        // backend, and should see every item A wrote.
        let backend_dir = tempdir().expect("shared backend");
        let backend = LocalBackend::new(backend_dir.path()).expect("backend");

        let a_dir = tempdir().expect("a dir");
        let a_path = a_dir.path().join("a.unovault");
        let a_install = InstallId::new();
        {
            let mut a = Vault::create_for_tests(&a_path, Secret::new("pw".into()), a_install)
                .expect("a create");
            a.add_item(snap("GitHub")).expect("gh");
            a.add_item(snap("Gmail")).expect("gm");
            a.save().expect("a save");
            a.sync_with_backend(&backend).expect("a push");
        }

        // Install B uses the **same password** so its derived keys
        // match. In real sync this would be handled by the
        // master-password-wrapping layer; we use identical
        // passwords here to isolate the sync behaviour.
        //
        // The two vaults also need identical manifest-level keys.
        // To get that in v2 (where the master key is random), B
        // must be constructed from A's bundle, not its own fresh
        // creation. The realistic workflow: the user copies the
        // whole `.unovault` folder from device A to device B (or
        // iCloud does it for them), then opens it with the same
        // password. We simulate this by cloning A's bundle into B.
        let b_dir = tempdir().expect("b dir");
        let b_path = b_dir.path().join("b.unovault");
        copy_bundle_recursive(&a_path, &b_path);

        // B uses a fresh install id so its future writes don't
        // collide with A's.
        let b_install = InstallId::new();
        let mut b = Vault::unlock(&b_path, Secret::new("pw".into()), b_install).expect("b unlock");
        assert_eq!(b.len(), 2, "B should see A's items after unlock");

        // Now have A write a new item and push again.
        let mut a = Vault::unlock(&a_path, Secret::new("pw".into()), a_install).expect("a unlock");
        a.add_item(snap("NewItem")).expect("new");
        a.save().expect("save new");
        a.sync_with_backend(&backend).expect("a push new");

        // B syncs and should pick up the new item.
        let summary = b.sync_with_backend(&backend).expect("b sync");
        assert!(summary.pulled >= 1, "B should pull at least one new chunk");
        assert_eq!(b.len(), 3, "B should now see all three items");
    }

    #[test]
    fn refresh_picks_up_chunks_written_externally() {
        // Simulates "iCloud delivered a new chunk underneath us
        // while we were running." The test writes a chunk
        // out-of-band through the format module, then calls
        // refresh() and verifies the new item appears.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("refresh.unovault");
        let install = InstallId::new();

        let mut vault =
            Vault::create_for_tests(&path, Secret::new("hunter2".into()), install).expect("create");
        vault.add_item(snap("Local")).expect("local add");
        vault.save().expect("local save");
        assert_eq!(vault.len(), 1);

        // Generate a chunk from a different install id — simulates
        // "another device wrote this file into our bundle."
        let other_install = InstallId::new();
        let external_id = ItemId::new();
        let external_event = Event::new(
            other_install.as_uuid(),
            1,
            current_timestamp_ms().expect("ts"),
            Op::CreateItem {
                item_id: external_id,
                initial: snap("External"),
            },
        );
        // Re-use the same keys — in production the sync layer
        // trusts that the backend only carries chunks encrypted
        // under the same master.
        let bytes = crate::format::encode_chunk_bytes(&vault.keys, &[external_event])
            .expect("encode external");
        let filename = format::VaultPaths::chunk_filename(1, &other_install);
        let external_chunk = vault.paths.chunks_dir.join(&filename);
        std::fs::write(&external_chunk, &bytes).expect("drop chunk");

        // Before refresh: still only the local item.
        assert_eq!(vault.len(), 1);

        vault.refresh().expect("refresh");
        assert_eq!(vault.len(), 2, "refresh should surface the external item");
        assert!(vault.get(&external_id).is_some());
    }

    #[test]
    fn sync_converges_two_vaults_under_chaos_reorder() {
        // Two vaults, both hold their own install id. Each writes
        // a few items and pushes to a shared chaos-wrapped backend.
        // After full reveal, both sides pull + refresh and must
        // end up with identical item sets.
        use crate::sync::chaos::ChaosBackend;

        let backend_dir = tempdir().expect("backend");
        let local_backend = LocalBackend::new(backend_dir.path()).expect("local");
        // Wrap in chaos so list() returns shuffled results. For
        // this convergence test we don't hide any files — LWW
        // convergence is what we're proving, not delivery
        // eventuality (which the existing chaos tests already
        // prove).
        let backend = ChaosBackend::new(Box::new(local_backend), 0xC0FFEE);

        // A's initial bundle — both vaults must share the same
        // master key, so we clone A's bundle to create B.
        let a_dir = tempdir().expect("a");
        let a_path = a_dir.path().join("a.unovault");
        let a_install = InstallId::new();
        {
            let mut a = Vault::create_for_tests(&a_path, Secret::new("pw".into()), a_install)
                .expect("a create");
            a.save().expect("a empty save noop");
        }
        let b_dir = tempdir().expect("b");
        let b_path = b_dir.path().join("b.unovault");
        copy_bundle_recursive(&a_path, &b_path);
        let b_install = InstallId::new();

        let mut a = Vault::unlock(&a_path, Secret::new("pw".into()), a_install).expect("a unlock");
        let mut b = Vault::unlock(&b_path, Secret::new("pw".into()), b_install).expect("b unlock");

        // A writes three items and pushes.
        a.add_item(snap("A1")).expect("a1");
        a.add_item(snap("A2")).expect("a2");
        a.add_item(snap("A3")).expect("a3");
        a.save().expect("a save");
        a.sync_with_backend(&backend).expect("a push");

        // B writes two items and pushes.
        b.add_item(snap("B1")).expect("b1");
        b.add_item(snap("B2")).expect("b2");
        b.save().expect("b save");
        b.sync_with_backend(&backend).expect("b push");

        // Both sides sync again — each pulls the other's chunks.
        a.sync_with_backend(&backend).expect("a pull");
        b.sync_with_backend(&backend).expect("b pull");

        // Both vaults should now hold all five items. The titles
        // are a stable fingerprint to compare against.
        assert_eq!(a.len(), 5);
        assert_eq!(b.len(), 5);

        let mut a_titles: Vec<_> = a.items().map(|i| i.title.clone()).collect();
        let mut b_titles: Vec<_> = b.items().map(|i| i.title.clone()).collect();
        a_titles.sort();
        b_titles.sort();
        assert_eq!(a_titles, b_titles, "LWW must converge across installs");
        assert_eq!(a_titles, vec!["A1", "A2", "A3", "B1", "B2"]);
    }

    // =========================================================================
    // Week 23 — two-install LWW convergence property test
    // =========================================================================

    /// One action a random test case can apply to a vault. Small
    /// closed set so the proptest space stays tractable and every
    /// operation is meaningful to fold/merge.
    #[derive(Debug, Clone)]
    enum Action {
        AddItem(String),
        SetNotes(usize, String),
    }

    fn apply_action(vault: &mut Vault, action: &Action, known_ids: &mut Vec<ItemId>) {
        match action {
            Action::AddItem(title) => {
                if let Ok(id) = vault.add_item(snap(title)) {
                    known_ids.push(id);
                }
            }
            Action::SetNotes(idx, text) => {
                if known_ids.is_empty() {
                    return;
                }
                let id = known_ids[*idx % known_ids.len()];
                let _ = vault.set_field(id, FieldKey::Notes, FieldValue::Text(text.clone()));
            }
        }
    }

    /// Turn a packed `u32` seed into a typed [`Action`]. The low
    /// bits pick the variant, the next bits pick an item index,
    /// and the remaining bits seed a short lowercase title.
    fn action_from_seed(seed: u32) -> Action {
        let variant = seed & 0x1;
        let idx = ((seed >> 1) & 0xFF) as usize;
        let word_seed = (seed >> 9) & 0xFFFF;
        let title = format!("w{word_seed:04x}");
        if variant == 0 {
            Action::AddItem(title)
        } else {
            Action::SetNotes(idx, title)
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(16))]

        // Two vaults share a master key (B is cloned from A). Each
        // applies a random sequence of Add + SetNotes actions,
        // derived from a u32 seed. Both push their saved chunks to
        // a shared backend and then pull. After both syncs
        // complete, the folded item state on both sides must be
        // equal (same set of items and same notes per item),
        // regardless of which actions happened on which install.
        #[test]
        fn proptest_two_install_lww_converges(
            seeds_a in proptest::collection::vec(proptest::num::u32::ANY, 1..=6),
            seeds_b in proptest::collection::vec(proptest::num::u32::ANY, 1..=6),
        ) {
            let a_dir = tempdir().expect("a");
            let a_path = a_dir.path().join("a.unovault");
            let a_install = InstallId::new();
            {
                let _a = Vault::create_for_tests(
                    &a_path,
                    Secret::new("pw".into()),
                    a_install,
                ).expect("a create");
            }
            let b_dir = tempdir().expect("b");
            let b_path = b_dir.path().join("b.unovault");
            copy_bundle_recursive(&a_path, &b_path);
            let b_install = InstallId::new();

            let mut a = Vault::unlock(
                &a_path,
                Secret::new("pw".into()),
                a_install,
            ).expect("a unlock");
            let mut b = Vault::unlock(
                &b_path,
                Secret::new("pw".into()),
                b_install,
            ).expect("b unlock");

            let plan_a: Vec<Action> = seeds_a.iter().copied().map(action_from_seed).collect();
            let plan_b: Vec<Action> = seeds_b.iter().copied().map(action_from_seed).collect();

            let mut a_ids: Vec<ItemId> = Vec::new();
            let mut b_ids: Vec<ItemId> = Vec::new();
            for action in &plan_a {
                apply_action(&mut a, action, &mut a_ids);
            }
            for action in &plan_b {
                apply_action(&mut b, action, &mut b_ids);
            }
            a.save().expect("a save");
            b.save().expect("b save");

            let backend_dir = tempdir().expect("backend");
            let backend = LocalBackend::new(backend_dir.path()).expect("backend");

            a.sync_with_backend(&backend).expect("a sync 1");
            b.sync_with_backend(&backend).expect("b sync 1");
            // Second round pulls what the other side just pushed.
            a.sync_with_backend(&backend).expect("a sync 2");
            b.sync_with_backend(&backend).expect("b sync 2");

            // Both sides must see the same item set and the same
            // notes per item. Titles + notes are a compact
            // fingerprint that catches realistic divergences.
            let mut a_state: Vec<(String, Option<String>)> = a
                .items()
                .map(|i| (i.title.clone(), i.notes.clone()))
                .collect();
            let mut b_state: Vec<(String, Option<String>)> = b
                .items()
                .map(|i| (i.title.clone(), i.notes.clone()))
                .collect();
            a_state.sort();
            b_state.sort();
            proptest::prop_assert_eq!(a_state, b_state);
        }
    }

    /// Copy a vault bundle directory recursively. Used by the
    /// sync tests to simulate "the user copied the vault from
    /// device A to device B."
    fn copy_bundle_recursive(src: &Path, dst: &Path) {
        std::fs::create_dir_all(dst).expect("dst dir");
        for entry in std::fs::read_dir(src).expect("read src") {
            let entry = entry.expect("entry");
            let ty = entry.file_type().expect("file type");
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            if ty.is_dir() {
                copy_bundle_recursive(&src_path, &dst_path);
            } else {
                std::fs::copy(&src_path, &dst_path).expect("copy");
            }
        }
    }
}
