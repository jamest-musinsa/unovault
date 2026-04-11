// Panic-policy exception for test code.
//
// The workspace root denies `unwrap_used`, `expect_used`, `panic`,
// `assertions_on_constants`, `todo`, and `unimplemented` for production code.
// Tests are the one place where a panic IS the legitimate failure mode: a
// failed `expect()` or `panic!()` inside a `#[test]` simply reports the test
// as failed, which is the intended behavior. Allowing these lints only under
// `cfg(test)` keeps production code strict while letting tests stay readable.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::assertions_on_constants,
    )
)]

//! # unovault-core
//!
//! The vault engine. Owns the `.unovault` file format, encryption, item model,
//! and the LWW event log that drives sync.
//!
//! Architectural constraints (enforced here, not documented elsewhere):
//!
//! * No plaintext credential material ever leaves this crate as a bare
//!   `String` or `Vec<u8>`. Every sensitive value is wrapped in [`Secret<T>`]
//!   whose `Drop` impl zeroizes memory and whose `Debug` impl prints
//!   `<redacted>`.
//! * Every fallible function returns [`Result<T, VaultError>`] — the
//!   5-category error taxonomy is the single supported error type. No
//!   `anyhow`, no ad-hoc strings.
//! * No panics on valid input. `unwrap`, `expect`, `panic!`, `todo!`, and
//!   `unimplemented!` are denied at crate root; violations require an
//!   `#[allow(...)]` with a comment explaining why.

pub mod crypto;
pub mod error;
pub mod event;
pub mod format;
pub mod install_id;
pub mod ipc;
pub mod recovery;
pub mod secret;
pub mod sync;
pub mod vault;

pub use crypto::{DerivedKeys, KdfParams};
pub use error::{
    BugInUnovaultError, HardwareIssueError, NetworkTransientError, PlatformPolicyError,
    UserActionableError, VaultError,
};
pub use event::{
    decode_event, encode_event, sort_events, Event, FieldKey, FieldValue, ItemId, ItemKind,
    ItemSnapshot, Op,
};
pub use format::{VaultManifest, VaultPaths};
pub use install_id::{InstallId, InstallIdStore};
pub use ipc::{IpcSafe, IpcString, ItemKindTag, ItemMetadata};
pub use recovery::RecoveryPhrase;
pub use secret::Secret;
pub use vault::{fold_events, ItemState, Vault};

/// Semantic version of the `.unovault` on-disk format.
///
/// Bumped when the chunk encoding, manifest layout, or Event schema changes in
/// a way that is not backward-compatible. Minor schema additions that older
/// readers can ignore do not bump this.
///
/// # v2 — weeks 16-17
///
/// Introduces the dual-wrap key hierarchy: the manifest stores a
/// random 32-byte master key wrapped under a password-derived KEK,
/// and optionally a second copy wrapped under a BIP39 recovery phrase
/// KEK. Rotation flows (`Vault::change_password`, `rotate_recovery`)
/// operate on the wraps only and never re-encrypt chunks. v1 vaults
/// are **not** readable by this build — there were no v1 vaults in
/// the wild, so the migration path is "create a fresh v2 vault."
pub const FORMAT_VERSION: u16 = 2;

/// Semantic version of the `unovault-core` crate. Distinct from the on-disk
/// format version — the same format can be read by many crate versions.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
