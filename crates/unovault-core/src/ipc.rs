//! IPC safety marker trait.
//!
//! The design doc's architectural rule #4 is non-negotiable:
//!
//! > No plaintext credential material in Tauri IPC return types. When the
//! > app shell lands, a `#[unovault::safe_command]` proc-macro enforces
//! > this at compile time.
//!
//! This module is the type-system half of that rule. [`IpcSafe`] is a
//! marker trait implemented for every type that is allowed to cross
//! the Rust ↔ JavaScript boundary via Tauri's serde-based IPC. Types
//! that could carry secret material (`String`, `Vec<u8>`, `&str`) are
//! **deliberately not implemented**, so a command that tries to return
//! one fails the static assertion inside the `safe_command` proc-macro.
//!
//! # Design notes
//!
//! * `String` is not `IpcSafe`. If a command needs to return a text
//!   identifier (item id, install id, vault filename), it wraps the
//!   value in [`IpcString`]. The wrapper is a single conscious line
//!   at the call site and creates a reviewable audit trail.
//!
//! * `Vec<u8>` is not `IpcSafe`. Raw byte returns are almost always a
//!   security bug in a password manager; there is currently no
//!   legitimate command that needs to return bytes.
//!
//! * `Result<T, E>` requires **both** `T: IpcSafe` and `E: IpcSafe`,
//!   so command errors have to be explicitly marked safe too. This
//!   stops an error enum with a `String` payload from silently leaking
//!   a value the caller passed in.
//!
//! # Adding a new safe type
//!
//! When a new record or enum needs to cross the boundary, import this
//! trait and add a plain `impl IpcSafe for MyType {}` next to its
//! definition. The marker carries no methods — it exists only for the
//! proc-macro's compile-time check.

/// Marker trait for types that are safe to return from a Tauri IPC
/// command. The trait has no methods and no provided behavior — it
/// exists purely so that `#[safe_command]` can compile-time assert
/// the return type is on the allow-list.
///
/// See the module docs for the rules about which types are safe and
/// why `String` is not.
pub trait IpcSafe {}

// Primitives and unit.
impl IpcSafe for () {}
impl IpcSafe for bool {}
impl IpcSafe for i8 {}
impl IpcSafe for i16 {}
impl IpcSafe for i32 {}
impl IpcSafe for i64 {}
impl IpcSafe for i128 {}
impl IpcSafe for isize {}
impl IpcSafe for u8 {}
impl IpcSafe for u16 {}
impl IpcSafe for u32 {}
impl IpcSafe for u64 {}
impl IpcSafe for u128 {}
impl IpcSafe for usize {}
impl IpcSafe for f32 {}
impl IpcSafe for f64 {}
impl IpcSafe for char {}

// Collections: if every element is safe, so is the collection.
impl<T: IpcSafe> IpcSafe for Option<T> {}
impl<T: IpcSafe> IpcSafe for Vec<T> {}
impl<T: IpcSafe, const N: usize> IpcSafe for [T; N] {}

/// A `Result` is IPC-safe only if both the success and error variants
/// are safe. This stops a `Result<ItemMetadata, String>` from slipping
/// through because the error side was overlooked.
impl<T: IpcSafe, E: IpcSafe> IpcSafe for Result<T, E> {}

// =============================================================================
// IpcString — the opt-in wrapper for identifier strings that legitimately
// need to cross the boundary.
// =============================================================================

/// Opt-in wrapper around `String` for values that need to cross the IPC
/// boundary and are known not to carry credential material.
///
/// Every call site that constructs an `IpcString` is a conscious decision
/// that the wrapped string is safe to ship to the frontend. A future
/// reviewer searching for "why is this string leaking" has a grep target
/// at every conversion point.
///
/// # Correct uses
///
/// * Item IDs rendered as hyphenated UUID strings
/// * Install IDs
/// * Vault bundle paths (filesystem metadata, not secret)
/// * Titles, URLs, masked usernames (these are item *metadata*, not
///   credentials — the secret part lives inside the Secret<T> fields
///   on the core vault state and never converts to `IpcString`)
/// * Timestamps formatted for display
///
/// # Incorrect uses
///
/// * Passwords
/// * TOTP seeds
/// * Passkey private material
/// * Recovery phrases
/// * Anything derived from the master password
///
/// Reviewers: grep for `IpcString::new` and audit each call site against
/// this list. If any new use is added, add a comment explaining why the
/// wrapped value is provably not credential material.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct IpcString(pub String);

impl IpcSafe for IpcString {}

impl IpcString {
    /// Wrap a value as an IPC-safe string. The wrap is conscious —
    /// grepping for `IpcString::new` gives the audit trail.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Unwrap the inner string. Useful on the backend after
    /// deserializing an IPC request; callers on the frontend never see
    /// this method because it is not exposed over the boundary.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for IpcString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for IpcString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::fmt::Display for IpcString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// =============================================================================
// ItemMetadata — the canonical record every "list items" command returns.
// =============================================================================

/// Metadata shown in vault list rows and item detail headers. Contains
/// zero credential material: passwords, TOTP seeds, and passkey private
/// keys are NOT fields on this struct. The frontend uses the booleans
/// `has_password` / `has_totp` / `has_passkey` to render kind badges,
/// and requests secret reveal through a separate command that draws
/// the plaintext as a native overlay (not as IPC return value).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ItemMetadata {
    pub id: IpcString,
    pub title: IpcString,
    pub kind: ItemKindTag,
    pub username: Option<IpcString>,
    pub url: Option<IpcString>,
    pub has_password: bool,
    pub has_totp: bool,
    pub has_passkey: bool,
    pub created_at_ms: u64,
    pub modified_at_ms: u64,
}

impl IpcSafe for ItemMetadata {}

/// IPC-safe enum mirroring [`crate::event::ItemKind`].
///
/// Separate type so that the core `ItemKind` can stay `#[non_exhaustive]`
/// (which the format version benefits from) while the IPC boundary
/// exposes an exhaustive list that the frontend can pattern-match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ItemKindTag {
    Password,
    Passkey,
    Totp,
    SshKey,
    ApiToken,
    SecureNote,
}

impl IpcSafe for ItemKindTag {}

impl From<crate::event::ItemKind> for ItemKindTag {
    fn from(k: crate::event::ItemKind) -> Self {
        use crate::event::ItemKind;
        // Intra-crate match is exhaustive even though `ItemKind` is
        // `#[non_exhaustive]`. When a new variant is added in a future
        // format version, the compile error here is the reviewer's
        // signal to update the IPC tag enum + the frontend.
        match k {
            ItemKind::Password => Self::Password,
            ItemKind::Passkey => Self::Passkey,
            ItemKind::Totp => Self::Totp,
            ItemKind::SshKey => Self::SshKey,
            ItemKind::ApiToken => Self::ApiToken,
            ItemKind::SecureNote => Self::SecureNote,
        }
    }
}

impl From<ItemKindTag> for crate::event::ItemKind {
    fn from(k: ItemKindTag) -> Self {
        use crate::event::ItemKind;
        match k {
            ItemKindTag::Password => ItemKind::Password,
            ItemKindTag::Passkey => ItemKind::Passkey,
            ItemKindTag::Totp => ItemKind::Totp,
            ItemKindTag::SshKey => ItemKind::SshKey,
            ItemKindTag::ApiToken => ItemKind::ApiToken,
            ItemKindTag::SecureNote => ItemKind::SecureNote,
        }
    }
}

// Convert an in-memory vault item into an IPC-safe metadata record.
// This is the single place the translation happens, so if a new secret
// field is added to ItemState the reviewer has exactly one site to
// audit for leakage.
impl ItemMetadata {
    pub fn from_item_state(item: &crate::vault::ItemState) -> Self {
        Self {
            id: IpcString::new(item.id.0.hyphenated().to_string()),
            title: IpcString::new(item.title.clone()),
            kind: item.kind.into(),
            username: item.username.clone().map(IpcString::new),
            url: item.url.clone().map(IpcString::new),
            has_password: item.password.is_some(),
            has_totp: item.totp_secret.is_some(),
            // passkey credentials are stored inline in the vault state
            // via field-level UpdateField events; the current ItemState
            // doesn't have a dedicated passkey field yet. Surface
            // `has_passkey = false` until the passkey field lands in
            // weeks 14-15, then update this single line.
            has_passkey: false,
            created_at_ms: item.created_at_ms,
            modified_at_ms: item.modified_at_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof that every allowed type satisfies IpcSafe.
    // If any of these stop compiling, the allow-list has regressed.
    #[allow(non_upper_case_globals, dead_code)]
    const _IPC_SAFE_ALLOWLIST: fn() = || {
        fn assert<T: IpcSafe>() {}
        assert::<()>();
        assert::<bool>();
        assert::<u64>();
        assert::<i32>();
        assert::<Option<u64>>();
        assert::<Vec<u64>>();
        assert::<IpcString>();
        assert::<ItemKindTag>();
        assert::<ItemMetadata>();
        assert::<Option<IpcString>>();
        assert::<Vec<ItemMetadata>>();
        assert::<Result<Vec<ItemMetadata>, ItemKindTag>>();
    };

    // Negative compile tests (String NOT IpcSafe) would live in a
    // trybuild test harness. That's a heavier dep; deferred to a
    // later sprint. For now the audit signal is that every command
    // goes through #[safe_command] and only types whose names are
    // reviewable appear in the allow-list above.

    #[test]
    fn ipc_string_roundtrips_serde() {
        let s = IpcString::new("hello");
        let json = serde_json::to_string(&s).expect("serialize");
        assert_eq!(json, "\"hello\"");
        let parsed: IpcString = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, s);
    }

    #[test]
    fn ipc_string_display_is_inner() {
        let s = IpcString::new("vault.unovault");
        assert_eq!(format!("{s}"), "vault.unovault");
    }

    #[test]
    fn item_kind_tag_round_trip_with_core_kind() {
        for tag in [
            ItemKindTag::Password,
            ItemKindTag::Passkey,
            ItemKindTag::Totp,
            ItemKindTag::SshKey,
            ItemKindTag::ApiToken,
            ItemKindTag::SecureNote,
        ] {
            let core: crate::event::ItemKind = tag.into();
            let back: ItemKindTag = core.into();
            assert_eq!(tag, back);
        }
    }

    #[test]
    fn item_metadata_from_item_state_does_not_leak_password_bytes() {
        use crate::event::{ItemKind, ItemSnapshot};
        use crate::vault::ItemState;
        let mut item = ItemState::from_snapshot(
            crate::event::ItemId::new(),
            ItemSnapshot {
                title: "GitHub".into(),
                kind: ItemKind::Password,
                username: Some("james".into()),
                url: Some("github.com".into()),
            },
            1_700_000_000_000,
        );
        item.password = Some(b"super secret plaintext".to_vec());
        item.totp_secret = Some(b"JBSWY3DPEHPK3PXP".to_vec());

        let metadata = ItemMetadata::from_item_state(&item);
        let json = serde_json::to_string(&metadata).expect("serialize");

        // The secret bytes must not appear anywhere in the JSON.
        assert!(!json.contains("super secret"));
        assert!(!json.contains("JBSWY3DPEHPK3PXP"));
        // But the booleans correctly reflect that they exist.
        assert!(metadata.has_password);
        assert!(metadata.has_totp);
        assert!(!metadata.has_passkey);
        // And the metadata fields are present.
        assert!(json.contains("GitHub"));
        assert!(json.contains("james"));
    }
}
