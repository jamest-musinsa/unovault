//! Last-writer-wins event log — the canonical on-disk data model.
//!
//! The design doc rejected a full CRDT (automerge) in favor of per-item LWW
//! semantics. This module defines the [`Event`] type that rides inside each
//! encrypted chunk file and the deterministic ordering that makes LWW replay
//! produce the same vault state across every device.
//!
//! # Layering
//!
//! ```text
//! Vault state (in-memory HashMap<ItemId, ItemState>)
//!      ▲
//!      │  fold(events)          (module: vault, not yet built)
//!      │
//! Vec<Event> sorted by Event::cmp
//!      ▲
//!      │  sort_events(&mut)
//!      │
//! Decrypted Vec<Event> from chunks
//!      ▲
//!      │  postcard::from_bytes   (this module)
//!      │
//! Plaintext chunk payload
//!      ▲
//!      │  XChaCha20-Poly1305     (module: crypto, next)
//!      │
//! *.chunk file
//! ```
//!
//! # Why Event is not a [`Secret`](crate::Secret)
//!
//! Event carries plaintext credential material in [`FieldValue::Bytes`]. When
//! an Event exists in RAM it has already been decrypted, and the plaintext
//! bytes live in the Vec inside the enum variant. This is fine at the wire-
//! format layer because Events are ephemeral: they are deserialized, folded
//! into the vault state, and dropped. The **vault state itself** (defined in
//! a later module) wraps its secret fields in `Secret<T>`.
//!
//! Callers that hold Events for any non-trivial duration should drop them
//! promptly. A future audit will add proptest-backed fuzzing to ensure that
//! postcard deserialization does not leave plaintext fragments in the input
//! buffer after the Event is consumed.

use core::cmp::Ordering;
use core::fmt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable identifier for a vault item. Generated on `CreateItem`, survives
/// every `UpdateField`, destroyed by `DeleteItem`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ItemId(pub Uuid);

impl ItemId {
    /// Generate a random v4 item id.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ItemId {
    fn default() -> Self {
        Self::new()
    }
}

/// Category of a vault item. Drives UI affordances (which fields to render,
/// which kind chip to show) and informs search hints. New variants may be
/// added in later format versions; the `#[non_exhaustive]` attribute makes
/// that a non-breaking change.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ItemKind {
    /// A classic username+password login.
    Password,
    /// A WebAuthn passkey credential.
    Passkey,
    /// A TOTP generator (time-based one-time password).
    Totp,
    /// An SSH private key.
    SshKey,
    /// A long-lived API token or bearer secret.
    ApiToken,
    /// Freeform encrypted note with no structured fields.
    SecureNote,
}

/// Name of a field on an item. The LWW merge rule keys `(ItemId, FieldKey)`
/// against the most recent `UpdateField` event.
///
/// Custom keys exist so users can add arbitrary fields (e.g. "recovery email",
/// "security question") without the format version having to know about them.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FieldKey {
    Title,
    Username,
    Url,
    Password,
    TotpSecret,
    PasskeyPublicKey,
    PasskeyCredentialId,
    Notes,
    Kind,
    /// Arbitrary user-defined field.
    Custom(String),
}

/// A field's value. Text for human-readable fields, bytes for raw crypto
/// material, Kind for the kind update operation, and Tombstone to record
/// an explicit deletion of a single field without deleting the whole item.
///
/// Debug is implemented manually so `FieldValue::Bytes(secret_password)`
/// prints as `Bytes(<redacted N bytes>)` — derive would print the byte
/// array and leak the plaintext via any log statement that formats an
/// enclosing struct. Text is still printed because text fields like Title
/// and URL are not secrets. Code reviewers must keep the "no text secrets"
/// invariant — if a secret field is ever added as `Text`, update this impl.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldValue {
    /// UTF-8 string — titles, URLs, usernames, notes.
    Text(String),
    /// Raw bytes — passwords, TOTP secrets, passkey private material.
    ///
    /// These bytes are plaintext while the Event is in memory. They become
    /// ciphertext when the enclosing chunk file is written to disk. The
    /// manual Debug impl below ensures the bytes themselves never appear
    /// in a formatted representation.
    Bytes(Vec<u8>),
    /// Kind update (for `FieldKey::Kind` only).
    Kind(ItemKind),
    /// Explicit "this field is now unset" marker. Useful for removing a note
    /// or a custom field without deleting the whole item.
    Tombstone,
}

impl fmt::Debug for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(s) => f.debug_tuple("Text").field(s).finish(),
            Self::Bytes(b) => f
                .debug_tuple("Bytes")
                .field(&format_args!("<redacted {} bytes>", b.len()))
                .finish(),
            Self::Kind(k) => f.debug_tuple("Kind").field(k).finish(),
            Self::Tombstone => f.debug_tuple("Tombstone").finish(),
        }
    }
}

/// Initial snapshot captured at `CreateItem` time. Carries non-secret metadata
/// only; secret material (passwords, TOTP seeds, passkey keys) is added via
/// subsequent `UpdateField` events.
///
/// Why split? Because adding an item is a two-step mental operation: "here's
/// what this is" (title, kind, URL), followed by "here's the secret." Keeping
/// them separate events means partial inputs don't block the item from
/// existing, and the UI can show the item row immediately after the first
/// event lands.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ItemSnapshot {
    pub title: String,
    pub kind: ItemKind,
    pub username: Option<String>,
    pub url: Option<String>,
}

/// Operation applied by a single Event.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum Op {
    /// Create a new item with an initial non-secret snapshot. Secrets land
    /// in subsequent `UpdateField` events.
    CreateItem {
        item_id: ItemId,
        initial: ItemSnapshot,
    },

    /// Set a field's value to a new value. LWW merge picks the newest
    /// UpdateField per (item_id, field).
    UpdateField {
        item_id: ItemId,
        field: FieldKey,
        value: FieldValue,
    },

    /// Tombstone the item. Subsequent non-resurrection events on this
    /// item id are dropped by the merge.
    DeleteItem { item_id: ItemId },
}

/// A single entry in the vault's append-only event log.
///
/// Events are written inside encrypted chunk files. One chunk may contain
/// many events. Across devices, the global ordering of events is determined
/// by the [`Event::cmp`] tuple `(timestamp_ms, install_id, lamport)` — fully
/// deterministic given the same chunk set, independent of disk delivery order.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    /// Unique identifier for this event. Used by tests and diagnostics; the
    /// merge order does not depend on it.
    pub event_id: Uuid,

    /// Wall-clock time on the writing device, milliseconds since Unix epoch.
    ///
    /// Wall clocks disagree across devices. The [`Event::cmp`] tiebreakers
    /// make the total order deterministic even when two devices produce
    /// events with identical timestamps.
    pub timestamp_ms: u64,

    /// Install id of the device that wrote this event. Stable per install,
    /// shared across all events that install produces. Used both as a
    /// sharding key for chunk filenames and as a tiebreaker in [`Event::cmp`].
    pub install_id: Uuid,

    /// Monotonic per-install counter. Guarantees that two events from the
    /// same install with the same `timestamp_ms` still have a stable order
    /// regardless of when the OS's millisecond clock ticks over.
    pub lamport: u64,

    /// The operation this event records.
    pub op: Op,
}

impl Event {
    /// Build a new event. Callers must supply a monotonic `lamport` for the
    /// given `install_id`; the caller is responsible for persisting and
    /// incrementing the counter.
    pub fn new(install_id: Uuid, lamport: u64, timestamp_ms: u64, op: Op) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp_ms,
            install_id,
            lamport,
            op,
        }
    }
}

/// Events are compared lexicographically on `(timestamp_ms, install_id,
/// lamport)`. This total order drives LWW replay.
///
/// The chosen order:
///
/// 1. `timestamp_ms` — the user's intent ("this happened later") dominates
///    when clocks broadly agree.
/// 2. `install_id` byte order — breaks cross-device ties when two devices
///    wrote events in the same millisecond. Arbitrary but deterministic,
///    which is all that matters for convergence.
/// 3. `lamport` — breaks same-device ties when the same install writes
///    multiple events in the same millisecond.
impl Ord for Event {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp_ms
            .cmp(&other.timestamp_ms)
            .then_with(|| self.install_id.as_bytes().cmp(other.install_id.as_bytes()))
            .then_with(|| self.lamport.cmp(&other.lamport))
    }
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Sort a slice of events into LWW replay order in place.
///
/// The input may have been decrypted from chunk files delivered out of order
/// (iCloud does not guarantee delivery order). After this call, replaying
/// events left to right will produce the same vault state on every device
/// that has the same chunk set.
pub fn sort_events(events: &mut [Event]) {
    events.sort();
}

/// Serialize an event to its postcard byte representation — the plaintext
/// payload that will be fed into the chunk encryption layer.
///
/// Errors become [`crate::BugInUnovaultError::SelfSerializationFailure`]
/// because serializing an Event we just built ourselves should never fail
/// in practice; if it does, an invariant was broken upstream.
pub fn encode_event(event: &Event) -> Result<Vec<u8>, crate::VaultError> {
    postcard::to_allocvec(event)
        .map_err(|_| crate::BugInUnovaultError::SelfSerializationFailure.into())
}

/// Deserialize an event from its postcard byte representation.
///
/// A decode failure is classified as [`crate::UserActionableError::CorruptedChunk`]
/// rather than a bug because the most likely cause is a damaged chunk file,
/// not a serialization error in our own code.
pub fn decode_event(bytes: &[u8]) -> Result<Event, crate::VaultError> {
    postcard::from_bytes(bytes).map_err(|_| crate::UserActionableError::CorruptedChunk.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal event with canned fields for ordering tests.
    fn ev(timestamp_ms: u64, install_id: Uuid, lamport: u64) -> Event {
        Event::new(
            install_id,
            lamport,
            timestamp_ms,
            Op::DeleteItem {
                item_id: ItemId::new(),
            },
        )
    }

    /// Helper: a stable non-zero install id for tests.
    fn iid(tag: u8) -> Uuid {
        Uuid::from_bytes([
            tag, tag, tag, tag, tag, tag, tag, tag, tag, tag, tag, tag, tag, tag, tag, tag,
        ])
    }

    #[test]
    fn round_trip_create_item_event() {
        let install = iid(1);
        let event = Event::new(
            install,
            1,
            1_700_000_000_000,
            Op::CreateItem {
                item_id: ItemId::new(),
                initial: ItemSnapshot {
                    title: "GitHub".into(),
                    kind: ItemKind::Password,
                    username: Some("james@personal".into()),
                    url: Some("github.com".into()),
                },
            },
        );

        let bytes = encode_event(&event).expect("encode must succeed");
        let decoded = decode_event(&bytes).expect("decode must succeed");

        assert_eq!(event, decoded);
    }

    #[test]
    fn round_trip_update_field_event_with_binary_value() {
        let install = iid(2);
        // Simulate a password field carrying plaintext bytes. In production
        // these bytes would be zeroized by the caller after the fold into
        // vault state.
        let password_bytes = b"correct horse battery staple".to_vec();
        let event = Event::new(
            install,
            2,
            1_700_000_001_000,
            Op::UpdateField {
                item_id: ItemId::new(),
                field: FieldKey::Password,
                value: FieldValue::Bytes(password_bytes.clone()),
            },
        );

        let bytes = encode_event(&event).expect("encode");
        let decoded = decode_event(&bytes).expect("decode");

        assert_eq!(event, decoded);
        match decoded.op {
            Op::UpdateField {
                value: FieldValue::Bytes(b),
                ..
            } => assert_eq!(b, password_bytes),
            other => panic!("decoded variant changed shape: {other:?}"),
        }
    }

    #[test]
    fn custom_field_key_round_trips() {
        let install = iid(3);
        let event = Event::new(
            install,
            3,
            1_700_000_002_000,
            Op::UpdateField {
                item_id: ItemId::new(),
                field: FieldKey::Custom("recovery_email".into()),
                value: FieldValue::Text("backup@example.com".into()),
            },
        );

        let bytes = encode_event(&event).expect("encode");
        let decoded = decode_event(&bytes).expect("decode");

        assert_eq!(event, decoded);
    }

    #[test]
    fn ordering_primary_key_is_timestamp() {
        let a = ev(1_000, iid(1), 0);
        let b = ev(2_000, iid(1), 0);
        assert!(a < b);
    }

    #[test]
    fn ordering_tiebreaks_on_install_id_when_timestamps_match() {
        let a = ev(1_000, iid(1), 99);
        let b = ev(1_000, iid(2), 0);
        // a's install id < b's install id, so a < b regardless of lamport.
        assert!(a < b);
    }

    #[test]
    fn ordering_tiebreaks_on_lamport_when_timestamp_and_install_match() {
        let install = iid(7);
        let a = ev(1_000, install, 1);
        let b = ev(1_000, install, 2);
        assert!(a < b);
    }

    #[test]
    fn sort_events_is_deterministic_across_shuffles() {
        // Build a set of events that collide on each tiebreaker level.
        let mut canonical: Vec<Event> = vec![
            ev(1_000, iid(1), 0),
            ev(1_000, iid(1), 1),
            ev(1_000, iid(2), 0),
            ev(2_000, iid(1), 0),
            ev(2_000, iid(3), 0),
        ];
        sort_events(&mut canonical);

        // Shuffle deterministically via a fixed permutation and re-sort;
        // the result must match the canonical order byte-for-byte.
        let mut shuffled = vec![
            canonical[4].clone(),
            canonical[0].clone(),
            canonical[2].clone(),
            canonical[3].clone(),
            canonical[1].clone(),
        ];
        sort_events(&mut shuffled);

        assert_eq!(canonical, shuffled);
    }

    #[test]
    fn decode_of_garbage_bytes_returns_corrupted_chunk_error() {
        let garbage = [0xFFu8, 0x00, 0x42, 0x13, 0x37];
        let result = decode_event(&garbage);
        match result {
            Err(crate::VaultError::UserActionable(crate::UserActionableError::CorruptedChunk)) => {}
            other => panic!("expected CorruptedChunk, got {other:?}"),
        }
    }

    #[test]
    fn postcard_encoding_is_reasonably_compact() {
        // A minimal DeleteItem event should fit comfortably under 64 bytes.
        // This is a sanity check, not a hard performance contract.
        let event = ev(1_700_000_000_000, iid(1), 42);
        let bytes = encode_event(&event).expect("encode");
        assert!(
            bytes.len() < 64,
            "DeleteItem event encoded to {} bytes; expected < 64",
            bytes.len()
        );
    }
}
