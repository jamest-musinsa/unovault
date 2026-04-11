// Test code in this crate uses `expect` for brevity; production code
// goes through explicit `Result` paths per the workspace panic policy.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! # unovault-import
//!
//! Importers for the three formats target users are most likely to be
//! leaving behind when they switch to unovault:
//!
//! | Format              | Extension | Source         |
//! |---------------------|-----------|----------------|
//! | 1Password export    | `.1pux`   | 1Password 8+   |
//! | Bitwarden JSON      | `.json`   | Bitwarden all  |
//! | KeePass KDBX4 XML   | `.xml`    | KeePassXC      |
//!
//! All three parsers land their output in a single neutral
//! [`ParsedItem`] shape. The vault engine then replays each
//! `ParsedItem` as a `CreateItem` event plus a short stream of
//! `UpdateField` events so the LWW log treats the import as a normal
//! set of writes.
//!
//! # Design notes
//!
//! * **No plaintext ever crosses the Tauri IPC boundary during
//!   preview.** The Tauri layer calls [`parse_file`], receives a
//!   `Vec<ParsedItem>` on the Rust side, keeps it in mutable state,
//!   and returns only a summary shape (counts + titles + kinds) to
//!   the frontend. The frontend never holds a password.
//!
//! * **Parsed items zeroize on drop.** Every string and byte vector
//!   carrying a secret is wrapped in the zeroize-on-drop scaffolding
//!   so a dropped `ParsedItem` wipes its payload. Tests verify this
//!   for the password path.
//!
//! * **Unknown categories are skipped, not dropped silently.** Every
//!   item that cannot be mapped to an [`ItemKind`] lands in
//!   [`ImportSummary::skipped`] with a reason. The UI shows the count
//!   and lets the user see the list before committing.
//!
//! * **One-shot import.** Week 14-15 scope does not include per-item
//!   review after parsing; the commit step is "take everything that
//!   parsed successfully and add it to the vault in one batch." A
//!   later sprint adds the per-item approve/skip flow. Skipped items
//!   are already tracked so only the UI has to land.

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unovault_core::event::ItemKind;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod parsers;

// =============================================================================
// PUBLIC TYPES
// =============================================================================

/// Which source format a file came from. Used for format auto-
/// detection, for the import wizard's source display, and for log
/// lines that make an audit trail of who contributed which items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportSource {
    /// 1Password 8+ `.1pux` export — ZIP with an `export.data` JSON.
    OnePassword1pux,
    /// Bitwarden unencrypted JSON export.
    BitwardenJson,
    /// KeePass / KeePassXC plain XML export (KDBX4 flavour).
    KeepassXml,
}

impl ImportSource {
    /// Human display name for the source. Shown in the import wizard.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::OnePassword1pux => "1Password",
            Self::BitwardenJson => "Bitwarden",
            Self::KeepassXml => "KeePass",
        }
    }

    /// Guess the source from the file extension. Returns `None` if
    /// the extension is unrecognised; callers should then show a
    /// "pick a source" dropdown instead of auto-detecting.
    pub fn detect_from_extension(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "1pux" => Some(Self::OnePassword1pux),
            "json" => Some(Self::BitwardenJson),
            "xml" => Some(Self::KeepassXml),
            _ => None,
        }
    }
}

/// A single item successfully parsed out of an export file.
///
/// This type is intentionally flat — the parsers don't try to model
/// their source format's nested structures. Everything the vault
/// engine needs lives directly on the struct, and everything else is
/// discarded.
///
/// `Zeroize + ZeroizeOnDrop` mean a dropped `ParsedItem` wipes its
/// password, TOTP secret, notes, and title buffers. Call sites that
/// need to clone the item should think carefully before doing so —
/// an accidental clone is a new plaintext copy the zeroize discipline
/// cannot reach.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ParsedItem {
    pub title: String,
    #[zeroize(skip)]
    pub kind: ItemKind,
    pub username: Option<String>,
    pub url: Option<String>,
    pub password: Option<Vec<u8>>,
    pub totp_secret: Option<Vec<u8>>,
    pub notes: Option<String>,
    #[zeroize(skip)]
    pub created_at_ms: Option<u64>,
    #[zeroize(skip)]
    pub modified_at_ms: Option<u64>,
}

// Manual Debug that redacts every secret field so a stray
// tracing::debug! can't leak during development.
impl std::fmt::Debug for ParsedItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedItem")
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

/// An item the importer saw but could not translate into a
/// [`ParsedItem`]. Tracked so the UI can show the user which pieces
/// of their old vault did not make it across.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedItem {
    /// Best-effort display title from the source format. May be the
    /// empty string if the source didn't give us one.
    pub title: String,
    /// One-line reason why the item was not imported.
    pub reason: String,
}

/// The result of parsing a single export file. Holds the parsed
/// items, the skipped items, and the source format.
#[derive(Debug)]
pub struct ImportSummary {
    pub source: ImportSource,
    pub items: Vec<ParsedItem>,
    pub skipped: Vec<SkippedItem>,
}

impl ImportSummary {
    /// Number of items successfully parsed and ready to import.
    pub fn imported_count(&self) -> usize {
        self.items.len()
    }

    /// Number of items the importer saw but skipped.
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    /// Short one-line summary for logs and UI toasts, e.g.
    /// `"247 items imported, 3 skipped (1Password)"`.
    pub fn display_line(&self) -> String {
        let imp = self.imported_count();
        let sk = self.skipped_count();
        format!(
            "{imp} {} imported, {sk} skipped ({source})",
            if imp == 1 { "item" } else { "items" },
            imp = imp,
            sk = sk,
            source = self.source.display_name(),
        )
    }
}

/// Errors surfaced by the importer layer. Collapses into
/// `unovault_core::VaultError::UserActionable` at the Tauri command
/// boundary so the frontend gets a friendly category.
#[derive(Debug, Error)]
pub enum ImportError {
    #[error("could not open the export file: {0}")]
    FileOpen(String),

    #[error("export file is not valid {format}: {reason}")]
    Malformed {
        format: &'static str,
        reason: String,
    },

    #[error("unknown source format — the file extension is not .1pux, .json, or .xml")]
    UnknownFormat,

    #[error("the JSON is encrypted — unovault can only import unencrypted exports")]
    EncryptedSource,

    #[error("1Password export has no accounts in it")]
    OnePasswordEmpty,
}

// =============================================================================
// PUBLIC ENTRY POINT
// =============================================================================

/// Parse an export file from disk. The format is detected from the
/// file extension; callers that already know the source can call the
/// format-specific functions in [`parsers`] directly.
///
/// Returns an [`ImportSummary`] on success. Errors fall into two
/// buckets: file-level problems (`FileOpen`, `UnknownFormat`) and
/// format-level problems (`Malformed`, `EncryptedSource`,
/// `OnePasswordEmpty`).
pub fn parse_file(path: &Path) -> Result<ImportSummary, ImportError> {
    let source = ImportSource::detect_from_extension(path).ok_or(ImportError::UnknownFormat)?;
    parse_file_with_source(path, source)
}

/// Like [`parse_file`] but with an explicit source. Useful when the
/// UI lets the user pick the format from a dropdown because the
/// extension lies.
pub fn parse_file_with_source(
    path: &Path,
    source: ImportSource,
) -> Result<ImportSummary, ImportError> {
    match source {
        ImportSource::OnePassword1pux => parsers::onepassword::parse_1pux(path),
        ImportSource::BitwardenJson => parsers::bitwarden::parse_json(path),
        ImportSource::KeepassXml => parsers::keepass::parse_xml(path),
    }
}

// =============================================================================
// TESTS — parser tests live in their own module; this block covers
// the public surface of the crate itself.
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_from_extension_handles_each_supported_suffix() {
        assert_eq!(
            ImportSource::detect_from_extension(Path::new("backup.1pux")),
            Some(ImportSource::OnePassword1pux),
        );
        assert_eq!(
            ImportSource::detect_from_extension(Path::new("export.json")),
            Some(ImportSource::BitwardenJson),
        );
        assert_eq!(
            ImportSource::detect_from_extension(Path::new("vault.xml")),
            Some(ImportSource::KeepassXml),
        );
    }

    #[test]
    fn detect_from_extension_is_case_insensitive() {
        assert_eq!(
            ImportSource::detect_from_extension(Path::new("backup.1PUX")),
            Some(ImportSource::OnePassword1pux),
        );
        assert_eq!(
            ImportSource::detect_from_extension(Path::new("VAULT.XML")),
            Some(ImportSource::KeepassXml),
        );
    }

    #[test]
    fn detect_from_extension_returns_none_for_unknown() {
        assert_eq!(
            ImportSource::detect_from_extension(Path::new("backup.txt")),
            None,
        );
        assert_eq!(
            ImportSource::detect_from_extension(Path::new("no-extension")),
            None,
        );
    }

    #[test]
    fn parsed_item_debug_redacts_secrets() {
        let item = ParsedItem {
            title: "GitHub".into(),
            kind: ItemKind::Password,
            username: Some("james".into()),
            url: Some("github.com".into()),
            password: Some(b"super-secret-value".to_vec()),
            totp_secret: Some(b"JBSWY3DPEHPK3PXP".to_vec()),
            notes: Some("keep this safe".into()),
            created_at_ms: None,
            modified_at_ms: None,
        };
        let debug = format!("{item:?}");
        assert!(!debug.contains("super-secret-value"));
        assert!(!debug.contains("JBSWY3DPEHPK3PXP"));
        assert!(!debug.contains("keep this safe"));
        assert!(debug.contains("redacted"));
        // Non-secret metadata is still visible.
        assert!(debug.contains("GitHub"));
        assert!(debug.contains("james"));
    }

    #[test]
    fn display_line_is_grammatical() {
        let one = ImportSummary {
            source: ImportSource::OnePassword1pux,
            items: vec![fake_item("GitHub")],
            skipped: vec![],
        };
        assert_eq!(one.display_line(), "1 item imported, 0 skipped (1Password)");

        let many = ImportSummary {
            source: ImportSource::BitwardenJson,
            items: vec![fake_item("a"), fake_item("b")],
            skipped: vec![SkippedItem {
                title: "credit card".into(),
                reason: "unsupported kind".into(),
            }],
        };
        assert_eq!(
            many.display_line(),
            "2 items imported, 1 skipped (Bitwarden)",
        );
    }

    fn fake_item(title: &str) -> ParsedItem {
        ParsedItem {
            title: title.into(),
            kind: ItemKind::Password,
            username: None,
            url: None,
            password: None,
            totp_secret: None,
            notes: None,
            created_at_ms: None,
            modified_at_ms: None,
        }
    }
}
