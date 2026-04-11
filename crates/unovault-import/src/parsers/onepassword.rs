//! 1Password `.1pux` parser.
//!
//! A `.1pux` file is a ZIP archive. The single file we care about is
//! `export.data`, a JSON document with the accounts → vaults →
//! items structure. Attached files (passport scans, license photos)
//! live under `files/` and are not imported in v1.
//!
//! # Schema
//!
//! The relevant subset, simplified:
//!
//! ```json
//! {
//!   "accounts": [
//!     {
//!       "vaults": [
//!         {
//!           "items": [
//!             {
//!               "uuid": "...",
//!               "createdAt": 1700000000,
//!               "updatedAt": 1700001000,
//!               "categoryUuid": "001",
//!               "state": "active",
//!               "overview": {
//!                 "title": "GitHub",
//!                 "url": "github.com",
//!                 "urls": [{"u": "github.com"}]
//!               },
//!               "details": {
//!                 "loginFields": [
//!                   {"designation": "username", "value": "james"},
//!                   {"designation": "password", "value": "..."}
//!                 ],
//!                 "notesPlain": "optional notes"
//!               }
//!             }
//!           ]
//!         }
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! # Category mapping
//!
//! 1Password uses a stable set of category UUIDs. We map the handful
//! we care about; everything else lands in `skipped` with a reason.
//!
//! | categoryUuid | 1Password name    | unovault `ItemKind`      |
//! |--------------|-------------------|--------------------------|
//! | `001`        | Login             | `Password`               |
//! | `005`        | Password          | `Password`               |
//! | `003`        | Secure Note       | `SecureNote`             |
//! | `111`        | Passkey (2024+)   | `Passkey`                |
//! | anything else| —                 | skipped                  |
//!
//! # What is not handled in v1
//!
//! * Deleted items (items with `state` != `"active"`)
//! * Attached files under `files/`
//! * Custom sections with user-defined field types
//! * 1Password "Watchtower" metadata and breach reports
//! * Trashed + archived items

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use unovault_core::event::ItemKind;

use crate::{ImportError, ImportSource, ImportSummary, ParsedItem, SkippedItem};

// =============================================================================
// SERDE MODELS — only the fields we actually consume.
// =============================================================================

#[derive(Debug, Deserialize)]
struct Export {
    #[serde(default)]
    accounts: Vec<Account>,
}

#[derive(Debug, Deserialize)]
struct Account {
    #[serde(default)]
    vaults: Vec<Vault>,
}

#[derive(Debug, Deserialize)]
struct Vault {
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Item {
    #[serde(default, rename = "categoryUuid")]
    category_uuid: String,
    #[serde(default, rename = "createdAt")]
    created_at: Option<i64>,
    #[serde(default, rename = "updatedAt")]
    updated_at: Option<i64>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    overview: Option<Overview>,
    #[serde(default)]
    details: Option<Details>,
}

#[derive(Debug, Deserialize)]
struct Overview {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    urls: Vec<OverviewUrl>,
}

#[derive(Debug, Deserialize)]
struct OverviewUrl {
    #[serde(default)]
    u: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Details {
    #[serde(default, rename = "loginFields")]
    login_fields: Vec<LoginField>,
    #[serde(default, rename = "notesPlain")]
    notes_plain: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginField {
    #[serde(default)]
    designation: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

// =============================================================================
// PARSER ENTRY POINT
// =============================================================================

/// Parse a `.1pux` file on disk into an [`ImportSummary`].
pub fn parse_1pux(path: &Path) -> Result<ImportSummary, ImportError> {
    let file = File::open(path).map_err(|e| ImportError::FileOpen(e.to_string()))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| ImportError::Malformed {
        format: "1pux",
        reason: format!("not a valid zip archive: {e}"),
    })?;

    let mut export_data = archive
        .by_name("export.data")
        .map_err(|_| ImportError::Malformed {
            format: "1pux",
            reason: "missing export.data entry — not a 1Password 1pux file".into(),
        })?;

    let mut buffer = String::new();
    export_data
        .read_to_string(&mut buffer)
        .map_err(|e| ImportError::Malformed {
            format: "1pux",
            reason: format!("export.data is not UTF-8: {e}"),
        })?;

    parse_export_json(&buffer)
}

/// Parse an already-extracted `export.data` JSON string. Exposed so
/// unit tests can bypass the zip layer and feed canned JSON directly.
pub fn parse_export_json(json: &str) -> Result<ImportSummary, ImportError> {
    let export: Export = serde_json::from_str(json).map_err(|e| ImportError::Malformed {
        format: "1pux",
        reason: format!("export.data is not valid JSON: {e}"),
    })?;

    if export.accounts.is_empty() {
        return Err(ImportError::OnePasswordEmpty);
    }

    let mut items = Vec::new();
    let mut skipped = Vec::new();

    for account in export.accounts {
        for vault in account.vaults {
            for item in vault.items {
                convert_item(item, &mut items, &mut skipped);
            }
        }
    }

    Ok(ImportSummary {
        source: ImportSource::OnePassword1pux,
        items,
        skipped,
    })
}

// =============================================================================
// CONVERSION
// =============================================================================

fn convert_item(item: Item, items: &mut Vec<ParsedItem>, skipped: &mut Vec<SkippedItem>) {
    // Skip anything that isn't active (trashed, archived, etc.).
    if let Some(state) = item.state.as_deref() {
        if state != "active" {
            let title = item
                .overview
                .as_ref()
                .and_then(|o| o.title.clone())
                .unwrap_or_default();
            skipped.push(SkippedItem {
                title,
                reason: format!("state = {state:?}, not active"),
            });
            return;
        }
    }

    let kind = match item.category_uuid.as_str() {
        "001" | "005" => ItemKind::Password,
        "003" => ItemKind::SecureNote,
        "111" => ItemKind::Passkey,
        other => {
            let title = item
                .overview
                .as_ref()
                .and_then(|o| o.title.clone())
                .unwrap_or_default();
            skipped.push(SkippedItem {
                title,
                reason: format!("unsupported categoryUuid {other:?}"),
            });
            return;
        }
    };

    let overview = item.overview.unwrap_or(Overview {
        title: None,
        url: None,
        urls: Vec::new(),
    });
    let details = item.details.unwrap_or(Details {
        login_fields: Vec::new(),
        notes_plain: None,
        password: None,
    });

    let title = overview.title.clone().unwrap_or_else(|| "Untitled".into());

    let url = overview
        .url
        .clone()
        .or_else(|| overview.urls.iter().find_map(|u| u.u.clone()));

    let (username, password_from_fields) = extract_login_fields(&details.login_fields);

    // Password for a Login item comes from loginFields; a bare
    // "Password" category item uses details.password instead.
    let password = password_from_fields.or_else(|| details.password.clone());

    let parsed = ParsedItem {
        title,
        kind,
        username,
        url,
        password: password.map(|s| s.into_bytes()),
        totp_secret: None,
        notes: details.notes_plain.clone(),
        // 1Password timestamps are whole seconds; convert to ms and
        // drop pre-epoch values rather than silently casting negatives.
        created_at_ms: item.created_at.and_then(seconds_to_ms),
        modified_at_ms: item.updated_at.and_then(seconds_to_ms),
    };
    items.push(parsed);
}

fn extract_login_fields(fields: &[LoginField]) -> (Option<String>, Option<String>) {
    let mut username = None;
    let mut password = None;
    for field in fields {
        match field.designation.as_deref() {
            Some("username") => username = field.value.clone(),
            Some("password") => password = field.value.clone(),
            _ => {}
        }
    }
    (username, password)
}

fn seconds_to_ms(s: i64) -> Option<u64> {
    if s < 0 {
        None
    } else {
        Some((s as u64).saturating_mul(1_000))
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::FileOptions;

    /// Build a minimal valid `.1pux` archive on disk for the given
    /// JSON body. Uses the zip crate's writer with a deflate-encoded
    /// `export.data` entry because real 1Password outputs use
    /// compression.
    fn make_1pux_file(dir: &Path, json: &str) -> std::path::PathBuf {
        let path = dir.join("fixture.1pux");
        let file = File::create(&path).expect("create fixture");
        let mut zip = zip::ZipWriter::new(file);
        let options: FileOptions<'_, ()> =
            FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("export.data", options).expect("start");
        zip.write_all(json.as_bytes()).expect("write");
        zip.finish().expect("finish");
        path
    }

    const FULL_SAMPLE: &str = r#"{
      "accounts": [{
        "vaults": [{
          "items": [
            {
              "uuid": "gh",
              "createdAt": 1700000000,
              "updatedAt": 1700001000,
              "state": "active",
              "categoryUuid": "001",
              "overview": {
                "title": "GitHub",
                "urls": [{"u": "github.com"}]
              },
              "details": {
                "loginFields": [
                  {"designation": "username", "value": "james@personal"},
                  {"designation": "password", "value": "correct horse battery staple"}
                ],
                "notesPlain": "main dev account"
              }
            },
            {
              "uuid": "wifi",
              "createdAt": 1700002000,
              "updatedAt": 1700002000,
              "state": "active",
              "categoryUuid": "005",
              "overview": { "title": "Home WiFi" },
              "details": {
                "password": "home-password-42"
              }
            },
            {
              "uuid": "note",
              "createdAt": 1700003000,
              "state": "active",
              "categoryUuid": "003",
              "overview": { "title": "Server IP" },
              "details": { "notesPlain": "10.0.0.42" }
            },
            {
              "uuid": "card",
              "state": "active",
              "categoryUuid": "002",
              "overview": { "title": "My Visa" },
              "details": {}
            },
            {
              "uuid": "deleted",
              "state": "trashed",
              "categoryUuid": "001",
              "overview": { "title": "Old Gmail" },
              "details": { "loginFields": [] }
            }
          ]
        }]
      }]
    }"#;

    #[test]
    fn parse_export_json_happy_path() {
        let summary = parse_export_json(FULL_SAMPLE).expect("parse");
        assert_eq!(summary.source, ImportSource::OnePassword1pux);
        assert_eq!(summary.imported_count(), 3, "login + password + note");
        assert_eq!(summary.skipped_count(), 2, "card + trashed");

        let github = summary
            .items
            .iter()
            .find(|i| i.title == "GitHub")
            .expect("GitHub item");
        assert_eq!(github.kind, ItemKind::Password);
        assert_eq!(github.username.as_deref(), Some("james@personal"));
        assert_eq!(github.url.as_deref(), Some("github.com"));
        assert_eq!(
            github.password.as_deref(),
            Some(b"correct horse battery staple".as_slice()),
        );
        assert_eq!(github.notes.as_deref(), Some("main dev account"));
        assert_eq!(github.created_at_ms, Some(1_700_000_000_000));

        let wifi = summary
            .items
            .iter()
            .find(|i| i.title == "Home WiFi")
            .expect("WiFi item");
        assert_eq!(wifi.kind, ItemKind::Password);
        assert_eq!(
            wifi.password.as_deref(),
            Some(b"home-password-42".as_slice())
        );

        let note = summary
            .items
            .iter()
            .find(|i| i.title == "Server IP")
            .expect("note item");
        assert_eq!(note.kind, ItemKind::SecureNote);
        assert_eq!(note.notes.as_deref(), Some("10.0.0.42"));
    }

    #[test]
    fn parse_export_json_skipped_items_have_reasons() {
        let summary = parse_export_json(FULL_SAMPLE).expect("parse");
        assert!(summary
            .skipped
            .iter()
            .any(|s| s.title == "My Visa" && s.reason.contains("categoryUuid")));
        assert!(summary
            .skipped
            .iter()
            .any(|s| s.title == "Old Gmail" && s.reason.contains("trashed")));
    }

    #[test]
    fn parse_export_json_empty_accounts_errors() {
        match parse_export_json(r#"{"accounts": []}"#) {
            Err(ImportError::OnePasswordEmpty) => {}
            other => panic!("expected OnePasswordEmpty, got {other:?}"),
        }
    }

    #[test]
    fn parse_export_json_malformed_json_errors() {
        match parse_export_json("{ this is not json") {
            Err(ImportError::Malformed { format: "1pux", .. }) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn parse_1pux_roundtrip_through_zip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = make_1pux_file(tmp.path(), FULL_SAMPLE);
        let summary = parse_1pux(&path).expect("parse 1pux");
        assert_eq!(summary.imported_count(), 3);
        assert_eq!(summary.source, ImportSource::OnePassword1pux);
    }

    #[test]
    fn parse_1pux_rejects_zip_without_export_data() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("bad.1pux");
        let file = File::create(&path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let options: FileOptions<'_, ()> = FileOptions::default();
        zip.start_file("readme.txt", options).expect("start");
        zip.write_all(b"not the file you were looking for")
            .expect("write");
        zip.finish().expect("finish");

        match parse_1pux(&path) {
            Err(ImportError::Malformed {
                format: "1pux",
                reason,
            }) => {
                assert!(reason.contains("export.data"));
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn parse_1pux_rejects_non_zip_bytes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("garbage.1pux");
        std::fs::write(&path, b"definitely not a zip archive").expect("write");
        match parse_1pux(&path) {
            Err(ImportError::Malformed { format: "1pux", .. }) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }
}
