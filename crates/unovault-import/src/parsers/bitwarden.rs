//! Bitwarden unencrypted JSON export parser.
//!
//! Bitwarden's export shape is flatter than 1Password's — no
//! accounts/vaults nesting, just a single `items` array. Field names
//! match the Bitwarden API wire format.
//!
//! # Schema
//!
//! Simplified:
//!
//! ```json
//! {
//!   "encrypted": false,
//!   "folders": [...],
//!   "items": [
//!     {
//!       "id": "...",
//!       "type": 1,
//!       "name": "GitHub",
//!       "notes": "optional",
//!       "login": {
//!         "username": "james",
//!         "password": "...",
//!         "totp": "JBSWY3DPEHPK3PXP",
//!         "uris": [{"uri": "https://github.com"}]
//!       },
//!       "creationDate": "2024-01-12T12:34:56.789Z",
//!       "revisionDate": "2024-02-15T09:00:00.000Z"
//!     }
//!   ]
//! }
//! ```
//!
//! # Type mapping
//!
//! | `type` | Bitwarden name | unovault `ItemKind` |
//! |--------|----------------|---------------------|
//! | `1`    | Login          | `Password`          |
//! | `2`    | Secure Note    | `SecureNote`        |
//! | `3`    | Card           | skipped             |
//! | `4`    | Identity       | skipped             |
//!
//! # What is not handled in v1
//!
//! * Encrypted exports (`encrypted: true`) — these use the user's
//!   master password to wrap the payload and we don't want to ask
//!   for it just to re-decrypt on our side. The parser refuses
//!   encrypted exports with [`ImportError::EncryptedSource`].
//! * Attachments — Bitwarden lets users attach files to items;
//!   we ignore the field entirely.
//! * Custom fields — the `fields` array is dropped in v1. Those can
//!   land in a later iteration as custom `FieldKey::Custom(name)`
//!   events.
//! * Organization vaults — multi-user vaults have an
//!   `organizationId`; v1 imports them as if they belonged to the
//!   user's personal vault.

use std::path::Path;

use serde::Deserialize;
use unovault_core::event::ItemKind;

use crate::{ImportError, ImportSource, ImportSummary, ParsedItem, SkippedItem};

// =============================================================================
// SERDE MODELS
// =============================================================================

#[derive(Debug, Deserialize)]
struct Export {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Item {
    #[serde(default, rename = "type")]
    kind: i32,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    login: Option<Login>,
    #[serde(default, rename = "creationDate")]
    creation_date: Option<String>,
    #[serde(default, rename = "revisionDate")]
    revision_date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Login {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<LoginUri>,
}

#[derive(Debug, Deserialize)]
struct LoginUri {
    #[serde(default)]
    uri: Option<String>,
}

// =============================================================================
// ENTRY POINT
// =============================================================================

/// Parse a Bitwarden JSON export from disk.
pub fn parse_json(path: &Path) -> Result<ImportSummary, ImportError> {
    let bytes = std::fs::read(path).map_err(|e| ImportError::FileOpen(e.to_string()))?;
    parse_json_bytes(&bytes)
}

/// Parse already-loaded JSON bytes. Exposed for tests that want to
/// feed a literal string.
pub fn parse_json_bytes(bytes: &[u8]) -> Result<ImportSummary, ImportError> {
    let export: Export = serde_json::from_slice(bytes).map_err(|e| ImportError::Malformed {
        format: "Bitwarden JSON",
        reason: format!("invalid JSON: {e}"),
    })?;

    if export.encrypted {
        return Err(ImportError::EncryptedSource);
    }

    let mut items = Vec::new();
    let mut skipped = Vec::new();

    for item in export.items {
        convert(item, &mut items, &mut skipped);
    }

    Ok(ImportSummary {
        source: ImportSource::BitwardenJson,
        items,
        skipped,
    })
}

// =============================================================================
// CONVERSION
// =============================================================================

fn convert(item: Item, items: &mut Vec<ParsedItem>, skipped: &mut Vec<SkippedItem>) {
    let title = item.name.clone().unwrap_or_else(|| "Untitled".into());

    let kind = match item.kind {
        1 => ItemKind::Password,
        2 => ItemKind::SecureNote,
        3 => {
            skipped.push(SkippedItem {
                title,
                reason: "credit card items are not supported in v1".into(),
            });
            return;
        }
        4 => {
            skipped.push(SkippedItem {
                title,
                reason: "identity items are not supported in v1".into(),
            });
            return;
        }
        other => {
            skipped.push(SkippedItem {
                title,
                reason: format!("unknown Bitwarden type {other}"),
            });
            return;
        }
    };

    let login = item.login.unwrap_or(Login {
        username: None,
        password: None,
        totp: None,
        uris: Vec::new(),
    });

    let url = login.uris.iter().find_map(|u| u.uri.clone());

    let password = login.password.map(|s| s.into_bytes());

    // TOTP strings come as either a bare secret or an `otpauth://`
    // URI. The vault engine stores the raw secret; parsing the URI
    // is a future improvement. v1 treats the whole string as the
    // secret bytes so a later upgrade can re-parse without a
    // migration.
    let totp_secret = login.totp.map(|s| s.into_bytes());

    let created_at_ms = item.creation_date.and_then(parse_iso8601);
    let modified_at_ms = item.revision_date.and_then(parse_iso8601);

    items.push(ParsedItem {
        title,
        kind,
        username: login.username,
        url,
        password,
        totp_secret,
        notes: item.notes,
        created_at_ms,
        modified_at_ms,
    });
}

/// Minimal ISO-8601 parser for `YYYY-MM-DDTHH:MM:SS.sssZ` and the
/// handful of variants Bitwarden actually emits. Returns the value
/// as milliseconds since the Unix epoch.
///
/// Deliberately hand-rolled so we don't take a chrono/time
/// dependency for one call site. If the format ever shifts or gains
/// timezone offsets we don't handle, the function returns `None`
/// and the parsed item loses its timestamps — not a fatal error.
fn parse_iso8601(s: String) -> Option<u64> {
    // Strip a trailing 'Z' or a '+00:00' — both mean UTC.
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut dp = date.split('-');
    let year: i32 = dp.next()?.parse().ok()?;
    let month: u32 = dp.next()?.parse().ok()?;
    let day: u32 = dp.next()?.parse().ok()?;
    let mut tp = time.split(':');
    let hour: u32 = tp.next()?.parse().ok()?;
    let minute: u32 = tp.next()?.parse().ok()?;
    let second_frac = tp.next()?;
    // Drop fractional seconds.
    let second: u32 = second_frac.split('.').next()?.parse().ok()?;

    // Convert a (year, month, day, hour, minute, second) to epoch
    // millis using the civil-from-days formula from the "date"
    // paper. Works from year 1 onwards, which is all we need for
    // credential timestamps.
    let days = days_from_civil(year, month, day)?;
    let total_seconds: i64 =
        days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;
    if total_seconds < 0 {
        return None;
    }
    Some((total_seconds as u64).saturating_mul(1_000))
}

/// Howard Hinnant's days-from-civil algorithm. Returns the day index
/// from 1970-01-01 (day 0) to the given (year, month, day). Works
/// for any proleptic Gregorian date after year 1.
fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (month + if month > 2 { 0u32.wrapping_sub(3) } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era as i64 * 146_097 + doe as i64 - 719_468)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "encrypted": false,
      "items": [
        {
          "type": 1,
          "name": "GitHub",
          "notes": "dev account",
          "login": {
            "username": "james@personal",
            "password": "hunter2",
            "totp": "JBSWY3DPEHPK3PXP",
            "uris": [{"uri": "https://github.com"}]
          },
          "creationDate": "2024-01-12T12:34:56.789Z",
          "revisionDate": "2024-02-15T09:00:00.000Z"
        },
        {
          "type": 2,
          "name": "Server IP",
          "notes": "10.0.0.42"
        },
        {
          "type": 3,
          "name": "Visa",
          "notes": "ignored card"
        }
      ]
    }"#;

    #[test]
    fn parse_json_bytes_happy_path() {
        let summary = parse_json_bytes(SAMPLE.as_bytes()).expect("parse");
        assert_eq!(summary.source, ImportSource::BitwardenJson);
        assert_eq!(summary.imported_count(), 2);
        assert_eq!(summary.skipped_count(), 1);

        let github = summary
            .items
            .iter()
            .find(|i| i.title == "GitHub")
            .expect("github");
        assert_eq!(github.kind, ItemKind::Password);
        assert_eq!(github.username.as_deref(), Some("james@personal"));
        assert_eq!(github.password.as_deref(), Some(b"hunter2".as_slice()));
        assert_eq!(
            github.totp_secret.as_deref(),
            Some(b"JBSWY3DPEHPK3PXP".as_slice()),
        );
        assert_eq!(github.url.as_deref(), Some("https://github.com"));
        assert_eq!(github.notes.as_deref(), Some("dev account"));

        let note = summary
            .items
            .iter()
            .find(|i| i.title == "Server IP")
            .expect("note");
        assert_eq!(note.kind, ItemKind::SecureNote);
        assert_eq!(note.notes.as_deref(), Some("10.0.0.42"));

        let visa_reason = &summary
            .skipped
            .iter()
            .find(|s| s.title == "Visa")
            .expect("visa skipped")
            .reason;
        assert!(visa_reason.contains("credit card"));
    }

    #[test]
    fn encrypted_export_is_refused() {
        let encrypted = r#"{"encrypted": true, "items": []}"#;
        match parse_json_bytes(encrypted.as_bytes()) {
            Err(ImportError::EncryptedSource) => {}
            other => panic!("expected EncryptedSource, got {other:?}"),
        }
    }

    #[test]
    fn identity_items_are_skipped_with_reason() {
        let json = r#"{"encrypted": false, "items": [
          {"type": 4, "name": "My identity"}
        ]}"#;
        let summary = parse_json_bytes(json.as_bytes()).expect("parse");
        assert_eq!(summary.imported_count(), 0);
        assert_eq!(summary.skipped_count(), 1);
        assert!(summary.skipped[0].reason.contains("identity"));
    }

    #[test]
    fn malformed_json_returns_malformed_error() {
        match parse_json_bytes(b"not json") {
            Err(ImportError::Malformed {
                format: "Bitwarden JSON",
                ..
            }) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn iso8601_parser_matches_a_known_timestamp() {
        // 2024-01-12T12:34:56.789Z → 1705062896 seconds → 1705062896000 ms
        let ms = parse_iso8601("2024-01-12T12:34:56.789Z".into()).expect("parse");
        assert_eq!(ms, 1_705_062_896_000);
    }

    #[test]
    fn iso8601_parser_rejects_malformed_input() {
        assert_eq!(parse_iso8601("not a date".into()), None);
        assert_eq!(parse_iso8601("2024".into()), None);
    }

    #[test]
    fn parse_json_reads_from_disk() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("bitwarden.json");
        std::fs::write(&path, SAMPLE).expect("write");
        let summary = parse_json(&path).expect("parse");
        assert_eq!(summary.imported_count(), 2);
    }
}
