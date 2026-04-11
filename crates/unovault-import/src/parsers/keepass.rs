//! KeePass / KeePassXC plain XML export parser (KDBX4 flavour).
//!
//! KeePassXC can export the database as an unencrypted XML file.
//! This is the path we support in v1. The binary KDBX format (with
//! its own crypto) is out of scope — users who want that should
//! decrypt in KeePassXC and export the plain XML.
//!
//! # Schema
//!
//! Simplified:
//!
//! ```xml
//! <KeePassFile>
//!   <Meta>...</Meta>
//!   <Root>
//!     <Group>
//!       <Name>Root</Name>
//!       <Entry>
//!         <String><Key>Title</Key><Value>GitHub</Value></String>
//!         <String><Key>UserName</Key><Value>james</Value></String>
//!         <String><Key>Password</Key><Value>hunter2</Value></String>
//!         <String><Key>URL</Key><Value>https://github.com</Value></String>
//!         <String><Key>Notes</Key><Value>dev account</Value></String>
//!         <Times>
//!           <CreationTime>2024-01-12T12:34:56Z</CreationTime>
//!           <LastModificationTime>2024-02-15T09:00:00Z</LastModificationTime>
//!         </Times>
//!       </Entry>
//!       <Group>
//!         <Name>Subgroup</Name>
//!         <Entry>...</Entry>
//!       </Group>
//!     </Group>
//!   </Root>
//! </KeePassFile>
//! ```
//!
//! # Field mapping
//!
//! KeePass stores everything as string key/value pairs. We extract
//! the five well-known keys and drop the rest:
//!
//! | KeePass key | unovault field      |
//! |-------------|---------------------|
//! | `Title`     | `title`             |
//! | `UserName`  | `username`          |
//! | `Password`  | `password` (bytes)  |
//! | `URL`       | `url`               |
//! | `Notes`     | `notes`             |
//!
//! An entry is classified as [`ItemKind::Password`] if it has a
//! `Password` field, otherwise [`ItemKind::SecureNote`] if it has
//! `Notes`, otherwise it is skipped with a reason.
//!
//! # What is not handled in v1
//!
//! * Attachments — `Binary` entries are ignored.
//! * Custom string fields — only the five well-known keys above
//!   make it through. Everything else is dropped.
//! * AutoType sequences and window matching rules.
//! * History entries — KeePass keeps a per-entry `History`
//!   subtree with prior revisions; v1 takes only the current value.
//! * Recycle bin entries — KeePassXC puts deleted items in a
//!   `Recycle Bin` group. We still import them; a future iteration
//!   should match the `EnableRecycleBin` meta flag and skip that
//!   group by name.

use std::path::Path;

use serde::Deserialize;
use unovault_core::event::ItemKind;

use crate::{ImportError, ImportSource, ImportSummary, ParsedItem, SkippedItem};

// =============================================================================
// SERDE MODELS
// =============================================================================

#[derive(Debug, Deserialize)]
struct KeePassFile {
    #[serde(rename = "Root", default)]
    root: Option<Root>,
}

#[derive(Debug, Deserialize, Default)]
struct Root {
    #[serde(rename = "Group", default)]
    groups: Vec<Group>,
}

#[derive(Debug, Deserialize, Default)]
struct Group {
    #[serde(rename = "Name", default)]
    #[allow(dead_code)]
    name: Option<String>,
    #[serde(rename = "Entry", default)]
    entries: Vec<Entry>,
    #[serde(rename = "Group", default)]
    groups: Vec<Group>,
}

#[derive(Debug, Deserialize, Default)]
struct Entry {
    #[serde(rename = "String", default)]
    strings: Vec<StringField>,
    #[serde(rename = "Times", default)]
    times: Option<Times>,
}

#[derive(Debug, Deserialize)]
struct StringField {
    #[serde(rename = "Key", default)]
    key: Option<String>,
    #[serde(rename = "Value", default)]
    value: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Times {
    #[serde(rename = "CreationTime", default)]
    creation: Option<String>,
    #[serde(rename = "LastModificationTime", default)]
    last_modification: Option<String>,
}

// =============================================================================
// ENTRY POINT
// =============================================================================

/// Parse a KeePass plain-XML export from disk.
pub fn parse_xml(path: &Path) -> Result<ImportSummary, ImportError> {
    let bytes = std::fs::read(path).map_err(|e| ImportError::FileOpen(e.to_string()))?;
    parse_xml_bytes(&bytes)
}

/// Parse already-loaded XML bytes. Exposed for tests.
pub fn parse_xml_bytes(bytes: &[u8]) -> Result<ImportSummary, ImportError> {
    let text = std::str::from_utf8(bytes).map_err(|e| ImportError::Malformed {
        format: "KeePass XML",
        reason: format!("file is not UTF-8: {e}"),
    })?;

    let file: KeePassFile = quick_xml::de::from_str(text).map_err(|e| ImportError::Malformed {
        format: "KeePass XML",
        reason: format!("invalid XML: {e}"),
    })?;

    let mut items = Vec::new();
    let mut skipped = Vec::new();

    if let Some(root) = file.root {
        for group in root.groups {
            walk_group(group, &mut items, &mut skipped);
        }
    }

    Ok(ImportSummary {
        source: ImportSource::KeepassXml,
        items,
        skipped,
    })
}

// =============================================================================
// CONVERSION
// =============================================================================

fn walk_group(group: Group, items: &mut Vec<ParsedItem>, skipped: &mut Vec<SkippedItem>) {
    for entry in group.entries {
        convert_entry(entry, items, skipped);
    }
    for child in group.groups {
        walk_group(child, items, skipped);
    }
}

fn convert_entry(entry: Entry, items: &mut Vec<ParsedItem>, skipped: &mut Vec<SkippedItem>) {
    let mut title = None;
    let mut username = None;
    let mut password = None;
    let mut url = None;
    let mut notes = None;

    for field in entry.strings {
        let Some(key) = field.key else { continue };
        let value = field.value;
        match key.as_str() {
            "Title" => title = value,
            "UserName" => username = value,
            "Password" => password = value,
            "URL" => url = value,
            "Notes" => notes = value,
            _ => {}
        }
    }

    let title = title.unwrap_or_else(|| "Untitled".into());

    // KeePassXC always emits the five well-known keys even if the
    // value is empty, so filter placeholders before classifying.
    // An entry whose Password is "" is a SecureNote, not a Password.
    let username = username.filter(|s| !s.is_empty());
    let url = url.filter(|s| !s.is_empty());
    let notes = notes.filter(|s| !s.is_empty());
    let password = password.filter(|s| !s.is_empty()).map(|s| s.into_bytes());

    let kind = if password.is_some() {
        ItemKind::Password
    } else if notes.is_some() {
        ItemKind::SecureNote
    } else {
        skipped.push(SkippedItem {
            title,
            reason: "entry has no Password or Notes field".into(),
        });
        return;
    };

    let (created_at_ms, modified_at_ms) = entry
        .times
        .map(|t| {
            (
                t.creation.and_then(parse_iso8601),
                t.last_modification.and_then(parse_iso8601),
            )
        })
        .unwrap_or((None, None));

    items.push(ParsedItem {
        title,
        kind,
        username,
        url,
        password,
        totp_secret: None,
        notes,
        created_at_ms,
        modified_at_ms,
    });
}

/// KeePass emits ISO-8601 with a trailing `Z`. Share the same
/// civil-days formula the Bitwarden parser uses — re-implementing is
/// cheaper than exposing a crate-internal util that exists for two
/// callers.
fn parse_iso8601(s: String) -> Option<u64> {
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut dp = date.split('-');
    let year: i32 = dp.next()?.parse().ok()?;
    let month: u32 = dp.next()?.parse().ok()?;
    let day: u32 = dp.next()?.parse().ok()?;
    let mut tp = time.split(':');
    let hour: u32 = tp.next()?.parse().ok()?;
    let minute: u32 = tp.next()?.parse().ok()?;
    let second: u32 = tp.next()?.split('.').next()?.parse().ok()?;

    let days = days_from_civil(year, month, day)?;
    let total_seconds: i64 =
        days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;
    if total_seconds < 0 {
        return None;
    }
    Some((total_seconds as u64).saturating_mul(1_000))
}

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

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta><DatabaseName>Test</DatabaseName></Meta>
  <Root>
    <Group>
      <Name>Root</Name>
      <Entry>
        <String><Key>Title</Key><Value>GitHub</Value></String>
        <String><Key>UserName</Key><Value>james@personal</Value></String>
        <String><Key>Password</Key><Value>hunter2</Value></String>
        <String><Key>URL</Key><Value>https://github.com</Value></String>
        <String><Key>Notes</Key><Value>dev account</Value></String>
        <Times>
          <CreationTime>2024-01-12T12:34:56Z</CreationTime>
          <LastModificationTime>2024-02-15T09:00:00Z</LastModificationTime>
        </Times>
      </Entry>
      <Group>
        <Name>Servers</Name>
        <Entry>
          <String><Key>Title</Key><Value>Server IP</Value></String>
          <String><Key>UserName</Key><Value></Value></String>
          <String><Key>Password</Key><Value></Value></String>
          <String><Key>URL</Key><Value></Value></String>
          <String><Key>Notes</Key><Value>10.0.0.42</Value></String>
        </Entry>
        <Entry>
          <String><Key>Title</Key><Value>Empty Entry</Value></String>
          <String><Key>UserName</Key><Value></Value></String>
        </Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>"#;

    #[test]
    fn parse_xml_bytes_happy_path() {
        let summary = parse_xml_bytes(SAMPLE.as_bytes()).expect("parse");
        assert_eq!(summary.source, ImportSource::KeepassXml);
        assert_eq!(summary.imported_count(), 2, "github + server ip");
        assert_eq!(summary.skipped_count(), 1, "empty entry");

        let github = summary
            .items
            .iter()
            .find(|i| i.title == "GitHub")
            .expect("github");
        assert_eq!(github.kind, ItemKind::Password);
        assert_eq!(github.username.as_deref(), Some("james@personal"));
        assert_eq!(github.password.as_deref(), Some(b"hunter2".as_slice()));
        assert_eq!(github.url.as_deref(), Some("https://github.com"));
        assert_eq!(github.notes.as_deref(), Some("dev account"));
        assert_eq!(github.created_at_ms, Some(1_705_062_896_000));

        let note = summary
            .items
            .iter()
            .find(|i| i.title == "Server IP")
            .expect("server ip");
        assert_eq!(note.kind, ItemKind::SecureNote);
        assert_eq!(note.notes.as_deref(), Some("10.0.0.42"));
        assert!(note.password.is_none(), "empty password must be dropped");
        assert!(note.username.is_none(), "empty username must be dropped");
    }

    #[test]
    fn parse_xml_bytes_skipped_entry_has_reason() {
        let summary = parse_xml_bytes(SAMPLE.as_bytes()).expect("parse");
        let empty = summary
            .skipped
            .iter()
            .find(|s| s.title == "Empty Entry")
            .expect("empty entry skipped");
        assert!(empty.reason.contains("Password"));
    }

    #[test]
    fn deeply_nested_groups_are_walked() {
        let xml = r#"<?xml version="1.0"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>L0</Name>
      <Group>
        <Name>L1</Name>
        <Group>
          <Name>L2</Name>
          <Entry>
            <String><Key>Title</Key><Value>Deep</Value></String>
            <String><Key>Password</Key><Value>p</Value></String>
          </Entry>
        </Group>
      </Group>
    </Group>
  </Root>
</KeePassFile>"#;
        let summary = parse_xml_bytes(xml.as_bytes()).expect("parse");
        assert_eq!(summary.imported_count(), 1);
        assert_eq!(summary.items[0].title, "Deep");
    }

    #[test]
    fn malformed_xml_returns_malformed_error() {
        match parse_xml_bytes(b"<KeePassFile><Root><Group>unterminated") {
            Err(ImportError::Malformed {
                format: "KeePass XML",
                ..
            }) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn non_utf8_returns_malformed_error() {
        let bytes = [0xFF, 0xFE, 0xFD];
        match parse_xml_bytes(&bytes) {
            Err(ImportError::Malformed {
                format: "KeePass XML",
                reason,
            }) => assert!(reason.contains("UTF-8")),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn empty_root_is_ok_with_zero_items() {
        let xml = r#"<?xml version="1.0"?><KeePassFile><Root></Root></KeePassFile>"#;
        let summary = parse_xml_bytes(xml.as_bytes()).expect("parse");
        assert_eq!(summary.imported_count(), 0);
        assert_eq!(summary.skipped_count(), 0);
    }

    #[test]
    fn parse_xml_reads_from_disk() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("keepass.xml");
        std::fs::write(&path, SAMPLE).expect("write");
        let summary = parse_xml(&path).expect("parse");
        assert_eq!(summary.imported_count(), 2);
    }
}
