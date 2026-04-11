// Panic-policy exception for tests — see unovault-core/src/lib.rs.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! # unovault-native-host
//!
//! Chrome native messaging host. Chrome launches this binary on
//! demand when the extension calls `chrome.runtime.connectNative`.
//! The binary speaks Chrome's native messaging protocol over
//! stdin/stdout and proxies requests to the unovault desktop app
//! over a local Unix socket.
//!
//! # Why a proxy instead of direct vault access
//!
//! The desktop app owns the unlocked vault state (master key in
//! memory, derived sub-keys, item state). A fresh native host
//! process spawned by Chrome has none of that. Rather than giving
//! the host its own copy of the vault material — which would mean
//! re-authenticating with the master password on every Chrome
//! launch — the host forwards requests to the already-running
//! desktop app via a local socket. If the desktop app is not
//! running, the host returns an error and Chrome shows a
//! "unovault is not running" hint.
//!
//! # Framing
//!
//! Chrome's protocol is deliberately small:
//!
//! ```text
//! [u32 length (native endian)] [UTF-8 JSON body]
//! ```
//!
//! Each direction uses the same framing. The length header is the
//! operating system's native byte order — `u32::from_ne_bytes` and
//! `to_ne_bytes` — NOT big-endian. The max payload size Chrome
//! accepts is 1 MiB; we enforce the same bound on reads.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod protocol;

// =============================================================================
// FRAMING
// =============================================================================

/// Maximum frame size Chrome will accept from a native host. See
/// <https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging>.
pub const MAX_FRAME_SIZE: u32 = 1024 * 1024;

/// Errors at the framing layer.
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("stdin closed before a complete frame arrived")]
    StdinClosed,

    #[error("frame header said {length} bytes, which exceeds the {max}-byte limit")]
    FrameTooLarge { length: u32, max: u32 },

    #[error("frame body was not valid UTF-8")]
    NotUtf8,

    #[error("frame body was not valid JSON: {0}")]
    InvalidJson(String),

    #[error("io error while reading/writing a frame: {0}")]
    Io(String),
}

impl From<io::Error> for FrameError {
    fn from(err: io::Error) -> Self {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::StdinClosed
        } else {
            FrameError::Io(err.to_string())
        }
    }
}

/// Read one length-prefixed JSON frame from `reader`. Returns
/// `Ok(None)` on a clean EOF (no bytes yet) so the main loop can
/// exit gracefully; returns `Err(StdinClosed)` if EOF happens in
/// the middle of a frame.
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<Option<T>, FrameError> {
    // Read the 4-byte header one byte at a time so we can
    // distinguish "clean EOF before any bytes" (Ok(None)) from
    // "partial header read" (StdinClosed).
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        let n = reader
            .read(&mut header[filled..])
            .map_err(|e| FrameError::Io(e.to_string()))?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(FrameError::StdinClosed)
            };
        }
        filled += n;
    }
    let length = u32::from_ne_bytes(header);
    if length > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge {
            length,
            max: MAX_FRAME_SIZE,
        });
    }

    let mut body = vec![0u8; length as usize];
    reader.read_exact(&mut body).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::StdinClosed
        } else {
            FrameError::Io(err.to_string())
        }
    })?;

    let text = std::str::from_utf8(&body).map_err(|_| FrameError::NotUtf8)?;
    let value = serde_json::from_str(text).map_err(|e| FrameError::InvalidJson(e.to_string()))?;
    Ok(Some(value))
}

/// Write one length-prefixed JSON frame to `writer`.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), FrameError> {
    let body = serde_json::to_vec(value).map_err(|e| FrameError::InvalidJson(e.to_string()))?;
    let length = u32::try_from(body.len()).map_err(|_| FrameError::FrameTooLarge {
        length: u32::MAX,
        max: MAX_FRAME_SIZE,
    })?;
    if length > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge {
            length,
            max: MAX_FRAME_SIZE,
        });
    }
    writer.write_all(&length.to_ne_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

// =============================================================================
// HOST INSTALLATION MANIFEST
// =============================================================================

/// Contents of the `com.unovault.host.json` manifest Chrome reads
/// to find this binary. On macOS the file lives at
/// `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/
/// com.unovault.host.json`.
///
/// Serialization order matches Chrome's documented schema so the
/// output is byte-stable.
#[derive(Debug, Serialize)]
pub struct HostManifest<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub path: &'a str,
    #[serde(rename = "type")]
    pub kind: &'a str,
    pub allowed_origins: Vec<String>,
}

impl<'a> HostManifest<'a> {
    /// Build a default manifest pointing at the installed binary
    /// path + the Chrome extension ID(s) authorised to connect.
    pub fn for_extension(binary_path: &'a str, extension_ids: &[&str]) -> Self {
        Self {
            name: "com.unovault.host",
            description: "unovault Chrome extension bridge",
            path: binary_path,
            kind: "stdio",
            allowed_origins: extension_ids
                .iter()
                .map(|id| format!("chrome-extension://{id}/"))
                .collect(),
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct Envelope {
        request_id: String,
        payload: String,
    }

    #[test]
    fn write_then_read_frame_round_trips() {
        let mut buf = Vec::new();
        let original = Envelope {
            request_id: "abc".into(),
            payload: "hello world".into(),
        };
        write_frame(&mut buf, &original).expect("write");

        let mut cursor = Cursor::new(buf);
        let decoded: Envelope = read_frame(&mut cursor).expect("read").expect("some");
        assert_eq!(decoded, original);
    }

    #[test]
    fn read_frame_on_clean_eof_returns_none() {
        let mut empty: &[u8] = &[];
        let result: Result<Option<Envelope>, FrameError> = read_frame(&mut empty);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn read_frame_on_partial_header_errors_as_stdin_closed() {
        let mut partial: &[u8] = &[0x01, 0x02];
        let result: Result<Option<Envelope>, FrameError> = read_frame(&mut partial);
        assert!(matches!(result, Err(FrameError::StdinClosed)));
    }

    #[test]
    fn read_frame_on_partial_body_errors_as_stdin_closed() {
        // Claim 100 bytes, supply 10.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100u32.to_ne_bytes());
        bytes.extend_from_slice(&[0u8; 10]);
        let mut cursor = Cursor::new(bytes);
        let result: Result<Option<Envelope>, FrameError> = read_frame(&mut cursor);
        assert!(matches!(result, Err(FrameError::StdinClosed)));
    }

    #[test]
    fn read_frame_rejects_oversize_length() {
        let mut bytes = Vec::new();
        // Claim 2 MiB, exceeds the 1 MiB cap.
        bytes.extend_from_slice(&(MAX_FRAME_SIZE + 1).to_ne_bytes());
        let mut cursor = Cursor::new(bytes);
        let result: Result<Option<Envelope>, FrameError> = read_frame(&mut cursor);
        assert!(matches!(result, Err(FrameError::FrameTooLarge { .. })));
    }

    #[test]
    fn read_frame_rejects_invalid_json() {
        let body = b"not json at all";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(body.len() as u32).to_ne_bytes());
        bytes.extend_from_slice(body);
        let mut cursor = Cursor::new(bytes);
        let result: Result<Option<Envelope>, FrameError> = read_frame(&mut cursor);
        assert!(matches!(result, Err(FrameError::InvalidJson(_))));
    }

    #[test]
    fn host_manifest_serializes_with_chrome_field_names() {
        let m = HostManifest::for_extension("/usr/local/bin/unovault-native-host", &["aabbcc"]);
        let json = serde_json::to_string_pretty(&m).expect("serialize");
        assert!(json.contains("\"name\": \"com.unovault.host\""));
        assert!(json.contains("\"type\": \"stdio\""));
        assert!(json.contains("\"allowed_origins\""));
        assert!(json.contains("chrome-extension://aabbcc/"));
    }

    #[test]
    fn host_manifest_supports_multiple_extension_ids() {
        let m = HostManifest::for_extension("/path", &["aa", "bb"]);
        assert_eq!(m.allowed_origins.len(), 2);
    }
}
