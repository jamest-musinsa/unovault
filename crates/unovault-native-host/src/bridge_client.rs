//! Client side of the Unix-socket protocol to the desktop app.
//!
//! The native host process is short-lived: Chrome spawns it on
//! `connectNative`, the host accepts one Chrome connection, and
//! exits when Chrome closes the pipe. So each socket session is
//! also short-lived — we open a new socket per forwarded request
//! for simplicity. A future iteration can pool the connection if
//! latency becomes a problem.
//!
//! # Protocol
//!
//! Newline-delimited JSON in both directions. Matches the server
//! side in `unovault-app::bridge` — both halves define their own
//! matching types so neither crate has to depend on the other.
//!
//! # Error handling
//!
//! Any transport failure (socket missing, connection refused,
//! timeout) maps to a single `NativeHostUnavailable` error the
//! extension displays as "unovault is not running." A structured
//! error from the server side is passed through unchanged so the
//! extension can render the real reason.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::protocol::{HostRequestPayload, HostResponsePayload, ItemRef};

/// How long to wait for the desktop app to respond to one request.
/// Generous upper bound so a slow argon2 unlock or a big vault scan
/// doesn't trip the timeout; tight enough that a dead socket
/// surfaces quickly.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve the default socket path the desktop app binds to.
///
/// The `UNOVAULT_BRIDGE_SOCKET` environment variable overrides the
/// default — useful for dev and integration tests.
pub fn default_socket_path() -> PathBuf {
    if let Ok(override_path) = std::env::var("UNOVAULT_BRIDGE_SOCKET") {
        return PathBuf::from(override_path);
    }
    let base = dirs::data_dir().unwrap_or_else(std::env::temp_dir);
    base.join("unovault").join("bridge.sock")
}

// -----------------------------------------------------------------------------
// Wire types — deliberately duplicated from the `unovault-app::bridge`
// module. These stay in lockstep manually until a future sprint extracts
// them into a shared `unovault-bridge-protocol` crate.
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeRequest {
    pub request_id: String,
    pub payload: BridgeRequestPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum BridgeRequestPayload {
    Ping,
    ListMatchingItems { origin: String },
    GetPassword { item_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeResponse {
    pub request_id: String,
    pub payload: BridgeResponsePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BridgeResponsePayload {
    Pong { version: String },
    ListMatchingItems { items: Vec<BridgeItemRef> },
    GetPassword { password: String },
    Error { category: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeItemRef {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
}

// -----------------------------------------------------------------------------
// Forwarding
// -----------------------------------------------------------------------------

/// Send one request to the desktop app's bridge socket and return
/// the response. On any transport failure, returns an `Error`
/// response shaped like the server would have sent one, so the
/// main loop's match arms stay uniform.
pub fn forward(
    socket_path: &Path,
    request_id: &str,
    payload: HostRequestPayload,
) -> HostResponsePayload {
    let bridge_payload = match to_bridge(payload) {
        Some(b) => b,
        None => {
            return HostResponsePayload::Error {
                category: "NativeHostBug".into(),
                message:
                    "internal: attempted to forward a payload that should have been handled locally"
                        .into(),
            };
        }
    };

    let stream = match UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(err) => {
            return HostResponsePayload::Error {
                category: "NativeHostUnavailable".into(),
                message: format!(
                    "could not connect to the unovault desktop app at {}: {err}",
                    socket_path.display()
                ),
            };
        }
    };
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));

    match one_shot(stream, request_id, bridge_payload) {
        Ok(bridge_response) => from_bridge(bridge_response.payload),
        Err(err) => HostResponsePayload::Error {
            category: "NativeHostUnavailable".into(),
            message: err,
        },
    }
}

/// Encode the request, write it, read one line of response. Errors
/// stringify into a short developer-readable message; categorisation
/// happens one level up.
fn one_shot(
    stream: UnixStream,
    request_id: &str,
    payload: BridgeRequestPayload,
) -> Result<BridgeResponse, String> {
    let request = BridgeRequest {
        request_id: request_id.to_string(),
        payload,
    };
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    let body = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    writer.write_all(&body).map_err(|e| e.to_string())?;
    writer.write_all(b"\n").map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let read = reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if read == 0 {
        return Err("bridge socket closed before a response was written".into());
    }
    serde_json::from_str(line.trim())
        .map_err(|e| format!("bridge response was not valid JSON: {e}"))
}

/// Map a native-host request payload to the bridge's wire type.
/// `Ping` is intentionally handled locally in `main.rs` — this
/// helper returns `None` for it so a caller that routes pings
/// through `forward` by mistake lands in the `NativeHostBug`
/// branch.
fn to_bridge(payload: HostRequestPayload) -> Option<BridgeRequestPayload> {
    match payload {
        HostRequestPayload::Ping => None,
        HostRequestPayload::ListMatchingItems { origin } => {
            Some(BridgeRequestPayload::ListMatchingItems { origin })
        }
        HostRequestPayload::GetPassword { item_id } => {
            Some(BridgeRequestPayload::GetPassword { item_id })
        }
    }
}

/// Map a bridge response back to the native-host protocol shape
/// the extension expects.
fn from_bridge(payload: BridgeResponsePayload) -> HostResponsePayload {
    match payload {
        BridgeResponsePayload::Pong { version } => HostResponsePayload::Pong { version },
        BridgeResponsePayload::ListMatchingItems { items } => {
            HostResponsePayload::ListMatchingItems {
                items: items
                    .into_iter()
                    .map(|i| ItemRef {
                        id: i.id,
                        title: i.title,
                        username: i.username,
                    })
                    .collect(),
            }
        }
        BridgeResponsePayload::GetPassword { password } => {
            HostResponsePayload::GetPassword { password }
        }
        BridgeResponsePayload::Error { category, message } => {
            HostResponsePayload::Error { category, message }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// Stand up a minimal Unix socket server in a temp dir, run one
    /// `forward` call against it, and assert the server saw the
    /// right framed request and returned the canned response to the
    /// client unchanged.
    fn with_mock_server<F>(canned: BridgeResponse, verify_request: F) -> HostResponsePayload
    where
        F: FnOnce(BridgeRequest) + Send + 'static,
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("mock.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");

        let server_handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            // Read one line.
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).expect("read");
            let request_text = std::str::from_utf8(&buf[..n])
                .expect("utf8")
                .trim_end_matches('\n');
            let request: BridgeRequest =
                serde_json::from_str(request_text).expect("decode request");
            verify_request(request);
            // Write canned response.
            let body = serde_json::to_vec(&canned).expect("encode");
            stream.write_all(&body).expect("write");
            stream.write_all(b"\n").expect("newline");
            stream.flush().expect("flush");
        });

        let response = forward(
            &sock_path,
            "req-1",
            HostRequestPayload::ListMatchingItems {
                origin: "https://github.com".into(),
            },
        );
        server_handle.join().expect("server thread");
        // Keep dir alive until after forward() completes.
        drop(dir);
        response
    }

    #[test]
    fn forward_list_matching_items_round_trips_through_socket() {
        let canned = BridgeResponse {
            request_id: "req-1".into(),
            payload: BridgeResponsePayload::ListMatchingItems {
                items: vec![BridgeItemRef {
                    id: "abc".into(),
                    title: "GitHub".into(),
                    username: Some("james".into()),
                }],
            },
        };
        let response = with_mock_server(canned, |request| {
            assert_eq!(request.request_id, "req-1");
            match request.payload {
                BridgeRequestPayload::ListMatchingItems { origin } => {
                    assert_eq!(origin, "https://github.com");
                }
                other => panic!("expected ListMatchingItems, got {other:?}"),
            }
        });

        match response {
            HostResponsePayload::ListMatchingItems { items } => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].id, "abc");
                assert_eq!(items[0].title, "GitHub");
                assert_eq!(items[0].username.as_deref(), Some("james"));
            }
            other => panic!("expected ListMatchingItems, got {other:?}"),
        }
    }

    #[test]
    fn forward_error_response_passes_through_unchanged() {
        let canned = BridgeResponse {
            request_id: "req-1".into(),
            payload: BridgeResponsePayload::Error {
                category: "UserActionable".into(),
                message: "vault is locked".into(),
            },
        };
        let response = with_mock_server(canned, |_| {});
        match response {
            HostResponsePayload::Error { category, message } => {
                assert_eq!(category, "UserActionable");
                assert_eq!(message, "vault is locked");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn forward_returns_native_host_unavailable_when_socket_missing() {
        let response = forward(
            Path::new("/tmp/nonexistent-unovault-bridge.sock"),
            "r",
            HostRequestPayload::ListMatchingItems {
                origin: "https://x.y".into(),
            },
        );
        match response {
            HostResponsePayload::Error { category, .. } => {
                assert_eq!(category, "NativeHostUnavailable");
            }
            other => panic!("expected NativeHostUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn forward_ping_is_rejected_as_bug_because_caller_should_handle_locally() {
        let response = forward(
            Path::new("/tmp/does-not-matter.sock"),
            "r",
            HostRequestPayload::Ping,
        );
        match response {
            HostResponsePayload::Error { category, .. } => {
                assert_eq!(category, "NativeHostBug");
            }
            other => panic!("expected NativeHostBug, got {other:?}"),
        }
    }
}
