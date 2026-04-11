//! Local IPC bridge server for the Chrome extension / native host.
//!
//! This module is the "server side" of the native-host ↔ desktop-app
//! pipe. The `unovault-native-host` binary, spawned by Chrome per the
//! native messaging spec, connects to a Unix socket in the user's
//! application support directory and forwards JSON-RPC frames over
//! it. This module owns the listener, the per-connection handler,
//! and the dispatch into [`crate::state::AppState`].
//!
//! # Why a Unix socket, not a TCP port
//!
//! * Local-only: bind to `~/Library/Application Support/unovault/bridge.sock`
//!   with mode 0600, so the filesystem ACL is the only authentication
//!   we need. No port to pick, no firewall surface.
//! * Chrome native messaging already assumes a local-only transport;
//!   exposing a TCP port would invert the threat model.
//! * Works on macOS, Linux, and (since Windows 10) Windows — we can
//!   drop Windows support onto the same code path later.
//!
//! # Threading model
//!
//! `spawn` starts one background OS thread that owns the listener.
//! Each incoming connection gets its own handler thread. A handler
//! reads newline-framed JSON from the socket, dispatches against the
//! shared `Arc<RwLock<Option<Vault>>>`, and writes a single-line JSON
//! response back per request. When the other end closes, the handler
//! exits.
//!
//! The listener thread is a daemon thread from the OS's point of
//! view — on process exit it dies with the rest of the app.
//! Best-effort socket file cleanup happens via a `Drop` guard on the
//! `BridgeServer` handle that `run()` holds onto for the lifetime
//! of the process.
//!
//! # What this module does not do
//!
//! * **No framing compatibility with Chrome's native messaging
//!   directly.** Chrome's framing (length-prefixed binary) is handled
//!   by the `unovault-native-host` process. This module speaks
//!   newline-delimited JSON over the Unix socket, which is simpler
//!   and easier to test with `nc` during development.
//! * **No auth beyond filesystem perms.** v1 treats "can open the
//!   socket file" as proof of user identity. A future sprint adds a
//!   per-session token that the native host reads from a sibling
//!   file with the same perms; that is a small addition on top of
//!   the current skeleton.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::thread;

use serde::{Deserialize, Serialize};
use unovault_core::vault::Vault;

/// Handle returned by [`spawn`]. Dropping it removes the socket file
/// so a future app run can re-bind cleanly. The listener thread is a
/// daemon and dies with the process; the handle's only job is the
/// file cleanup.
pub struct BridgeServer {
    socket_path: PathBuf,
}

impl Drop for BridgeServer {
    fn drop(&mut self) {
        // Best-effort: if the cleanup fails (missing file, permissions
        // changed out from under us), the next startup's pre-bind
        // unlink will catch it.
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl BridgeServer {
    /// Path the listener is bound to. Exposed so tests and dev
    /// tooling can connect without re-deriving the location.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

// =============================================================================
// PROTOCOL — mirrors the unovault-native-host JSON-RPC shape.
// =============================================================================
//
// These types are duplicated from `unovault_native_host::protocol` on
// purpose. The native host crate is a binary build target; pulling it
// in as a library dependency would drag its main.rs and serde
// configuration into the desktop app's feature set. The duplication
// is small (two enums + two structs) and a future sprint can merge
// them into a tiny `unovault-bridge-protocol` crate that both sides
// depend on.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeRequest {
    pub request_id: String,
    pub payload: BridgeRequestPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum BridgeRequestPayload {
    /// Liveness probe. Replies with [`BridgeResponsePayload::Pong`].
    Ping,

    /// Return every item whose URL matches the given origin. v1
    /// match policy is exact origin equality against `item.url`
    /// after normalising both to the `scheme://host[:port]` prefix.
    /// More sophisticated matching (public-suffix, path, subdomain)
    /// lands with the save-on-submit flow.
    ListMatchingItems { origin: String },

    /// Return the plaintext password for one item. The bridge layer
    /// refuses this if the vault is locked.
    GetPassword { item_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeResponse {
    pub request_id: String,
    pub payload: BridgeResponsePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BridgeResponsePayload {
    Pong { version: String },
    ListMatchingItems { items: Vec<BridgeItemRef> },
    GetPassword { password: String },
    Error { category: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeItemRef {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
}

/// Crate version reported to `Ping` requests.
const BRIDGE_VERSION: &str = env!("CARGO_PKG_VERSION");

// =============================================================================
// SPAWN + LISTENER
// =============================================================================

/// Default path for the bridge socket on the current platform.
///
/// On macOS this resolves to
/// `~/Library/Application Support/unovault/bridge.sock`. The
/// `UNOVAULT_BRIDGE_SOCKET` environment variable overrides the
/// default — set it during development when you want the socket
/// somewhere other than the user's real data dir.
pub fn default_socket_path() -> PathBuf {
    if let Ok(override_path) = std::env::var("UNOVAULT_BRIDGE_SOCKET") {
        return PathBuf::from(override_path);
    }
    let base = dirs::data_dir().unwrap_or_else(std::env::temp_dir);
    base.join("unovault").join("bridge.sock")
}

/// Start the listener thread. Creates the parent directory if it
/// doesn't exist, removes any stale socket file, binds, and spawns
/// a daemon worker. Returns a [`BridgeServer`] whose drop cleans up
/// the socket file — callers typically stash it in `AppState`.
pub fn spawn(
    socket_path: PathBuf,
    vault: Arc<RwLock<Option<Vault>>>,
) -> std::io::Result<BridgeServer> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A stale socket file from a previous run blocks bind with
    // EADDRINUSE. Removing it is the standard Unix pattern — the
    // file is never meaningful on its own, only while a process
    // holds an fd on it.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;

    // Tighten permissions to user-only so another local user can't
    // sniff the socket. Inherited umask could otherwise widen this.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    thread::Builder::new()
        .name("unovault-bridge".into())
        .spawn(move || accept_loop(listener, vault))?;

    Ok(BridgeServer { socket_path })
}

/// Accept loop. One connection per spawn — simple enough that a
/// dedicated thread per connection is fine on the v1 scale of one
/// Chrome extension.
fn accept_loop(listener: UnixListener, vault: Arc<RwLock<Option<Vault>>>) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let vault = Arc::clone(&vault);
                // Detach the handler; a panic in one connection does
                // not take down the listener. The handler swallows
                // its errors and closes the socket on any failure.
                let _ = thread::Builder::new()
                    .name("unovault-bridge-conn".into())
                    .spawn(move || handle_connection(stream, vault));
            }
            Err(_) => {
                // Accept failure is almost always "listener was
                // closed" — exit the loop so the thread can die.
                return;
            }
        }
    }
}

/// Per-connection protocol handler. Reads newline-delimited JSON
/// [`BridgeRequest`] frames, dispatches them, and writes the matching
/// [`BridgeResponse`] frames. On any parse or IO error, closes the
/// stream and returns.
fn handle_connection(stream: UnixStream, vault: Arc<RwLock<Option<Vault>>>) {
    let reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut writer = stream;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => return,
        };
        if line.trim().is_empty() {
            continue;
        }
        let request: BridgeRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(err) => {
                let resp = BridgeResponse {
                    request_id: "malformed".into(),
                    payload: BridgeResponsePayload::Error {
                        category: "BadRequest".into(),
                        message: format!("could not parse request: {err}"),
                    },
                };
                if write_response(&mut writer, &resp).is_err() {
                    return;
                }
                continue;
            }
        };
        let response = dispatch(request, &vault);
        if write_response(&mut writer, &response).is_err() {
            return;
        }
    }
}

fn write_response(writer: &mut UnixStream, response: &BridgeResponse) -> std::io::Result<()> {
    let body = serde_json::to_vec(response)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    writer.write_all(&body)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

// =============================================================================
// DISPATCH
// =============================================================================

/// Route one request against the vault state. Pure function of
/// (request, vault) — easy to unit-test without touching the socket
/// layer, which is exactly how the tests at the bottom of this
/// module exercise it.
pub fn dispatch(request: BridgeRequest, vault: &Arc<RwLock<Option<Vault>>>) -> BridgeResponse {
    let request_id = request.request_id.clone();
    let payload = match request.payload {
        BridgeRequestPayload::Ping => BridgeResponsePayload::Pong {
            version: BRIDGE_VERSION.into(),
        },
        BridgeRequestPayload::ListMatchingItems { origin } => match list_matching(&origin, vault) {
            Ok(items) => BridgeResponsePayload::ListMatchingItems { items },
            Err(err) => err,
        },
        BridgeRequestPayload::GetPassword { item_id } => match get_password(&item_id, vault) {
            Ok(password) => BridgeResponsePayload::GetPassword { password },
            Err(err) => err,
        },
    };
    BridgeResponse {
        request_id,
        payload,
    }
}

fn list_matching(
    origin: &str,
    vault: &Arc<RwLock<Option<Vault>>>,
) -> Result<Vec<BridgeItemRef>, BridgeResponsePayload> {
    let guard = vault.read().map_err(|_| BridgeResponsePayload::Error {
        category: "BugInUnovault".into(),
        message: "vault lock poisoned".into(),
    })?;
    let vault = guard.as_ref().ok_or(BridgeResponsePayload::Error {
        category: "UserActionable".into(),
        message: "vault is locked".into(),
    })?;

    let target = normalise_origin(origin);
    let items = vault
        .items()
        .filter_map(|item| {
            let item_origin = item.url.as_deref().map(normalise_origin);
            if item_origin.as_deref() == Some(target.as_str()) {
                Some(BridgeItemRef {
                    id: item.id.0.hyphenated().to_string(),
                    title: item.title.clone(),
                    username: item.username.clone(),
                })
            } else {
                None
            }
        })
        .collect();
    Ok(items)
}

fn get_password(
    item_id: &str,
    vault: &Arc<RwLock<Option<Vault>>>,
) -> Result<String, BridgeResponsePayload> {
    let guard = vault.read().map_err(|_| BridgeResponsePayload::Error {
        category: "BugInUnovault".into(),
        message: "vault lock poisoned".into(),
    })?;
    let vault = guard.as_ref().ok_or(BridgeResponsePayload::Error {
        category: "UserActionable".into(),
        message: "vault is locked".into(),
    })?;

    let parsed = uuid::Uuid::parse_str(item_id).map_err(|_| BridgeResponsePayload::Error {
        category: "UserActionable".into(),
        message: "item id is not a valid UUID".into(),
    })?;
    let item = vault
        .get(&unovault_core::ItemId(parsed))
        .ok_or(BridgeResponsePayload::Error {
            category: "UserActionable".into(),
            message: "item not found".into(),
        })?;
    let bytes = item.password.as_ref().ok_or(BridgeResponsePayload::Error {
        category: "UserActionable".into(),
        message: "item has no password field".into(),
    })?;
    // Password plaintext lives in the vault as raw bytes; we send
    // it over the Unix socket as UTF-8 text. Non-UTF-8 passwords
    // are rare but possible (a user pasting binary entropy) — in
    // that case we fall back to an error rather than silently
    // corrupting the value with a lossy conversion.
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| BridgeResponsePayload::Error {
            category: "UserActionable".into(),
            message: "stored password is not valid UTF-8 and cannot be surfaced to the browser"
                .into(),
        })
}

/// Normalise an origin or URL for matching. Takes either
/// `"https://github.com"` or `"github.com"` and returns the scheme
/// + host form. Ports are preserved. Trailing slashes are dropped.
fn normalise_origin(input: &str) -> String {
    let trimmed = input.trim().trim_end_matches('/');
    // If there's no scheme, assume https — every item URL the user
    // types in lacks one by convention.
    if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::tempdir;
    use unovault_core::event::{ItemKind, ItemSnapshot};
    use unovault_core::secret::Secret;
    use unovault_core::{FieldKey, FieldValue, InstallId};

    fn fresh_vault_with(
        item_title: &str,
        url: &str,
        password: &[u8],
    ) -> (tempfile::TempDir, Arc<RwLock<Option<Vault>>>, String) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.unovault");
        let mut vault = Vault::create_for_tests(
            &path,
            Secret::new(String::from("hunter2")),
            InstallId::new(),
        )
        .expect("create vault");
        let id = vault
            .add_item(ItemSnapshot {
                title: item_title.into(),
                kind: ItemKind::Password,
                username: Some("james".into()),
                url: Some(url.into()),
            })
            .expect("add");
        vault
            .set_field(id, FieldKey::Password, FieldValue::Bytes(password.to_vec()))
            .expect("set pw");
        vault.save().expect("save");
        let handle = Arc::new(RwLock::new(Some(vault)));
        (dir, handle, id.0.hyphenated().to_string())
    }

    #[test]
    fn normalise_origin_strips_trailing_slash_and_adds_scheme() {
        assert_eq!(normalise_origin("github.com"), "https://github.com");
        assert_eq!(
            normalise_origin("https://github.com/"),
            "https://github.com"
        );
        assert_eq!(normalise_origin("https://github.com"), "https://github.com");
    }

    #[test]
    fn dispatch_ping_returns_pong_with_version() {
        let vault: Arc<RwLock<Option<Vault>>> = Arc::new(RwLock::new(None));
        let response = dispatch(
            BridgeRequest {
                request_id: "r1".into(),
                payload: BridgeRequestPayload::Ping,
            },
            &vault,
        );
        match response.payload {
            BridgeResponsePayload::Pong { version } => assert_eq!(version, BRIDGE_VERSION),
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_list_returns_matching_items_by_origin() {
        let (_dir, vault, _id) = fresh_vault_with("GitHub", "https://github.com", b"secret");
        let response = dispatch(
            BridgeRequest {
                request_id: "r2".into(),
                payload: BridgeRequestPayload::ListMatchingItems {
                    origin: "https://github.com".into(),
                },
            },
            &vault,
        );
        match response.payload {
            BridgeResponsePayload::ListMatchingItems { items } => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].title, "GitHub");
                assert_eq!(items[0].username.as_deref(), Some("james"));
            }
            other => panic!("expected ListMatchingItems, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_list_accepts_bare_host_and_matches() {
        // User saves the URL as "github.com" (no scheme). A sign-in
        // page reports its origin as "https://github.com". Both must
        // round-trip to the same normalised form.
        let (_dir, vault, _id) = fresh_vault_with("GitHub", "github.com", b"secret");
        let response = dispatch(
            BridgeRequest {
                request_id: "r3".into(),
                payload: BridgeRequestPayload::ListMatchingItems {
                    origin: "https://github.com".into(),
                },
            },
            &vault,
        );
        match response.payload {
            BridgeResponsePayload::ListMatchingItems { items } => {
                assert_eq!(items.len(), 1);
            }
            other => panic!("expected items, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_list_returns_empty_for_no_match() {
        let (_dir, vault, _id) = fresh_vault_with("GitHub", "https://github.com", b"secret");
        let response = dispatch(
            BridgeRequest {
                request_id: "r4".into(),
                payload: BridgeRequestPayload::ListMatchingItems {
                    origin: "https://attacker.com".into(),
                },
            },
            &vault,
        );
        match response.payload {
            BridgeResponsePayload::ListMatchingItems { items } => assert_eq!(items.len(), 0),
            other => panic!("expected empty ListMatchingItems, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_get_password_returns_stored_value() {
        let (_dir, vault, id) = fresh_vault_with("GitHub", "github.com", b"hunter42");
        let response = dispatch(
            BridgeRequest {
                request_id: "r5".into(),
                payload: BridgeRequestPayload::GetPassword { item_id: id },
            },
            &vault,
        );
        match response.payload {
            BridgeResponsePayload::GetPassword { password } => assert_eq!(password, "hunter42"),
            other => panic!("expected GetPassword, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_get_password_rejects_unknown_item() {
        let (_dir, vault, _id) = fresh_vault_with("GitHub", "github.com", b"pw");
        let response = dispatch(
            BridgeRequest {
                request_id: "r6".into(),
                payload: BridgeRequestPayload::GetPassword {
                    // A valid UUID but not in the vault.
                    item_id: uuid::Uuid::nil().hyphenated().to_string(),
                },
            },
            &vault,
        );
        match response.payload {
            BridgeResponsePayload::Error { category, message } => {
                assert_eq!(category, "UserActionable");
                assert!(message.contains("not found"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_list_errors_when_vault_is_locked() {
        let vault: Arc<RwLock<Option<Vault>>> = Arc::new(RwLock::new(None));
        let response = dispatch(
            BridgeRequest {
                request_id: "r7".into(),
                payload: BridgeRequestPayload::ListMatchingItems {
                    origin: "https://github.com".into(),
                },
            },
            &vault,
        );
        match response.payload {
            BridgeResponsePayload::Error { category, message } => {
                assert_eq!(category, "UserActionable");
                assert!(message.contains("locked"));
            }
            other => panic!("expected locked error, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_get_password_rejects_non_uuid_id() {
        let dir = tempdir().expect("tempdir");
        let vault: Arc<RwLock<Option<Vault>>> = Arc::new(RwLock::new(Some(
            Vault::create_for_tests(
                dir.path().join("v.unovault"),
                Secret::new("hunter2".into()),
                InstallId::new(),
            )
            .expect("create"),
        )));
        let response = dispatch(
            BridgeRequest {
                request_id: "r8".into(),
                payload: BridgeRequestPayload::GetPassword {
                    item_id: "not-a-uuid".into(),
                },
            },
            &vault,
        );
        match response.payload {
            BridgeResponsePayload::Error { category, message } => {
                assert_eq!(category, "UserActionable");
                assert!(message.contains("UUID"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn socket_round_trip_end_to_end() {
        // Spin up a real listener on a tempdir socket, connect with a
        // plain UnixStream, send a framed request, read the response.
        // This is the closest thing to the production path we can
        // test without Chrome.
        let (_dir, vault, _id) = fresh_vault_with("Gmail", "https://mail.google.com", b"gpw");

        let sock_dir = tempdir().expect("tempdir");
        let sock_path = sock_dir.path().join("bridge.sock");
        let _server = spawn(sock_path.clone(), Arc::clone(&vault)).expect("spawn bridge");

        let mut stream = UnixStream::connect(&sock_path).expect("connect");
        let request = BridgeRequest {
            request_id: "e2e".into(),
            payload: BridgeRequestPayload::Ping,
        };
        let mut framed = serde_json::to_vec(&request).expect("encode");
        framed.push(b'\n');
        stream.write_all(&framed).expect("write");
        stream.flush().expect("flush");

        // Read one line back.
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read");
        let response: BridgeResponse = serde_json::from_str(line.trim()).expect("decode");
        assert_eq!(response.request_id, "e2e");
        assert!(matches!(
            response.payload,
            BridgeResponsePayload::Pong { .. }
        ));
    }

    #[test]
    fn spawn_cleanup_on_drop_removes_socket_file() {
        let sock_dir = tempdir().expect("tempdir");
        let sock_path = sock_dir.path().join("cleanup.sock");
        let vault: Arc<RwLock<Option<Vault>>> = Arc::new(RwLock::new(None));
        {
            let _server = spawn(sock_path.clone(), vault).expect("spawn");
            assert!(
                sock_path.exists(),
                "socket file should exist while server is alive"
            );
        }
        assert!(
            !sock_path.exists(),
            "socket file should be removed by BridgeServer::drop"
        );
    }

    #[test]
    fn spawn_overwrites_stale_socket_file_from_prior_run() {
        let sock_dir = tempdir().expect("tempdir");
        let sock_path = sock_dir.path().join("stale.sock");
        // Plant a stale file from a notional prior run.
        std::fs::write(&sock_path, b"stale").expect("write stale");
        assert!(sock_path.exists());

        let vault: Arc<RwLock<Option<Vault>>> = Arc::new(RwLock::new(None));
        let _server = spawn(sock_path.clone(), vault).expect("spawn");
        // Prove the listener is live by pinging it.
        let mut stream = UnixStream::connect(&sock_path).expect("connect");
        let req = BridgeRequest {
            request_id: "x".into(),
            payload: BridgeRequestPayload::Ping,
        };
        let mut framed = serde_json::to_vec(&req).expect("encode");
        framed.push(b'\n');
        stream.write_all(&framed).expect("write");
        let mut response_buf = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let n = stream.read(&mut buf).expect("read");
            if n == 0 {
                break;
            }
            response_buf.extend_from_slice(&buf[..n]);
            if response_buf.ends_with(b"\n") {
                break;
            }
        }
        let response: BridgeResponse =
            serde_json::from_slice(response_buf.trim_ascii_end()).expect("decode");
        assert!(matches!(
            response.payload,
            BridgeResponsePayload::Pong { .. }
        ));
    }
}
