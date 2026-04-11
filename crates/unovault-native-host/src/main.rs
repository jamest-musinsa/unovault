// Panic-policy exception for test code — see unovault-core/src/lib.rs.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! `unovault-native-host` — the binary Chrome spawns when the
//! extension calls `chrome.runtime.connectNative("com.unovault.host")`.
//!
//! This binary runs for the duration of a single Chrome connection.
//! It reads length-prefixed JSON frames from stdin, forwards them to
//! the unovault desktop app over a local Unix socket, and writes the
//! app's responses back to stdout in the same framing.
//!
//! # Current scope (week 19 skeleton)
//!
//! * Full Chrome framing layer (read + write) via `unovault_native_host::*`.
//! * `ping` handled directly by the host — no socket needed.
//! * `list_matching_items` and `get_password` are wired as stubs
//!   that return a "not yet implemented" error because the desktop
//!   app has not yet exposed the local-socket surface. When the
//!   socket lands (week 22 or later, under iCloud sync work), this
//!   file's `route_request` function gains the socket client call
//!   and the stubs go away.
//!
//! # Why not pretend to talk to the app
//!
//! Returning a fake success from the skeleton would mask the fact
//! that the full chain isn't wired, and the Chrome extension would
//! silently paste empty strings into password fields. An explicit
//! error keeps the break visible during development.

use std::io::{self, Read, Write};

use unovault_native_host::protocol::{
    HostRequest, HostRequestPayload, HostResponse, HostResponsePayload,
};
use unovault_native_host::{read_frame, write_frame, FrameError};

/// Host binary version string. Reported in `Pong` responses so the
/// extension can decide whether its protocol version matches.
const HOST_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> std::process::ExitCode {
    // Chrome connects stdin/stdout to the host via pipes. Read
    // frames until either side closes or a parse error bubbles up.
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    match run_loop(&mut reader, &mut writer) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            // We cannot `eprintln!` (panic-policy clippy lint) and
            // stderr would go into Chrome's noisy native-messaging
            // log anyway. Encoding the error as a frame is the
            // nicest parting message — if the writer is already
            // dead we return non-zero and move on.
            let fatal = HostResponse {
                request_id: "fatal".into(),
                payload: HostResponsePayload::Error {
                    category: "NativeHostFatal".into(),
                    message: err.to_string(),
                },
            };
            let _ = write_frame(&mut writer, &fatal);
            std::process::ExitCode::FAILURE
        }
    }
}

fn run_loop<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<(), FrameError> {
    loop {
        match read_frame::<_, HostRequest>(reader)? {
            None => return Ok(()), // clean EOF — Chrome closed the port
            Some(request) => {
                let response = route_request(request);
                write_frame(writer, &response)?;
            }
        }
    }
}

fn route_request(request: HostRequest) -> HostResponse {
    let request_id = request.request_id.clone();
    let payload = match request.payload {
        HostRequestPayload::Ping => HostResponsePayload::Pong {
            version: HOST_VERSION.into(),
        },

        // The two stubs below block the chain until the desktop app
        // ships a local socket surface. They return a structured
        // error so the extension's `kind === 'error'` branch fires
        // and the popup shows "unovault is not running."
        HostRequestPayload::ListMatchingItems { origin: _ } => HostResponsePayload::Error {
            category: "NotImplemented".into(),
            message: "list_matching_items is not wired to the desktop app yet".into(),
        },
        HostRequestPayload::GetPassword { item_id: _ } => HostResponsePayload::Error {
            category: "NotImplemented".into(),
            message: "get_password is not wired to the desktop app yet".into(),
        },
    };

    HostResponse {
        request_id,
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Helper that runs one request through `run_loop` and returns
    /// the single response frame the host wrote.
    fn round_trip(request: HostRequest) -> HostResponse {
        // Build a stdin stream: one framed request.
        let mut stdin_bytes = Vec::new();
        write_frame(&mut stdin_bytes, &request).expect("write request");

        let mut reader = Cursor::new(stdin_bytes);
        let mut writer: Vec<u8> = Vec::new();
        run_loop(&mut reader, &mut writer).expect("run_loop");

        // Decode whatever the host wrote.
        let mut response_reader = Cursor::new(writer);
        let response: HostResponse = read_frame(&mut response_reader)
            .expect("read response")
            .expect("some response");
        response
    }

    #[test]
    fn ping_returns_pong_with_version() {
        let response = round_trip(HostRequest {
            request_id: "r1".into(),
            payload: HostRequestPayload::Ping,
        });
        assert_eq!(response.request_id, "r1");
        match response.payload {
            HostResponsePayload::Pong { version } => {
                assert_eq!(version, HOST_VERSION);
            }
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    #[test]
    fn list_matching_items_stub_returns_not_implemented_error() {
        let response = round_trip(HostRequest {
            request_id: "r2".into(),
            payload: HostRequestPayload::ListMatchingItems {
                origin: "https://github.com".into(),
            },
        });
        match response.payload {
            HostResponsePayload::Error { category, .. } => {
                assert_eq!(category, "NotImplemented");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn get_password_stub_returns_not_implemented_error() {
        let response = round_trip(HostRequest {
            request_id: "r3".into(),
            payload: HostRequestPayload::GetPassword {
                item_id: "abc".into(),
            },
        });
        match response.payload {
            HostResponsePayload::Error { category, .. } => {
                assert_eq!(category, "NotImplemented");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn run_loop_handles_multiple_requests_in_one_connection() {
        // Two requests back-to-back, then EOF.
        let mut stdin_bytes = Vec::new();
        write_frame(
            &mut stdin_bytes,
            &HostRequest {
                request_id: "first".into(),
                payload: HostRequestPayload::Ping,
            },
        )
        .expect("write 1");
        write_frame(
            &mut stdin_bytes,
            &HostRequest {
                request_id: "second".into(),
                payload: HostRequestPayload::Ping,
            },
        )
        .expect("write 2");

        let mut reader = Cursor::new(stdin_bytes);
        let mut writer: Vec<u8> = Vec::new();
        run_loop(&mut reader, &mut writer).expect("run_loop");

        let mut response_reader = Cursor::new(writer);
        let first: HostResponse = read_frame(&mut response_reader)
            .expect("read 1")
            .expect("some 1");
        let second: HostResponse = read_frame(&mut response_reader)
            .expect("read 2")
            .expect("some 2");
        assert_eq!(first.request_id, "first");
        assert_eq!(second.request_id, "second");
    }

    #[test]
    fn run_loop_exits_cleanly_on_eof_without_frame() {
        let mut reader: &[u8] = &[];
        let mut writer: Vec<u8> = Vec::new();
        run_loop(&mut reader, &mut writer).expect("clean EOF");
        assert!(
            writer.is_empty(),
            "no frame should be written on empty stdin"
        );
    }
}
