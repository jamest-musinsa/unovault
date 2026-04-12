//! Library crate for the Tauri desktop shell.
//!
//! `main.rs` is a trivial binary that calls [`run`]. Keeping the
//! business logic in a library crate means the command handlers and
//! state type are unit-testable with plain `cargo test` — no Tauri
//! runtime needed for most of the coverage.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod bridge;
pub mod commands;
pub mod error;
pub mod state;

pub use commands::*;
pub use error::{CommandError, CommandResult};
pub use state::AppState;

/// Bootstrap the Tauri runtime and run until the user quits. Called
/// by the binary in `main.rs`.
///
/// A failure to start the runtime is a genuine unrecoverable condition
/// at app boot — there is no sensible fallback and no user to show an
/// error to yet. We abort the process with a structured message rather
/// than calling `.expect()` (which clippy denies under the workspace
/// panic policy) so the behavior is explicit and greppable.
pub fn run() {
    let app_state = AppState::new();

    // Start the local socket bridge for the Chrome extension's
    // native messaging host. Failure to bind is logged and the app
    // keeps running — the extension will show "unovault is not
    // running" to the user, which is a far better posture than
    // refusing to launch the desktop app over a socket issue.
    let vault_handle = app_state.vault_handle();
    let socket_path = bridge::default_socket_path();
    match bridge::spawn(socket_path, vault_handle) {
        Ok(_server) => {
            // `_server` is intentionally dropped at end-of-function.
            // On drop the socket file is removed; but because this
            // function runs until `tauri::Builder::run` returns (ie.
            // the app is quitting), the listener thread dies
            // naturally with the process. The drop cleans up the
            // leftover file on exit. Holding it in the AppState
            // would be cleaner but requires AppState to be
            // mutable through Tauri's State wrapper; deferred until
            // a planned refactor.
        }
        Err(err) => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("unovault: bridge socket failed to start: {err}");
            }
        }
    }

    let build_result = tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::is_unlocked,
            commands::list_items,
            commands::get_item,
            commands::add_item,
            commands::set_password,
            commands::copy_password_to_clipboard,
            commands::has_recovery,
            commands::change_password,
            commands::enable_recovery_phrase,
            commands::rotate_recovery_phrase,
            commands::icloud_status,
            commands::sync_vault,
            commands::preview_import,
            commands::preview_import_with_source,
            commands::commit_import,
            commands::cancel_import,
            commands::format_version,
        ])
        .run(tauri::generate_context!());

    if let Err(err) = build_result {
        // No logger yet at this stage of boot. Write directly to
        // stderr via the tracing-compatible eprintln allow-list
        // exception and abort. This is the one place in the crate
        // where process::exit is appropriate.
        #[allow(clippy::print_stderr)]
        {
            eprintln!("unovault failed to start: {err}");
        }
        std::process::exit(1);
    }
}
