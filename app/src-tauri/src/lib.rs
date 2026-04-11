//! Library crate for the Tauri desktop shell.
//!
//! `main.rs` is a trivial binary that calls [`run`]. Keeping the
//! business logic in a library crate means the command handlers and
//! state type are unit-testable with plain `cargo test` — no Tauri
//! runtime needed for most of the coverage.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

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
    let build_result = tauri::Builder::default()
        .manage(AppState::new())
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
