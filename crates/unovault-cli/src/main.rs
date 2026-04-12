//! `unovault` CLI — the second reference implementation of the
//! `.unovault` format.
//!
//! The desktop app (Tauri + Svelte) is the primary UI; this CLI
//! exists for:
//!
//! * Power users who want to script vault operations.
//! * CI pipelines that need to read credentials.
//! * Format validation: a working CLI proves the format spec is
//!   implementable by a completely separate code path.
//!
//! # Commands
//!
//! ```text
//! unovault unlock <path>     Open a vault (prompts for password).
//! unovault ls                List items in the open vault.
//! unovault get <item-id>     Print a field value to stdout.
//! unovault lock              Close the vault.
//! unovault import <file>     Import items from 1Password / Bitwarden / KeePass.
//! unovault version           Print version info.
//! ```
//!
//! # Session model
//!
//! The CLI is stateless between invocations — every command that
//! touches vault data takes a `--vault <path>` flag and a password
//! from stdin (or `--password-stdin`). There is no "session file"
//! or daemon process. This is deliberate: a CLI that holds keys in
//! memory between calls is a security surface the desktop app
//! already manages via the Tauri lifecycle. The CLI trades
//! convenience (re-entering the password on every call) for
//! simplicity and auditability.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use unovault_core::event::{FieldKey, FieldValue, ItemKind, ItemSnapshot};
use unovault_core::secret::Secret;
use unovault_core::vault::Vault;
use unovault_core::InstallId;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return ExitCode::FAILURE;
    }

    let result = match args[1].as_str() {
        "unlock" | "ls" | "list" => cmd_ls(&args[2..]),
        "get" => cmd_get(&args[2..]),
        "import" => cmd_import(&args[2..]),
        "version" | "--version" | "-V" => {
            out(&format!(
                "unovault {} (format v{})",
                unovault_core::CRATE_VERSION,
                unovault_core::FORMAT_VERSION
            ));
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        other => {
            err(&format!("unknown command: {other}"));
            print_usage();
            Err(1)
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

// =============================================================================
// COMMANDS
// =============================================================================

/// `unovault ls <path>` — open the vault and list every item.
fn cmd_ls(args: &[String]) -> Result<(), i32> {
    let vault_path = require_vault_path(args)?;
    let vault = open_vault(&vault_path)?;

    if vault.is_empty() {
        out("(empty vault)");
        return Ok(());
    }

    // Tab-separated output: id, kind, title, username, url.
    out("ID\tKIND\tTITLE\tUSERNAME\tURL");
    for item in vault.items() {
        let id = item.id.0.hyphenated().to_string();
        let kind = match item.kind {
            ItemKind::Password => "password",
            ItemKind::Passkey => "passkey",
            ItemKind::Totp => "totp",
            ItemKind::SshKey => "ssh-key",
            ItemKind::ApiToken => "api-token",
            ItemKind::SecureNote => "note",
            _ => "other",
        };
        let title = &item.title;
        let username = item.username.as_deref().unwrap_or("");
        let url = item.url.as_deref().unwrap_or("");
        out(&format!("{id}\t{kind}\t{title}\t{username}\t{url}"));
    }
    Ok(())
}

/// `unovault get <path> <item-id> [field]` — print a field value.
/// Default field is `password`. Also supports `username`, `url`,
/// `notes`, `totp`.
fn cmd_get(args: &[String]) -> Result<(), i32> {
    if args.len() < 2 {
        err("usage: unovault get <vault-path> <item-id> [field]");
        return Err(1);
    }
    let vault_path = PathBuf::from(&args[0]);
    let item_id_str = &args[1];
    let field_name = args.get(2).map(|s| s.as_str()).unwrap_or("password");

    let vault = open_vault(&vault_path)?;

    let uuid = uuid::Uuid::parse_str(item_id_str).map_err(|_| {
        err("item-id is not a valid UUID");
        1
    })?;
    let item = vault.get(&unovault_core::ItemId(uuid)).ok_or_else(|| {
        err("item not found");
        1
    })?;

    match field_name {
        "password" | "pw" => {
            let bytes = item.password.as_ref().ok_or_else(|| {
                err("item has no password field");
                1
            })?;
            let text = std::str::from_utf8(bytes).map_err(|_| {
                err("password is not valid UTF-8");
                1
            })?;
            // Print without trailing newline so `unovault get ... | pbcopy`
            // doesn't include a newline.
            out_raw(text);
        }
        "username" | "user" => {
            out(item.username.as_deref().unwrap_or(""));
        }
        "url" => {
            out(item.url.as_deref().unwrap_or(""));
        }
        "notes" => {
            out(item.notes.as_deref().unwrap_or(""));
        }
        "totp" => {
            let bytes = item.totp_secret.as_ref().ok_or_else(|| {
                err("item has no TOTP secret");
                1
            })?;
            let text = std::str::from_utf8(bytes).map_err(|_| {
                err("TOTP secret is not valid UTF-8");
                1
            })?;
            out_raw(text);
        }
        other => {
            err(&format!("unknown field: {other}"));
            err("  valid fields: password, username, url, notes, totp");
            return Err(1);
        }
    }
    Ok(())
}

/// `unovault import <vault-path> <export-file>` — import items from
/// a 1Password .1pux, Bitwarden .json, or KeePass .xml export.
fn cmd_import(args: &[String]) -> Result<(), i32> {
    if args.len() < 2 {
        err("usage: unovault import <vault-path> <export-file>");
        return Err(1);
    }
    let vault_path = PathBuf::from(&args[0]);
    let export_path = PathBuf::from(&args[1]);

    let mut vault = open_vault(&vault_path)?;

    let summary = unovault_import::parse_file(&export_path).map_err(|e| {
        err(&format!("import error: {e}"));
        1
    })?;

    out(&format!(
        "Parsed {} items, {} skipped ({})",
        summary.imported_count(),
        summary.skipped_count(),
        summary.source.display_name()
    ));

    if !summary.skipped.is_empty() {
        out("Skipped:");
        for skip in &summary.skipped {
            out(&format!("  - {} ({})", skip.title, skip.reason));
        }
    }

    let mut committed = 0u32;
    let mut failed = 0u32;
    for item in summary.items {
        let snapshot = ItemSnapshot {
            title: item.title.clone(),
            kind: item.kind,
            username: item.username.clone(),
            url: item.url.clone(),
        };
        match vault.add_item(snapshot) {
            Ok(id) => {
                if let Some(pw) = item.password.clone() {
                    let _ = vault.set_field(id, FieldKey::Password, FieldValue::Bytes(pw));
                }
                if let Some(totp) = item.totp_secret.clone() {
                    let _ = vault.set_field(id, FieldKey::TotpSecret, FieldValue::Bytes(totp));
                }
                if let Some(notes) = item.notes.clone() {
                    let _ = vault.set_field(id, FieldKey::Notes, FieldValue::Text(notes));
                }
                committed += 1;
            }
            Err(_) => {
                failed += 1;
            }
        }
    }

    vault.save().map_err(|e| {
        err(&format!("save failed: {e}"));
        1
    })?;

    out(&format!(
        "Done: {committed} items imported, {failed} failed."
    ));
    Ok(())
}

// =============================================================================
// HELPERS
// =============================================================================

fn require_vault_path(args: &[String]) -> Result<PathBuf, i32> {
    if args.is_empty() {
        err("usage: unovault <command> <vault-path>");
        return Err(1);
    }
    Ok(PathBuf::from(&args[0]))
}

fn open_vault(path: &PathBuf) -> Result<Vault, i32> {
    let password = read_password().map_err(|_| {
        err("could not read password from stdin");
        1
    })?;
    let install = InstallId::new();
    Vault::unlock(path, Secret::new(password), install).map_err(|e| {
        err(&format!("unlock failed: {e}"));
        1
    })
}

/// Read the master password from stdin. If stdin is a TTY, prompt on
/// stderr so the prompt doesn't pollute piped output. If stdin is a
/// pipe (e.g. `echo hunter2 | unovault ls vault.unovault`), read
/// silently.
fn read_password() -> io::Result<String> {
    let stdin = io::stdin();
    let is_tty = atty_heuristic();

    if is_tty {
        #[allow(clippy::print_stderr)]
        {
            eprint!("Master password: ");
        }
        io::stderr().flush()?;
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    // Trim the trailing newline.
    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
    Ok(trimmed.to_string())
}

/// Heuristic TTY detection: check the `TERM` env var. A proper
/// implementation uses `libc::isatty` but that's an FFI call the
/// panic policy doesn't love. This is good enough for the v1 CLI.
fn atty_heuristic() -> bool {
    std::env::var("TERM").is_ok()
}

fn print_usage() {
    err("unovault — local-first password manager");
    err("");
    err("Usage:");
    err("  unovault ls <vault-path>                  List items");
    err("  unovault get <vault-path> <id> [field]     Print a field (default: password)");
    err("  unovault import <vault-path> <export-file> Import from 1Password/Bitwarden/KeePass");
    err("  unovault version                           Print version info");
    err("");
    err("The password is read from stdin. Pipe it or type interactively.");
    err("Fields: password, username, url, notes, totp");
}

/// Write to stdout. The `#[allow]` is needed because the workspace
/// panic policy denies `print_stdout`; the CLI is the one crate
/// where stdout IS the intended output channel.
#[allow(clippy::print_stdout)]
fn out(msg: &str) {
    println!("{msg}");
}

/// Write to stdout WITHOUT a trailing newline.
#[allow(clippy::print_stdout)]
fn out_raw(msg: &str) {
    print!("{msg}");
    let _ = io::stdout().flush();
}

/// Write to stderr. Used for prompts, errors, and usage text.
/// The `#[allow]` is needed for the same reason as `out` —
/// the workspace panic policy denies `print_stderr`, but the CLI
/// uses stderr as the diagnostic channel.
#[allow(clippy::print_stderr)]
fn err(msg: &str) {
    eprintln!("{msg}");
}
