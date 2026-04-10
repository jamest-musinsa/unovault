//! IPC-safe error type used by every Tauri command.
//!
//! The core [`unovault_core::VaultError`] taxonomy is 5-category nested
//! enums, which is wonderful for Rust-side pattern matching but awkward
//! to pattern-match on the JS side. At the IPC boundary we collapse it
//! to a flat enum whose variants are just category tags plus a log
//! message. The frontend pattern-matches on the tag, picks the right
//! headline from its own copy tables, and shows the log message only
//! in a "copy diagnostics" affordance.
//!
//! Every variant is a unit struct with an `IpcString` message, which
//! keeps the enum `IpcSafe` while still letting us include details
//! for developers and bug reports.

use serde::{Deserialize, Serialize};
use unovault_core::{IpcSafe, IpcString, VaultError};

/// Flat, IPC-safe error envelope for every Tauri command.
///
/// `thiserror::Error` powers backend logging; `serde::Serialize` lets
/// Tauri ship the value across the boundary. The `tag` field is what
/// the frontend pattern-matches on — mirror its variants in the Svelte
/// error renderer when adding new categories.
#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "category", content = "message")]
pub enum CommandError {
    /// Something the user can fix: wrong password, wrong file, etc.
    #[error("user-actionable: {0}")]
    UserActionable(IpcString),

    /// Temporary environmental failure — iCloud offline, DNS, retry.
    #[error("network-transient: {0}")]
    NetworkTransient(IpcString),

    /// Hardware or device state prevents the action.
    #[error("hardware-issue: {0}")]
    HardwareIssue(IpcString),

    /// Bug inside unovault — the frontend should show a "copy
    /// diagnostics" dialog and invite the user to file a report.
    #[error("bug-in-unovault: {0}")]
    BugInUnovault(IpcString),

    /// OS or sandbox refused. Ask the user to grant permission in
    /// System Settings.
    #[error("platform-policy: {0}")]
    PlatformPolicy(IpcString),
}

impl IpcSafe for CommandError {}

impl From<VaultError> for CommandError {
    fn from(err: VaultError) -> Self {
        let message = IpcString::new(err.to_string());
        match err {
            VaultError::UserActionable(_) => Self::UserActionable(message),
            VaultError::NetworkTransient(_) => Self::NetworkTransient(message),
            VaultError::HardwareIssue(_) => Self::HardwareIssue(message),
            VaultError::BugInUnovault(_) => Self::BugInUnovault(message),
            VaultError::PlatformPolicy(_) => Self::PlatformPolicy(message),
        }
    }
}

impl From<std::io::Error> for CommandError {
    fn from(err: std::io::Error) -> Self {
        Self::PlatformPolicy(IpcString::new(err.to_string()))
    }
}

/// Shorthand for command return types. Every Tauri command returns
/// `CommandResult<T>` so the boundary shape is uniform.
pub type CommandResult<T> = Result<T, CommandError>;

#[cfg(test)]
mod tests {
    use super::*;
    use unovault_core::UserActionableError;

    #[test]
    fn converts_wrong_password_to_user_actionable() {
        let err: CommandError = VaultError::from(UserActionableError::WrongPassword).into();
        match err {
            CommandError::UserActionable(msg) => {
                assert!(msg.as_str().contains("incorrect master password"));
            }
            other => panic!("expected UserActionable, got {other:?}"),
        }
    }

    #[test]
    fn serializes_with_category_tag() {
        let err = CommandError::UserActionable(IpcString::new("wrong pw"));
        let json = serde_json::to_string(&err).expect("serialize");
        assert!(json.contains("\"category\":\"UserActionable\""));
        assert!(json.contains("\"message\":\"wrong pw\""));
    }
}
