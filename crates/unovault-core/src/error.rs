//! Error taxonomy for the unovault vault engine.
//!
//! Every fallible path returns [`VaultError`], a single top-level enum with
//! five categories. The UI pattern-matches on the category — each category
//! maps to a distinct headline, icon, and recovery action — not on the
//! message string. Messages are logs, not UI copy.
//!
//! The five categories and their purpose:
//!
//! | Category           | Cause                          | UI response                              |
//! |--------------------|--------------------------------|------------------------------------------|
//! | `UserActionable`   | Something the user can fix     | Inline hint + clear next action          |
//! | `NetworkTransient` | Temporary and will resolve     | Soft banner, automatic retry              |
//! | `HardwareIssue`    | Device state prevents action   | Dialog, offer fallback (e.g. password)   |
//! | `BugInUnovault`    | Invariant broken, our fault    | Crash dialog + "copy diagnostics" button |
//! | `PlatformPolicy`   | OS or sandbox refused          | Dialog explaining the policy             |
//!
//! Messages deliberately avoid containing secrets. A future fuzz test on the
//! error emitter validates this invariant.

use thiserror::Error;

/// Top-level error type for every fallible entry point in `unovault-core`.
///
/// Pattern-match on the category variant in callers. Per-category enums below
/// carry the specific cause for logs and developer diagnostics.
#[derive(Debug, Error)]
pub enum VaultError {
    /// The user can fix this by changing an input or retrying differently.
    #[error("user-actionable: {0}")]
    UserActionable(#[from] UserActionableError),

    /// Transient environmental failure. Retrying later will probably work.
    #[error("network-transient: {0}")]
    NetworkTransient(#[from] NetworkTransientError),

    /// Hardware or device state prevents the operation. Not a bug.
    #[error("hardware-issue: {0}")]
    HardwareIssue(#[from] HardwareIssueError),

    /// An invariant inside unovault was violated. This is always our fault.
    #[error("bug-in-unovault: {0}")]
    BugInUnovault(#[from] BugInUnovaultError),

    /// The operating system or its sandbox refused the operation.
    #[error("platform-policy: {0}")]
    PlatformPolicy(#[from] PlatformPolicyError),
}

/// Things the user can fix by changing input, choosing a different file, or
/// trying again with different credentials.
#[derive(Debug, Error)]
pub enum UserActionableError {
    #[error("incorrect master password")]
    WrongPassword,

    #[error("vault not found at the selected path")]
    VaultNotFound,

    #[error("vault manifest integrity check failed — the file has been tampered with or is from an incompatible version")]
    CorruptedManifest,

    #[error("chunk file is corrupt and cannot be decrypted")]
    CorruptedChunk,

    #[error("the recovery phrase is not valid BIP-39")]
    InvalidRecoveryPhrase,

    #[error("unsupported format version {found}; this build supports {supported}")]
    UnsupportedFormatVersion { found: u16, supported: u16 },

    #[error("the destination directory already contains a vault")]
    VaultAlreadyExists,
}

/// Transient environmental failures — iCloud offline, DNS, disk temporarily
/// unavailable. Callers should retry with backoff rather than surfacing these
/// as hard errors.
#[derive(Debug, Error)]
pub enum NetworkTransientError {
    #[error("iCloud Drive is not currently available on this device")]
    ICloudUnavailable,

    #[error("sync backend timed out")]
    SyncTimeout,

    #[error("file system is temporarily read-only")]
    ReadOnlyFileSystem,
}

/// Hardware or device-state problems. Not user input errors; not bugs. Offer
/// a clear fallback path wherever possible (e.g. password unlock when
/// biometric unlock fails).
#[derive(Debug, Error)]
pub enum HardwareIssueError {
    #[error("Touch ID or Face ID was denied by the user")]
    BiometricDenied,

    #[error("no biometric authentication is enrolled on this device")]
    NoBiometricEnrolled,

    #[error("Secure Enclave is not available on this hardware")]
    NoSecureEnclave,

    #[error("disk is full")]
    DiskFull,
}

/// Something inside unovault broke an invariant. These should be rare once
/// the crate is tested; when they do fire, we want loud failures, structured
/// logs, and a user-visible "copy diagnostics" affordance.
#[derive(Debug, Error)]
pub enum BugInUnovaultError {
    #[error("internal invariant violated: {0}")]
    InvariantViolation(&'static str),

    #[error("serialization failed for a value we produced ourselves")]
    SelfSerializationFailure,

    #[error("chunk counter overflow — the vault has more than u64::MAX writes, which is impossible in practice")]
    ChunkCounterOverflow,
}

/// The OS or its sandbox refused. Distinguish from `HardwareIssue` because the
/// fallback is different: "grant this permission in System Settings" rather
/// than "try a different device."
#[derive(Debug, Error)]
pub enum PlatformPolicyError {
    #[error("the sandbox did not grant access to the selected file")]
    SandboxDenied,

    #[error("the Keychain refused to store or retrieve the install ID")]
    KeychainDenied,

    #[error("iCloud container entitlement is not configured for this build")]
    ICloudEntitlementMissing,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `From` impls let sub-errors bubble up through `?` without manual
    /// wrapping. This test exists so that regressions in the `#[from]` attrs
    /// are caught at compile time instead of silently forcing explicit
    /// `.into()` calls throughout the crate.
    #[test]
    fn sub_errors_coerce_via_question_mark() {
        fn inner() -> Result<(), UserActionableError> {
            Err(UserActionableError::WrongPassword)
        }
        fn outer() -> Result<(), VaultError> {
            inner()?;
            Ok(())
        }
        let err = outer().err();
        assert!(matches!(
            err,
            Some(VaultError::UserActionable(
                UserActionableError::WrongPassword
            ))
        ));
    }

    /// Error display strings must never leak secret material. This test is a
    /// placeholder until a proptest-backed version exists that exhausts every
    /// constructor with random inputs.
    #[test]
    fn error_messages_do_not_contain_the_word_password_value() {
        let err = VaultError::from(UserActionableError::WrongPassword);
        let msg = format!("{err}");
        // A minimal sanity check: error message mentions the category and
        // the failure mode, but never a literal credential string. Expanded
        // in a later pass.
        assert!(msg.contains("user-actionable"));
        assert!(msg.contains("incorrect master password"));
    }
}
