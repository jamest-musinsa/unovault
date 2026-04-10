//! [`Secret<T>`] — a zeroizing wrapper for anything that must never leak.
//!
//! Use this type for master passwords, derived keys, decrypted credential
//! values, recovery phrases, passkey private material, and any other byte
//! buffer where accidental disclosure would be a security incident.
//!
//! Guarantees:
//!
//! * `Drop` calls [`Zeroize::zeroize`] on the inner value, best-effort
//!   wiping the memory before it is released back to the allocator.
//! * `Debug` prints `Secret(<redacted>)` instead of the inner contents.
//!   A `Secret` inside a larger `#[derive(Debug)]` struct will therefore
//!   be safe to log even if the parent struct accidentally ends up in a
//!   tracing event.
//! * `Display` is *not* implemented — formatting a `Secret` into a user-
//!   visible string is a category error, not a convenience shortcut.
//! * `Clone` is deliberately *not* implemented. If you need a second copy
//!   of a secret, call [`Secret::expose`] and wrap the clone yourself. This
//!   makes every copy of a secret a conscious decision.
//!
//! The type is intentionally minimal. Higher-level wrappers (`MasterPassword`,
//! `VaultKey`, `Passphrase`) live in the modules that use them.

use core::fmt;
use zeroize::Zeroize;

/// A value that zeroizes its memory on drop and never prints its contents.
///
/// `T: Zeroize` is the only bound — any type that knows how to wipe itself
/// can be wrapped. In practice this is `Vec<u8>`, `String`, `[u8; N]`, and
/// types that derive `Zeroize`.
///
/// # Example
///
/// ```
/// use unovault_core::Secret;
///
/// let password = Secret::new(String::from("s3cret"));
/// assert_eq!(password.expose().len(), 6);
/// // Debug prints `<redacted>`, not the password:
/// let _ = format!("{password:?}");
/// // On drop, the String memory is zeroized.
/// ```
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wrap a value. Prefer constructing `Secret` as soon as the value
    /// exists, not after it has been copied around.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrow the inner value. The borrow lifetime ties the exposure window
    /// to the caller's scope, so plaintext references cannot outlive the
    /// `Secret` itself.
    ///
    /// Prefer passing the `&Secret` down into functions that need the value
    /// rather than calling `expose` eagerly, since each call to `expose` is
    /// a potential audit point.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper and return the inner value.
    ///
    /// The caller becomes responsible for zeroizing the returned value. This
    /// exists because some downstream APIs (e.g. crypto primitives that take
    /// owned buffers) cannot accept a reference. Use sparingly.
    #[must_use = "the returned value bypasses Secret's zeroize-on-drop guarantee"]
    pub fn into_inner(mut self) -> T
    where
        T: Default,
    {
        // Swap the inner value out so our Drop impl doesn't zeroize the one
        // we're returning. The default value takes its place and is dropped
        // normally by the now-empty Secret.
        core::mem::take(&mut self.0)
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Debug impl prints a fixed redacted marker. Never prints the inner value.
impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Secret").field(&"<redacted>").finish()
    }
}

// Intentionally not implemented:
//
//   impl<T: Zeroize> fmt::Display for Secret<T> { ... }
//
// There is no legitimate reason to Display a secret. If a caller reaches for
// `{}` formatting on a Secret, they have made a design mistake and should be
// stopped at compile time. The Debug impl covers the "accidentally logged via
// derive(Debug)" case with `<redacted>`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_impl_redacts_string_contents() {
        let s = Secret::new(String::from("hunter2"));
        let debug = format!("{s:?}");
        assert!(
            !debug.contains("hunter2"),
            "debug output leaked the secret: {debug}"
        );
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn debug_impl_redacts_byte_contents() {
        let s = Secret::new(vec![0xFEu8, 0xED, 0xFA, 0xCE]);
        let debug = format!("{s:?}");
        assert!(!debug.contains("0xfe"));
        assert!(!debug.contains("FE"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn expose_returns_inner_reference() {
        let s = Secret::new(String::from("correct horse battery staple"));
        assert_eq!(s.expose().len(), 28);
    }

    #[test]
    fn into_inner_returns_original_value_zeroed_by_caller() {
        let s = Secret::new(String::from("transient"));
        let owned: String = s.into_inner();
        assert_eq!(owned, "transient");
        // Caller is now responsible; in production code the caller would
        // either re-wrap in Secret or use the value within a tight scope and
        // zeroize manually.
    }

    /// This test is a marker that the property "no Clone impl" is intentional.
    /// If someone adds `#[derive(Clone)]` to `Secret`, this test still passes
    /// but the review will catch it. A compile-fail test via `trybuild` is a
    /// better long-term mechanism — added in a later pass.
    #[test]
    fn secret_deliberately_does_not_implement_clone() {
        // If you are reading this because Clone was added: please don't.
        // Read the doc comment on `Secret` for the reasoning. Use
        // `Secret::new(value.clone())` at the call site so the copy is
        // explicit and auditable.
    }
}
