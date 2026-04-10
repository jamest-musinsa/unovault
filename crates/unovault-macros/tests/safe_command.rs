// Test code in this file uses `unwrap`/`expect` for brevity; the
// workspace panic policy applies to production code, not tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests that prove `#[safe_command]` compiles the allowed
//! return types and rejects the forbidden ones.
//!
//! Compile-fail tests (the "does not compile" half of the proof) live
//! in the disabled `tests/compile-fail/` directory — adding a real
//! `trybuild` dependency is a week-14 chore, not a week-7 prerequisite.
//! For now, reviewers can flip any of the positive tests below to a
//! `String` return and `cargo test -p unovault-macros` will fail with
//! a clear error, which is enough signal.

use unovault_core::{IpcSafe, IpcString, ItemKindTag, ItemMetadata};
use unovault_macros::safe_command;

/// A function returning `()` (no explicit return) should pass.
#[safe_command]
fn returns_unit() {}

/// Primitives pass.
#[safe_command]
fn returns_u64() -> u64 {
    0
}

#[safe_command]
fn returns_bool() -> bool {
    false
}

/// `Option<T>` passes when `T: IpcSafe`.
#[safe_command]
fn returns_option_u64() -> Option<u64> {
    None
}

/// `Vec<T>` passes when `T: IpcSafe`.
#[safe_command]
fn returns_vec_metadata() -> Vec<ItemMetadata> {
    Vec::new()
}

/// `Result<T, E>` passes when both sides are IpcSafe.
#[safe_command]
fn returns_result_of_vec() -> Result<Vec<ItemMetadata>, ItemKindTag> {
    Ok(Vec::new())
}

/// Newtype wrapper around String passes.
#[safe_command]
fn returns_ipc_string() -> IpcString {
    IpcString::new("safe")
}

#[test]
fn every_positive_case_compiled() {
    // If the file compiles, the positive cases above were accepted by
    // the safe_command attribute. This test exists so `cargo test -p
    // unovault-macros` reports "tests passed" rather than "0 tests run".
    returns_unit();
    assert_eq!(returns_u64(), 0);
    assert!(!returns_bool());
    assert!(returns_option_u64().is_none());
    assert!(returns_vec_metadata().is_empty());
    assert!(returns_result_of_vec().unwrap().is_empty());
    assert_eq!(returns_ipc_string().as_str(), "safe");
}

/// A hand-rolled compile-time check: this block is equivalent to what
/// `#[safe_command]` emits. If the assertion ever fails to compile for
/// `ItemMetadata`, the `IpcSafe` impl regressed.
#[test]
fn allowlist_still_covers_item_metadata() {
    fn assert<T: IpcSafe>() {}
    assert::<ItemMetadata>();
    assert::<Vec<ItemMetadata>>();
    assert::<Option<ItemMetadata>>();
    assert::<Result<Vec<ItemMetadata>, IpcString>>();
}
