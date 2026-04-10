//! Procedural macros for unovault.
//!
//! The only macro today is [`safe_command`], which wraps a Tauri IPC
//! command handler with a compile-time assertion that its return type
//! implements [`unovault_core::IpcSafe`]. That trait has no impl for
//! bare `String` or `Vec<u8>`, so a command that would return a raw
//! password or secret byte buffer fails to compile with a clear
//! error message pointing at the function.
//!
//! # Why a proc-macro and not a plain trait bound?
//!
//! Tauri's `#[tauri::command]` generates its own wrapper around the
//! user's function and does not let us add a where-clause on the
//! return type. A companion attribute macro is the least-invasive way
//! to inject the check without forking Tauri. The macro emits:
//!
//! 1. The original function unchanged.
//! 2. A `const _: fn() = || { ... }` block containing a trait bound
//!    assertion against the return type the compiler sees.
//!
//! The compile-time cost is near zero — the const block evaluates to
//! a no-op and is eliminated by the compiler.
//!
//! # Example
//!
//! ```ignore
//! use unovault_macros::safe_command;
//! use unovault_core::{ItemMetadata, IpcSafe};
//!
//! // OK: `Vec<ItemMetadata>` implements IpcSafe.
//! #[safe_command]
//! #[tauri::command]
//! fn list_items() -> Vec<ItemMetadata> { vec![] }
//!
//! // Does NOT compile: `String` is not IpcSafe.
//! // #[safe_command]
//! // #[tauri::command]
//! // fn reveal_password(id: String) -> String { String::new() }
//! ```

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, ItemFn, ReturnType};

/// Attribute macro: asserts at compile time that the attached function's
/// return type satisfies `unovault_core::IpcSafe`.
///
/// Apply this to every `#[tauri::command]` that returns data to the
/// frontend. A function returning `()` (no explicit return) passes
/// trivially because `()` is marked safe.
///
/// # Pitfalls
///
/// * The macro inspects the written return type, not the type after
///   generic resolution. `fn f() -> T where T: ...` passes silently
///   because the macro does not know what `T` will be. Avoid generic
///   return types on Tauri commands.
///
/// * The emitted assertion uses the absolute path
///   `::unovault_core::IpcSafe`. Downstream crates must have
///   `unovault-core` in their dependency graph (direct or transitive);
///   this is normal for a Tauri backend that calls into the vault
///   engine, but aliased dependencies may need to re-export the trait.
#[proc_macro_attribute]
pub fn safe_command(_args: TokenStream, input: TokenStream) -> TokenStream {
    let func = parse_macro_input!(input as ItemFn);

    // A bare `()` return is always safe; emit the function unchanged
    // so we do not spam the output with trivially-satisfied asserts.
    let return_type = match &func.sig.output {
        ReturnType::Default => {
            return quote!(#func).into();
        }
        ReturnType::Type(_, ty) => (**ty).clone(),
    };

    // Build a unique ident for the const assertion block so multiple
    // functions in the same module do not clash.
    let assert_name = format_ident!("__UNOVAULT_SAFE_COMMAND_{}", func.sig.ident);

    let expanded = quote! {
        #func

        #[doc(hidden)]
        #[allow(non_upper_case_globals, dead_code)]
        const #assert_name: fn() = || {
            fn __assert_ipc_safe<__T: ::unovault_core::IpcSafe>() {}
            __assert_ipc_safe::<#return_type>();
        };
    };

    expanded.into()
}
