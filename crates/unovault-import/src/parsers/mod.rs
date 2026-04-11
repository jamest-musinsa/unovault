//! Per-format parser modules. Each parser exposes a `parse_*`
//! function that takes a `&Path` and returns a shared
//! [`crate::ImportSummary`].
//!
//! The parsers do not touch the vault engine. They produce
//! [`crate::ParsedItem`] values and leave persistence to the caller.

pub mod bitwarden;
pub mod keepass;
pub mod onepassword;
