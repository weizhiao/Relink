//! Minimal ELF dynamic-object writer.
//!
//! Builds shared objects from caller-provided text and exports, with program
//! headers, `.dynamic`, `.dynsym`, `.dynstr`, and `.hash` metadata.
//! Available in `no_std` builds.

mod builder;
mod hash;
mod layout;
mod string_table;
mod types;
mod writer;

pub use crate::elf::hash::sysv_hash;
pub use builder::DsoBuilder;
pub use types::{DsoExport, DsoExportLayout, DsoImage, DsoSymbolBind, DsoSymbolKind};
