//! ELF (Executable and Linkable Format) parsing and data structures.
//!
//! This module provides a collection of types and utilities for working with
//! the ELF format as defined in the System V ABI. It includes support for heades,
//! program headers, section headers, dynamic sections, and symbol tables.

pub mod abi;
mod defs;
mod dynamic;
mod ehdr;
mod hash;
mod phdrs;
mod symbol;
#[cfg(feature = "version")]
mod version;

// Internal module re-exports for use within the crate
pub(crate) use defs::*;
pub(crate) use dynamic::{ElfDynamic, ElfDynamicHashTab};
pub(crate) use hash::{HashTable, PreCompute};
pub(crate) use phdrs::ElfPhdrs;
pub(crate) use symbol::{ElfStringTable, SymbolInfo, SymbolTable};

// Public API exports
pub use defs::{ElfDyn, ElfPhdr, ElfRel, ElfRelType, ElfRela, ElfSymbol};
/// Core ELF data types for program headers, relocations, and symbols.
pub use ehdr::ElfHeader;
