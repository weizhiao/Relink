//! ELF (Executable and Linkable Format) parsing and data structures.
//!
//! This module provides a collection of types and utilities for working with
//! the ELF format as defined in the System V ABI. It includes support for headers,
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
#[cfg(feature = "object")]
pub(crate) use hash::ElfHashTable;
pub(crate) use hash::{HashTable, PreCompute};
pub(crate) use phdrs::ElfPhdrs;
#[cfg(any(feature = "object", feature = "version"))]
pub(crate) use symbol::ElfStringTable;
pub(crate) use symbol::{SymbolInfo, SymbolTable};

// Public API exports
pub use defs::{
    ElfClass, ElfFileType, ElfMachine, ElfPhdr, ElfProgramFlags, ElfProgramType,
    ElfRel, ElfRelType, ElfRela, ElfSectionFlags, ElfSectionType,
};
pub use dynamic::{ElfDyn, ElfDynamicTag};
/// Core ELF data types for program headers, relocations, and symbols.
pub use ehdr::ElfHeader;
pub use symbol::{ElfSymbol, ElfSymbolBind, ElfSymbolType};
