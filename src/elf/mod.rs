//! ELF (Executable and Linkable Format) parsing and data structures.
//!
//! This module provides a collection of types and utilities for working with
//! the ELF format as defined in the System V ABI. It includes support for headers,
//! program headers, section headers, dynamic sections, and symbol tables.

use crate::ByteRepr;

/// ELF ABI constants.
pub mod abi;
mod defs;
mod dynamic;
mod ehdr;
mod hash;
mod phdr;
mod shdr;
mod symbol;
#[cfg(feature = "version")]
mod version;
pub mod write;

// Internal module re-exports for use within the crate
pub(crate) use defs::*;
pub(crate) use dynamic::{ElfDynamic, ElfDynamicHashTab, parse_dynamic_entries};
#[cfg(feature = "object")]
pub(crate) use hash::ElfHashTable;
pub(crate) use hash::HashTable;
pub(crate) use phdr::ElfPhdrs;
pub(crate) use shdr::ElfShdr;
pub(crate) use symbol::ElfStringTable;

// Public API exports
pub use defs::{
    Elf32Layout, Elf32Sym, Elf64Layout, ElfClass, ElfDynamicTag, ElfFileType, ElfLayout,
    ElfMachine, ElfProgramFlags, ElfProgramType, ElfRel, ElfRelEntry, ElfRelType, ElfRela,
    ElfRelocationType, ElfSectionFlags, ElfSectionIndex, ElfSectionType, ElfSymbolBind,
    ElfSymbolType, Lifecycle, NativeElfLayout,
};
pub use dynamic::ElfDyn;
/// Core ELF data types for program headers, relocations, and symbols.
pub use ehdr::ElfHeader;
pub use hash::PreCompute;
pub use phdr::ElfPhdr;
pub use symbol::{ElfSymbol, SymbolInfo, SymbolTable};

unsafe impl ByteRepr for defs::ElfEhdr {}
unsafe impl<L: defs::ElfLayout> ByteRepr for dynamic::ElfDyn<L> {}
unsafe impl<L: defs::ElfLayout> ByteRepr for phdr::ElfPhdr<L> {}
unsafe impl<L: defs::ElfLayout> ByteRepr for shdr::ElfShdr<L> {}
unsafe impl<L: defs::ElfLayout> ByteRepr for symbol::ElfSymbol<L> {}
unsafe impl<L: defs::ElfLayout> ByteRepr for defs::ElfRelr<L> {}
unsafe impl<L: defs::ElfLayout> ByteRepr for defs::ElfRela<L> {}
unsafe impl<L: defs::ElfLayout> ByteRepr for defs::ElfRel<L> {}
