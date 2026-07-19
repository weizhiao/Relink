//! ELF (Executable and Linkable Format) parsing and data structures.
//!
//! This module provides a collection of types and utilities for working with
//! the ELF format as defined in the System V ABI. It includes support for headers,
//! program headers, section headers, dynamic sections, and symbol tables.

use crate::ByteRepr;

/// ELF ABI constants.
pub mod abi;
mod dynamic;
mod ehdr;
mod hash;
mod layout;
mod lifecycle;
mod note;
mod phdr;
mod raw;
mod rel;
mod shdr;
mod symbol;
#[cfg(feature = "version")]
pub(crate) mod version;
pub mod write;

// Internal module re-exports for use within the crate
pub(crate) use dynamic::{ElfDynamic, ElfDynamicHashTab, LifecycleSpec, parse_dynamic_entries};
#[cfg(feature = "object")]
pub(crate) use hash::SymbolHash;
#[cfg(test)]
pub(crate) use layout::ElfEhdr;
pub(crate) use phdr::ElfPhdrs;
pub(crate) use symbol::ElfStringTable;
#[cfg(test)]
pub(crate) use symbol::SymbolInfo;

// Public API exports
pub use dynamic::{ElfDyn, ElfDynamicTag};
/// Core ELF data types for program headers, relocations, and symbols.
pub use ehdr::{ElfClass, ElfFileType, ElfHeader, ElfMachine};
pub use hash::HashTable;
pub use layout::{Elf32Layout, Elf64Layout, ElfDataEncoding, ElfLayout, NativeElfLayout};
pub use lifecycle::Lifecycle;
pub use note::{ElfNhdr, ElfNote, ElfNotes};
pub use phdr::{ElfPhdr, ElfProgramFlags, ElfProgramType};
pub use raw::{Elf32Sym, ElfWord};
pub use rel::{ElfRel, ElfRelEntry, ElfRelType, ElfRela, ElfRelocationType, ElfRelr};
pub use shdr::{ElfSectionFlags, ElfSectionId, ElfSectionType, ElfShdr};
pub use symbol::{
    ElfSectionIndex, ElfSymbol, ElfSymbolBind, ElfSymbolType, ElfSymbolVisibility, SymbolEntry,
    SymbolLookup, SymbolTable, SymbolTableView,
};

unsafe impl ByteRepr for layout::ElfEhdr {}
unsafe impl<L: layout::ElfLayout> ByteRepr for dynamic::ElfDyn<L> {}
unsafe impl ByteRepr for note::ElfNhdr {}
unsafe impl<L: layout::ElfLayout> ByteRepr for phdr::ElfPhdr<L> {}
unsafe impl<L: layout::ElfLayout> ByteRepr for shdr::ElfShdr<L> {}
unsafe impl<L: layout::ElfLayout> ByteRepr for symbol::ElfSymbol<L> {}
unsafe impl<L: layout::ElfLayout> ByteRepr for rel::ElfRelr<L> {}
unsafe impl<L: layout::ElfLayout> ByteRepr for rel::ElfRela<L> {}
unsafe impl<L: layout::ElfLayout> ByteRepr for rel::ElfRel<L> {}
