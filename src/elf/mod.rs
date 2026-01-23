//! ELF (Executable and Linkable Format) data structures and utilities.

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
pub(crate) use ehdr::ElfHeader;
pub(crate) use hash::{HashTable, PreCompute};
pub(crate) use phdrs::ElfPhdrs;
pub(crate) use symbol::{ElfStringTable, SymbolInfo, SymbolTable};

// Public API exports
/// Core ELF data types for program headers, relocations, and symbols.
pub use defs::{ElfDyn, ElfPhdr, ElfRel, ElfRela, ElfSymbol};
/// ELF ABI constants and definitions from the elf crate.
pub use elf::abi::*;
