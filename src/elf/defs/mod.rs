//! ELF format definitions and utilities.
//!
//! This module contains the raw 32/64-bit access traits, layout selection,
//! semantic wrapper types, and relocation-entry definitions shared by the
//! higher-level ELF parsing modules.

mod layout;
mod raw;
mod rel;
mod types;

pub(crate) use layout::ElfEhdr;
pub use layout::{Elf32Layout, Elf64Layout, ElfLayout, NativeElfLayout};
pub use raw::{Elf32Sym, ElfWord};
pub(crate) use raw::{ElfDynRaw, ElfEhdrRaw, ElfPhdrRaw, ElfShdrRaw, ElfSymRaw};
pub use rel::{ElfRel, ElfRelEntry, ElfRelType, ElfRela, ElfRelr};
pub use types::{
    ElfClass, ElfDynamicTag, ElfFileType, ElfMachine, ElfProgramFlags, ElfProgramType,
    ElfRelocationType, ElfSectionFlags, ElfSectionIndex, ElfSectionType, ElfSymbolBind,
    ElfSymbolType,
};
