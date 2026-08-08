//! `gen-elf` is a utility for generating ELF files (Shared Objects and Relocatable Objects)
//! specifically designed for testing ELF loaders.
#![warn(unreachable_pub)]

mod arch;
mod common;
mod dylib;
mod relocatable;

pub use arch::Arch;
pub use common::{
    ContentKind, RelocEntry, RelocType, SectionKind, SymbolDesc, SymbolScope, SymbolType,
};
pub use dylib::{DylibWriter, ElfWriteOutput, ElfWriterConfig, RelocationInfo};
pub use relocatable::{ObjectElfOutput, ObjectWriter};
