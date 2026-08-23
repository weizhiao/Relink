//! `gen-elf` generates shared and relocatable ELF objects for loader tests.
#![warn(missing_docs, unreachable_pub)]

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
