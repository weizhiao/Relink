//! ELF writing helpers.
//!
//! The runtime loader mostly consumes ELF files, but higher-level users also
//! need small generated dynamic objects.  This module keeps that byte-writing
//! logic close to the parser/linker code while remaining independent from test
//! tooling such as `tools/gen-elf`.

mod dso;

pub use dso::{
    DsoBuilder, DsoExport, DsoExportLayout, DsoImage, DsoSymbolBind, DsoSymbolKind, sysv_hash,
};
