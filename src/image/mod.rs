//! Public image types returned by the loader and relocation pipeline.
//!
//! `Loader` produces raw image types such as [`RawElf`], [`RawDynamic`], [`RawDylib`],
//! and [`RawExec`].
//! Those raw values are mapped into memory but not yet relocated.
//!
//! After calling `.relocator().relocate()`, you get loaded image types such as
//! [`LoadedElf`], [`LoadedExec`], and [`LoadedCore`], which expose symbol lookup,
//! metadata, and dependency retention.

mod core;
mod elf;
mod module;
mod scanned;
mod synthetic;
mod traits;

pub use crate::elf::SymbolLookup;
pub use crate::segment::{ElfSegments, MappedRange};
pub(crate) use core::CoreRuntime;
pub use core::{ElfCore, ElfCoreRef, LoadedCore, Symbol};
pub(crate) use elf::DynamicInfo;
pub(crate) use elf::PltRelocInfo;
pub use elf::{LoadedElf, LoadedExec, RawDylib, RawDynamic, RawElf, RawExec, StaticExec};
#[cfg(feature = "object")]
pub use elf::{LoadedObject, RawObject};
pub(crate) use module::WeakModuleScope;
pub use module::{ModuleHandle, ModuleScope, ModuleScopeBuilder};
pub(crate) use scanned::ScannedDynamicLoadParts;
pub use scanned::{ModuleCapability, ScannedDynamic, ScannedElf, ScannedExec, ScannedSection};
pub use synthetic::{SyntheticModule, SyntheticSymbol};
pub(crate) use traits::exports_handle;
pub use traits::{Module, ModuleTls, SymbolExports};
