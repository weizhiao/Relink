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

#[cfg(feature = "lazy-binding")]
pub(crate) use core::CoreInner;
pub use core::{ElfCore, ElfCoreRef, LoadedCore, LoadedDeps, Symbol};
pub(crate) use elf::DynamicInfo;
#[cfg(feature = "lazy-binding")]
pub(crate) use elf::LazyBindingInfo;
pub(crate) use elf::RawDynamicParts;
pub use elf::{LoadedElf, LoadedExec, RawDylib, RawDynamic, RawElf, RawExec, StaticExec};
#[cfg(feature = "object")]
pub use elf::{LoadedObject, RawObject};
pub use module::{ModuleHandle, ModuleScope};
pub(crate) use scanned::ScannedDynamicLoadParts;
pub use scanned::{ModuleCapability, ScannedDynamic, ScannedElf, ScannedExec, ScannedSection};
pub use synthetic::{SyntheticModule, SyntheticSymbol};
pub(crate) use traits::exports_handle;
pub use traits::{Module, SymbolExports};
