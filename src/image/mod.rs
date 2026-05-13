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
mod dylib;
mod dynamic;
mod elf;
mod exec;
#[cfg(feature = "object")]
mod object;
mod scanned;

#[cfg(any(feature = "lazy-binding", feature = "object"))]
pub(crate) use core::CoreInner;
pub(crate) use dynamic::DynamicInfo;
#[cfg(feature = "lazy-binding")]
pub(crate) use dynamic::LazyBindingInfo;
pub(crate) use dynamic::RawDynamicParts;
pub(crate) use scanned::ScannedDynamicLoadParts;

pub use core::{ElfCore, ElfCoreRef, LoadedCore, Symbol};
pub use dylib::RawDylib;
pub use dynamic::RawDynamic;
pub use elf::{LoadedElf, RawElf};
pub use exec::{LoadedExec, RawExec, StaticExec};
#[cfg(feature = "object")]
pub use object::{LoadedObject, RawObject};
pub use scanned::{
    ModuleCapability, ScannedDynamic, ScannedDynamicInfo, ScannedElf, ScannedExec, ScannedSection,
    ScannedSectionId,
};
