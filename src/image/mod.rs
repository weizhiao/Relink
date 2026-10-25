//! Raw and relocated ELF images, synthetic modules, and symbol scopes.
//!
//! [`crate::LoaderRun`] returns mapped raw images such as [`RawDylib`] and [`RawExec`].
//! Relocate them with [`crate::Relocator::run`] to obtain loaded images with symbol lookup.

mod core;
mod elf;
mod exports;
mod module;
mod scanned;
mod search;
mod symbol_name;
mod synthetic;
mod traits;

pub use crate::elf::SymbolLookup;
pub use crate::segment::{ElfSegments, MappedRange};
pub(crate) use core::CoreRuntime;
pub use core::{ElfCore, ElfCoreRef, ElfModule, LoadedCore, Symbol};
pub(crate) use elf::DynamicInfo;
pub use elf::{LoadedElf, LoadedExec, RawDylib, RawDynamic, RawElf, RawExec, StaticExec};
#[cfg(feature = "object")]
pub use elf::{LoadedObject, RawObject};
pub use exports::{ExportTable, SymbolMap, SymbolVersion, SyntheticSymbol};
pub(crate) use module::WeakLocalScope;
pub use module::{
    GlobalScope, LocalScope, ModuleHandle, ModuleInstanceId, ModuleScope, ModuleState,
};
pub(crate) use scanned::ScannedDynamicLoadParts;
pub use scanned::{ModuleCapability, ScannedDynamic, ScannedElf, ScannedExec, ScannedSection};
pub use search::{ModuleSearch, PathTokens, SearchPathPool};
pub(crate) use search::{SharedDir, default_module_search, library_path_components, normalize_dir};
pub use symbol_name::SymbolName;
pub use synthetic::{ResolveHook, SyntheticModule};
pub use traits::Module;
