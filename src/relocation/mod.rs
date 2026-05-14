//! Relocation configuration, symbol scopes, and binding policy.
//!
//! Raw images returned by [`crate::Loader`] become executable through the relocation
//! pipeline. In practice, most users configure that pipeline through the builder
//! returned by `.relocator()`, then call `relocate()`.
//!
//! This module exposes the main customization points used during relocation:
//!
//! - [`crate::image::SyntheticModule`] for providing external symbol addresses
//! - [`RelocationHandler`] for intercepting or overriding relocations
//! - [`Emulator`] for guest runtime hooks during non-native relocation
//! - [`RelocationContext`] for inspecting the current relocation and search scope
//! - binding policy and lazy-fixup support configured through `Relocator`

mod defs;
mod dynamic;
mod emu;
mod helper;
mod lazy;
mod relocator;
mod traits;

pub(crate) use defs::{
    RelocAddr, RelocValue, RelocationValueFormula, RelocationValueKind, resolve_ifunc,
};
pub(crate) use dynamic::DynamicRelocation;
pub use emu::{EmuContext, EmuRelocationContext, EmulatedArch, Emulator};
pub use emu::{TlsDescEmuRequest, TlsDescEmuValue};
pub(crate) use helper::{RelocHelper, SymDef, find_symdef_impl, likely, reloc_error, unlikely};
pub(crate) use lazy::ResolvedBinding;
#[cfg(feature = "lazy-binding")]
pub(crate) use lazy::dl_fixup;
pub use traits::RelocationArch;
pub(crate) use traits::{Relocatable, RelocateArgs, RelocationValueProvider, SupportLazy};

pub use relocator::Relocator;
pub use traits::{BindingMode, HandleResult, RelocationContext, RelocationHandler};
