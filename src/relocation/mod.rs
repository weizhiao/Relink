//! Relocation configuration, symbol lookup hooks, and binding policy.
//!
//! Raw images returned by [`crate::Loader`] become executable through the relocation
//! pipeline. In practice, most users configure that pipeline through the builder
//! returned by `.relocator()`, then call `relocate()`.
//!
//! This module exposes the main customization points used during relocation:
//!
//! - [`SymbolLookup`] for providing external symbol addresses
//! - [`RelocationHandler`] for intercepting or overriding relocations
//! - [`RelocationContext`] for inspecting the current relocation and search scope
//! - binding policy and lazy-fixup support configured through `Relocator`

mod dynamic;
mod lazy;
mod relocator;
mod support;
mod traits;

pub(crate) use dynamic::DynamicRelocation;
pub(crate) use lazy::ResolvedBinding;
#[cfg(feature = "lazy-binding")]
pub(crate) use lazy::dl_fixup;
pub(crate) use support::{
    RelocAddr, RelocHelper, RelocValue, RelocationValueFormula, RelocationValueKind,
    RelocationValueProvider, SymDef, find_symdef_impl, likely, reloc_error, resolve_ifunc,
    unlikely,
};
pub use traits::RelocationArch;
pub(crate) use traits::{
    HandlerHooks, LazyLookupHooks, LookupHooks, Relocatable, RelocateArgs, SupportLazy,
};

pub use relocator::Relocator;
pub use traits::{BindingMode, HandleResult, RelocationContext, RelocationHandler, SymbolLookup};
