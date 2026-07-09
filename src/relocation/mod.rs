//! Relocation configuration, symbol scopes, and binding policy.
//!
//! Raw images returned by [`crate::Loader`] become executable through the relocation
//! pipeline. In practice, most users configure that pipeline with [`Relocator`],
//! pass the raw image to [`Relocator::run`], then call `relocate()`.
//!
//! This module exposes the main customization points used during relocation:
//!
//! - [`crate::image::SyntheticModule`] for providing external symbol addresses
//! - [`crate::observer::RelocationObserver`] for relocation, lifecycle, and
//!   runtime binding hooks
//! - [`RelocationEvent`] for inspecting the current relocation and search scope
//! - binding policy and lazy-fixup support configured through `Relocator`

mod defs;
mod dynamic;
mod helper;
mod relocator;
mod run;
mod traits;

pub(crate) use defs::{RelocValue, RelocationValueFormula, RelocationValueKind};
pub(crate) use dynamic::DynamicRelocation;
pub use dynamic::{relocate_relative, relocate_relr};
pub(crate) use helper::{RelocHelper, SymDef, find_symdef_impl};
pub use traits::{ObjectArch, RelocationArch};
pub(crate) use traits::{Relocatable, RelocateArgs, RelocationValueInput, RelocationValueProvider};

pub use crate::observer::{HandleResult, RelocationEvent};
pub use relocator::Relocator;
pub use run::RelocatorRun;
pub use traits::BindingMode;
