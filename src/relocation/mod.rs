//! Relocation, symbol lookup, and binding policy.
//!
//! Pass a raw image to [`Relocator::run`], configure its scopes, then call `relocate()`.
//! Supply host symbols through [`crate::image::SyntheticModule`] and customize
//! relocation through [`crate::observer::RelocationObserver`].

mod defs;
mod dynamic;
mod helper;
mod relocator;
mod run;
mod symbol;
mod traits;

pub(crate) use defs::{RelocValue, RelocationValueFormula, RelocationValueKind};
pub(crate) use dynamic::DynamicRelocation;
pub use dynamic::{relocate_relative, relocate_relr};
pub(crate) use helper::{BindingDeps, RelocHelper};
pub(crate) use symbol::{BindingEffect, SymDef, SymbolRegistry, SymbolResolver, SymbolSearch};
#[cfg(feature = "object")]
pub(crate) use traits::ObjectRelocation;
pub use traits::{ObjectArch, RelocationArch};
pub(crate) use traits::{Relocatable, RelocateArgs, RelocationValueInput, RelocationValueProvider};

pub use crate::observer::RelocationEvent;
pub use defs::HandleResult;
pub use relocator::Relocator;
pub use run::RelocatorRun;
pub use traits::{BindingMode, LookupOrder};
