//! Symbol relocation and binding logic.
//!
//! This module implements the core relocation engine of the linker. It handles
//! fixing up addresses in the mapped ELF image based on symbol resolution,
//! supporting both static (initial) and dynamic (lazy) relocation types.

mod dynamic;
mod r#static;
mod tls;
mod traits;
mod utils;

pub(crate) use dynamic::{DynamicRelocation, dl_fixup};
pub(crate) use r#static::{StaticReloc, StaticRelocation};
pub(crate) use traits::{Relocatable, SupportLazy};
pub(crate) use utils::{
    RelocHelper, RelocValue, Relocator, SymDef, find_symdef_impl, likely, reloc_error, unlikely,
};

pub use traits::{RelocationContext, RelocationHandler, SymbolLookup};
