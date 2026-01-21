//! ELF relocation processing module.
//!
//! This module handles the relocation of ELF objects, resolving symbol references
//! and applying address fixups. It supports both static and dynamic linking scenarios.
//!
//! Key concepts:
//! - **Symbol Lookup**: Finding addresses of external symbols.
//! - **Relocation Handlers**: Custom logic for handling specific relocation types.
//! - **Lazy Binding**: Deferred symbol resolution for performance.
//! - **Scope**: The set of loaded modules available for symbol resolution.
//!
//! # Safety
//! Relocation involves direct memory manipulation. Ensure proper bounds checking
//! and avoid corrupting memory during address calculations.

mod dynamic;
mod r#static;
mod tls;
mod traits;
mod utils;

pub(crate) use dynamic::{DynamicRelocation, dl_fixup};
pub(crate) use r#static::{StaticReloc, StaticRelocation};
pub(crate) use traits::Relocatable;
pub(crate) use utils::{
    RelocHelper, RelocValue, Relocator, SymDef, find_symbol_addr, find_symdef_impl, likely,
    reloc_error, unlikely,
};

pub use crate::tls::TlsResolver;
pub use traits::{RelocationContext, RelocationHandler, SymbolLookup};
