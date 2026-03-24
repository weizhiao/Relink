//! Thread Local Storage (TLS) management.
//!
//! This module provides support for both static and dynamic TLS models.
//! It includes the `TlsResolver` trait for integrating with the environment's
//! thread management system and, when the `tls` feature is enabled, a default
//! implementation for standard setups.

mod defs;
#[cfg(feature = "tls")]
mod manager;
#[cfg(feature = "tls")]
mod relocation;
mod state;
mod traits;

pub(crate) use defs::TlsDescDynamicArg;
pub(crate) use state::{CoreTlsState, TlsDescArgs};

pub use defs::{TlsIndex, TlsInfo};
#[cfg(feature = "tls")]
pub use manager::DefaultTlsResolver;
#[cfg(feature = "tls")]
pub(crate) use relocation::{handle_tls_reloc, lookup_tls_get_addr};
pub use traits::TlsResolver;

#[cfg(not(feature = "tls"))]
mod disabled {
    use crate::{
        elf::ElfRelType,
        relocation::{RelocHelper, RelocationHandler, SymbolLookup},
    };

    #[inline]
    pub(crate) fn lookup_tls_get_addr(_name: &str, _tls_get_addr: usize) -> Option<*const ()> {
        None
    }

    #[inline]
    pub(crate) fn handle_tls_reloc<D, PreS, PostS, PreH, PostH>(
        _helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
        _rel: &ElfRelType,
    ) -> bool
    where
        D: 'static,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        false
    }
}

#[cfg(not(feature = "tls"))]
pub(crate) use disabled::{handle_tls_reloc, lookup_tls_get_addr};
