//! Thread Local Storage (TLS) management.
//!
//! This module provides support for both static and dynamic TLS models.
//! It includes the `TlsResolver` trait for integrating with the environment's
//! thread management system and, when the `tls` feature is enabled, a default
//! implementation for standard setups.

mod defs;
#[cfg(feature = "tls")]
mod manager;
mod relocation;
mod state;
mod traits;

pub(crate) use state::{CoreTlsState, TlsDescArgs};

pub use defs::{TlsIndex, TlsInfo, TlsModuleId, TlsTpOffset};
#[cfg(feature = "tls")]
pub use manager::DefaultTlsResolver;
pub(crate) use relocation::{TlsRelocOutcome, handle_tls_reloc, lookup_tls_get_addr};
pub use traits::TlsResolver;
