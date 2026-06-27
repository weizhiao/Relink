//! Thread Local Storage (TLS) management.
//!
//! This module provides support for both static and dynamic TLS models.
//! It includes the `TlsResolver<Arch>` trait for integrating with the environment's
//! thread management system and, when the `tls` feature is enabled, a default
//! implementation for standard setups.

mod defs;
#[cfg(feature = "tls")]
mod manager;
mod relocation;
mod state;
mod traits;

pub(crate) use defs::{TLS_GET_ADDR_SYMBOL, TlsImageProvider, tls_image_provider_handle};
pub(crate) use state::CoreTlsState;

pub use defs::{
    TlsDescValue, TlsImageSource, TlsIndex, TlsInfo, TlsModuleId, TlsTemplate, TlsTpOffset,
};
#[cfg(feature = "tls")]
pub use manager::DefaultTlsResolver;
pub(crate) use relocation::TlsRelocOutcome;
pub use traits::TlsResolver;
