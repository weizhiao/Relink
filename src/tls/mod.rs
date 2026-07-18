//! Thread Local Storage (TLS) management.
//!
//! This module provides support for both static and dynamic TLS models.
//! It includes the `TlsResolver<Arch>` trait for integrating with the environment's
//! thread management system and, when the `tls` feature is enabled, a default
//! implementation for standard setups.

mod defs;
#[cfg(feature = "tls")]
mod manager;
mod registry;
mod relocation;
mod state;
mod thread;
mod traits;

pub(crate) use defs::{TLS_GET_ADDR_SYMBOL, TlsImageProvider, tls_image_provider_handle};
pub(crate) use state::CoreTlsState;

pub use defs::{
    ModuleTls, TlsDescBinding, TlsDescRequest, TlsImageSource, TlsIndex, TlsInfo, TlsModuleId,
    TlsRequest, TlsTpOffset,
};
#[cfg(feature = "tls")]
pub use manager::DefaultTlsResolver;
pub use registry::{
    TlsModuleSnapshot, TlsRegistry, TlsRegistrySnapshot, TlsSlotSnapshot, TlsStorage,
};
pub(crate) use relocation::TlsRelocOutcome;
pub use thread::ThreadDtv;
pub use traits::TlsResolver;
