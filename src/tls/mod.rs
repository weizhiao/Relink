//! Thread Local Storage (TLS) management.
//!
//! This module provides support for both static and dynamic TLS models.
//! It includes the `TlsResolver` trait for integrating with the environment's
//! thread management system and a default implementation for standard setups.

mod defs;
mod manager;
mod traits;

pub(crate) use defs::TlsDescDynamicArg;

pub use defs::{TlsIndex, TlsInfo};
pub use manager::DefaultTlsResolver;
pub use traits::TlsResolver;
