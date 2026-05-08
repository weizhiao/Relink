//! ARM architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides ARM specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

// See aarch64/mod.rs for why these are gated on `target_arch`.
#[cfg(all(feature = "lazy-binding", target_arch = "arm"))]
mod lazy;
#[cfg(all(feature = "tls", target_arch = "arm"))]
mod tls;

#[cfg(all(feature = "lazy-binding", target_arch = "arm"))]
pub(crate) use lazy::{DYLIB_OFFSET, RESOLVE_FUNCTION_OFFSET, dl_runtime_resolve};
#[cfg(all(feature = "tls", target_arch = "arm"))]
pub(crate) use tls::{get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static};

pub mod relocation;
