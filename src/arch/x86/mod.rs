//! x86 (32-bit) architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides x86 32-bit specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

// See aarch64/mod.rs for why these are gated on `target_arch`.
#[cfg(all(feature = "lazy-binding", target_arch = "x86"))]
mod lazy;
#[cfg(all(feature = "tls", target_arch = "x86"))]
mod tls;

#[cfg(all(feature = "lazy-binding", target_arch = "x86"))]
pub(crate) use lazy::{DYLIB_OFFSET, RESOLVE_FUNCTION_OFFSET, dl_runtime_resolve};
#[cfg(all(feature = "tls", target_arch = "x86"))]
pub(crate) use tls::{get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static};

pub mod relocation;
