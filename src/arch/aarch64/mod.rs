//! AArch64 architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides AArch64 specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

// `lazy` and `tls` contain naked assembly that is only valid when the host
// CPU matches this module's architecture. Other architectures only need the
// pure-data items (relocation type numbers, ...) so we gate the
// platform-specific submodules on `target_arch`.
#[cfg(all(feature = "lazy-binding", target_arch = "aarch64"))]
mod lazy;
#[cfg(all(feature = "tls", target_arch = "aarch64"))]
mod tls;

#[cfg(all(feature = "lazy-binding", target_arch = "aarch64"))]
pub(crate) use lazy::{DYLIB_OFFSET, RESOLVE_FUNCTION_OFFSET, dl_runtime_resolve};
#[cfg(all(feature = "tls", target_arch = "aarch64"))]
pub(crate) use tls::{get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static};

pub mod relocation;
