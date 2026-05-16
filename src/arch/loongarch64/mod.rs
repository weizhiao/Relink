//! LoongArch 64-bit architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides LoongArch 64-bit specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.
//!
//! Reference: <https://loongson.github.io/LoongArch-Documentation/LoongArch-ELF-ABI-CN.html>

// See aarch64/mod.rs for why these are gated on `target_arch`.
#[cfg(all(feature = "lazy-binding", target_arch = "loongarch64"))]
mod lazy;
#[cfg(all(feature = "tls", target_arch = "loongarch64"))]
mod tls;

#[cfg(all(feature = "lazy-binding", target_arch = "loongarch64"))]
pub(crate) use lazy::{DYLIB_OFFSET, RESOLVE_FUNCTION_OFFSET, dl_runtime_resolve};
#[cfg(all(feature = "tls", target_arch = "loongarch64"))]
pub(crate) use tls::{get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static};

pub mod relocation;
