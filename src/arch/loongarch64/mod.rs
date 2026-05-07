//! LoongArch 64-bit architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides LoongArch 64-bit specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.
//!
//! Reference: https://loongson.github.io/LoongArch-Documentation/LoongArch-ELF-ABI-CN.html

// See aarch64/mod.rs for why these are gated on `target_arch`.
#[cfg(all(feature = "lazy-binding", target_arch = "loongarch64"))]
mod lazy;
#[cfg(all(feature = "tls", target_arch = "loongarch64"))]
mod tls;

/// Custom relocation type constants for LoongArch 64-bit.
/// These are defined locally as they may not be available in all elf crate versions.
const EM_LARCH: u16 = 258;
pub(super) const R_LARCH_64: u32 = 2;
pub(super) const R_LARCH_RELATIVE: u32 = 3;
pub(super) const R_LARCH_COPY: u32 = 4;
pub(super) const R_LARCH_JUMP_SLOT: u32 = 5;
pub(super) const R_LARCH_TLS_DTPMOD64: u32 = 7;
pub(super) const R_LARCH_TLS_DTPREL64: u32 = 9;
pub(super) const R_LARCH_TLS_TPREL64: u32 = 11;
pub(super) const R_LARCH_IRELATIVE: u32 = 12;

#[cfg(all(feature = "lazy-binding", target_arch = "loongarch64"))]
pub(crate) use lazy::{DYLIB_OFFSET, RESOLVE_FUNCTION_OFFSET, dl_runtime_resolve};
#[cfg(all(feature = "tls", target_arch = "loongarch64"))]
pub(crate) use tls::{get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static};

pub mod relocation;

/// The ELF machine type for LoongArch architecture.
pub const EM_ARCH: u16 = EM_LARCH;
/// TLS dynamic thread vector offset for LoongArch 64-bit.
pub const TLS_DTV_OFFSET: usize = 0;
