//! x86 (32-bit) architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides x86 32-bit specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

// See aarch64/mod.rs for why these are gated on `target_arch`.
#[cfg(all(feature = "lazy-binding", target_arch = "x86"))]
mod lazy;
#[cfg(all(feature = "tls", target_arch = "x86"))]
mod tls;

use elf::abi::EM_386;

#[cfg(all(feature = "lazy-binding", target_arch = "x86"))]
pub(crate) use lazy::{DYLIB_OFFSET, RESOLVE_FUNCTION_OFFSET, dl_runtime_resolve};
#[cfg(all(feature = "tls", target_arch = "x86"))]
pub(crate) use tls::{get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static};

/// Custom relocation type constants for x86 (32-bit).
/// These are defined locally since they may not be available in all elf crate versions.
pub(super) const R_386_32: u32 = 1;
pub(super) const R_386_GLOB_DAT: u32 = 6;
pub(super) const R_386_JMP_SLOT: u32 = 7;
pub(super) const R_386_RELATIVE: u32 = 8;
pub(super) const R_386_COPY: u32 = 5;
pub(super) const R_386_TLS_DTPMOD32: u32 = 35;
pub(super) const R_386_TLS_DTPOFF32: u32 = 36;
pub(super) const R_386_IRELATIVE: u32 = 42;
pub(super) const R_386_TLS_TPOFF: u32 = 14;

pub mod relocation;

/// The ELF machine type for x86 architecture.
pub const EM_ARCH: u16 = EM_386;
/// TLS dynamic thread vector offset for x86.
pub const TLS_DTV_OFFSET: usize = 0;
