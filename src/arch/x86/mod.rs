//! x86 (32-bit) architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides x86 32-bit specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

#[cfg(feature = "lazy-binding")]
mod lazy;
#[cfg(feature = "tls")]
mod tls;

use elf::abi::*;

#[cfg(feature = "lazy-binding")]
pub(crate) use lazy::{DYLIB_OFFSET, RESOLVE_FUNCTION_OFFSET, dl_runtime_resolve};
#[cfg(feature = "tls")]
pub use tls::{REL_DTPMOD, REL_DTPOFF, REL_TLSDESC, REL_TPOFF, TLS_DTV_OFFSET};
#[cfg(feature = "tls")]
pub(crate) use tls::{get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static};

/// Custom relocation type constants for x86 (32-bit).
/// These are defined locally since they may not be available in all elf crate versions.
const R_386_32: u32 = 1;
const R_386_GLOB_DAT: u32 = 6;
const R_386_JMP_SLOT: u32 = 7;
const R_386_RELATIVE: u32 = 8;
const R_386_COPY: u32 = 5;
const R_386_TLS_DTPMOD32: u32 = 35;
const R_386_TLS_DTPOFF32: u32 = 36;
const R_386_IRELATIVE: u32 = 42;
const R_386_TLS_TPOFF: u32 = 14;

/// The ELF machine type for x86 architecture.
pub const EM_ARCH: u16 = EM_386;

pub const REL_RELATIVE: u32 = R_386_RELATIVE;
pub const REL_GOT: u32 = R_386_GLOB_DAT;
pub const REL_SYMBOLIC: u32 = R_386_32;
pub const REL_JUMP_SLOT: u32 = R_386_JMP_SLOT;
pub const REL_IRELATIVE: u32 = R_386_IRELATIVE;
pub const REL_COPY: u32 = R_386_COPY;

pub(crate) struct Architecture;

impl crate::relocation::RelocationValueProvider for Architecture {}

/// Map x86 relocation type to human readable name
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_386_32 => "R_386_32",
        R_386_GLOB_DAT => "R_386_GLOB_DAT",
        R_386_COPY => "R_386_COPY",
        R_386_JMP_SLOT => "R_386_JMP_SLOT",
        R_386_RELATIVE => "R_386_RELATIVE",
        R_386_TLS_DTPMOD32 => "R_386_TLS_DTPMOD32",
        R_386_TLS_DTPOFF32 => "R_386_TLS_DTPOFF32",
        R_386_IRELATIVE => "R_386_IRELATIVE",
        R_386_TLS_TPOFF => "R_386_TLS_TPOFF",
        _ => "UNKNOWN",
    }
}
