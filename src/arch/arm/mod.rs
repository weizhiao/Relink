//! ARM architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides ARM specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

#[cfg(feature = "lazy-binding")]
mod lazy;
#[cfg(feature = "tls")]
mod tls;

use elf::abi::*;

#[cfg(feature = "lazy-binding")]
pub(crate) use lazy::{DYLIB_OFFSET, RESOLVE_FUNCTION_OFFSET, dl_runtime_resolve};
#[cfg(feature = "tls")]
pub(crate) use tls::{get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static};

/// The ELF machine type for ARM architecture.
pub const EM_ARCH: u16 = EM_ARM;
/// Relative relocation type - add base address to relative offset.
pub const REL_RELATIVE: u32 = R_ARM_RELATIVE;
/// GOT entry relocation type - set GOT entry to symbol address.
pub const REL_GOT: u32 = R_ARM_GLOB_DAT;
/// Symbolic relocation type - set to absolute symbol address.
pub const REL_SYMBOLIC: u32 = R_ARM_ABS32;
/// PLT jump slot relocation type - set PLT entry to symbol address.
pub const REL_JUMP_SLOT: u32 = R_ARM_JUMP_SLOT;
/// IRELATIVE relocation type - call function to get address.
pub const REL_IRELATIVE: u32 = R_ARM_IRELATIVE;
/// COPY relocation type - copy data from shared object.
pub const REL_COPY: u32 = R_ARM_COPY;
pub const TLS_DTV_OFFSET: usize = 0;
pub const REL_DTPMOD: u32 = R_ARM_TLS_DTPMOD32;
pub const REL_DTPOFF: u32 = R_ARM_TLS_DTPOFF32;
pub const REL_TPOFF: u32 = R_ARM_TLS_TPOFF32;
pub const REL_TLSDESC: u32 = 0xffff_ffff;

pub(crate) struct Architecture;

impl crate::relocation::RelocationValueProvider for Architecture {}

/// Map arm relocation type to human readable name
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_ARM_NONE => "R_ARM_NONE",
        R_ARM_ABS32 => "R_ARM_ABS32",
        R_ARM_GLOB_DAT => "R_ARM_GLOB_DAT",
        R_ARM_JUMP_SLOT => "R_ARM_JUMP_SLOT",
        R_ARM_RELATIVE => "R_ARM_RELATIVE",
        R_ARM_IRELATIVE => "R_ARM_IRELATIVE",
        R_ARM_COPY => "R_ARM_COPY",
        _ => "UNKNOWN",
    }
}
