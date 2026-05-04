//! RISC-V 32-bit architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides RISC-V 32-bit specific implementations for ELF relocation,
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

/// The ELF machine type for RISC-V architecture.
pub const EM_ARCH: u16 = EM_RISCV;
/// Relative relocation type - add base address to relative offset.
pub const REL_RELATIVE: u32 = R_RISCV_RELATIVE;
/// GOT entry relocation type - set GOT entry to symbol address.
pub const REL_GOT: u32 = R_RISCV_32;
/// Symbolic relocation type - set to absolute symbol address.
pub const REL_SYMBOLIC: u32 = R_RISCV_32;
/// PLT jump slot relocation type - set PLT entry to symbol address.
pub const REL_JUMP_SLOT: u32 = R_RISCV_JUMP_SLOT;
/// IRELATIVE relocation type - call function to get address.
pub const REL_IRELATIVE: u32 = R_RISCV_IRELATIVE;
/// COPY relocation type - copy data from shared object.
pub const REL_COPY: u32 = R_RISCV_COPY;
pub const TLS_DTV_OFFSET: usize = 0;
pub const REL_DTPMOD: u32 = R_RISCV_TLS_DTPMOD32;
pub const REL_DTPOFF: u32 = R_RISCV_TLS_DTPREL32;
pub const REL_TPOFF: u32 = R_RISCV_TLS_TPREL32;
pub const REL_TLSDESC: u32 = 0;

pub(crate) struct Architecture;

impl crate::relocation::RelocationValueProvider for Architecture {}

/// Map riscv32 relocation types to human readable names
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_RISCV_NONE => "R_RISCV_NONE",
        R_RISCV_32 => "R_RISCV_32",
        R_RISCV_RELATIVE => "R_RISCV_RELATIVE",
        R_RISCV_COPY => "R_RISCV_COPY",
        R_RISCV_JUMP_SLOT => "R_RISCV_JUMP_SLOT",
        R_RISCV_IRELATIVE => "R_RISCV_IRELATIVE",
        _ => "UNKNOWN",
    }
}
