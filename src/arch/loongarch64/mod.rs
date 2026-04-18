//! LoongArch 64-bit architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides LoongArch 64-bit specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.
//!
//! Reference: https://loongson.github.io/LoongArch-Documentation/LoongArch-ELF-ABI-CN.html

#[cfg(feature = "lazy-binding")]
mod lazy;
#[cfg(feature = "tls")]
mod tls;

/// Custom relocation type constants for LoongArch 64-bit.
/// These are defined locally as they may not be available in all elf crate versions.
const EM_LARCH: u16 = 258;
const R_LARCH_64: u32 = 2;
const R_LARCH_RELATIVE: u32 = 3;
const R_LARCH_COPY: u32 = 4;
const R_LARCH_JUMP_SLOT: u32 = 5;
const R_LARCH_TLS_DTPMOD64: u32 = 7;
const R_LARCH_TLS_DTPREL64: u32 = 9;
const R_LARCH_TLS_TPREL64: u32 = 11;
const R_LARCH_IRELATIVE: u32 = 12;

#[cfg(feature = "lazy-binding")]
pub(crate) use lazy::{DYLIB_OFFSET, RESOLVE_FUNCTION_OFFSET, dl_runtime_resolve};
#[cfg(feature = "tls")]
pub use tls::{REL_DTPMOD, REL_DTPOFF, REL_TLSDESC, REL_TPOFF, TLS_DTV_OFFSET};
#[cfg(feature = "tls")]
pub(crate) use tls::{get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static};

/// The ELF machine type for LoongArch architecture.
pub const EM_ARCH: u16 = EM_LARCH;
/// Symbolic relocation type - set to absolute symbol address.
pub const REL_SYMBOLIC: u32 = R_LARCH_64;
/// Relative relocation type - add base address to relative offset.
pub const REL_RELATIVE: u32 = R_LARCH_RELATIVE;
/// COPY relocation type - copy data from shared object.
pub const REL_COPY: u32 = R_LARCH_COPY;
/// PLT jump slot relocation type - set PLT entry to symbol address.
pub const REL_JUMP_SLOT: u32 = R_LARCH_JUMP_SLOT;
/// IRELATIVE relocation type - call function to get address.
pub const REL_IRELATIVE: u32 = R_LARCH_IRELATIVE;

/// GOT entry relocation type - set GOT entry to symbol address.
pub const REL_GOT: u32 = R_LARCH_64;

pub(crate) struct Architecture;

impl crate::relocation::RelocationValueProvider for Architecture {}

/// Map loongarch64 relocation types to human readable names
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_LARCH_64 => "R_LARCH_64",
        R_LARCH_RELATIVE => "R_LARCH_RELATIVE",
        R_LARCH_COPY => "R_LARCH_COPY",
        R_LARCH_JUMP_SLOT => "R_LARCH_JUMP_SLOT",
        R_LARCH_TLS_DTPMOD64 => "R_LARCH_TLS_DTPMOD64",
        R_LARCH_TLS_DTPREL64 => "R_LARCH_TLS_DTPREL64",
        R_LARCH_IRELATIVE => "R_LARCH_IRELATIVE",
        _ => "UNKNOWN",
    }
}
