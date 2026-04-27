//! x86-64 architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides x86-64 specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

#[cfg(feature = "lazy-binding")]
mod lazy;
#[cfg(feature = "object")]
pub(crate) mod object;
pub(crate) mod rewrite;
#[cfg(feature = "tls")]
mod tls;

use crate::RelocationError;
use crate::relocation::{RelocationValueFormula, RelocationValueKind, RelocationValueProvider};
use elf::abi::*;

#[cfg(feature = "lazy-binding")]
pub(crate) use lazy::{DYLIB_OFFSET, RESOLVE_FUNCTION_OFFSET, dl_runtime_resolve};
#[cfg(feature = "tls")]
pub use tls::{REL_DTPMOD, REL_DTPOFF, REL_TLSDESC, REL_TPOFF, TLS_DTV_OFFSET};
#[cfg(feature = "tls")]
pub(crate) use tls::{get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static};

/// The ELF machine type for x86-64 architecture.
pub const EM_ARCH: u16 = EM_X86_64;

/// Relative relocation type - add base address to relative offset.
pub const REL_RELATIVE: u32 = R_X86_64_RELATIVE;
/// GOT entry relocation type - set GOT entry to symbol address.
pub const REL_GOT: u32 = R_X86_64_GLOB_DAT;
/// Symbolic relocation type - set to absolute symbol address.
pub const REL_SYMBOLIC: u32 = R_X86_64_64;
/// PLT jump slot relocation type - set PLT entry to symbol address.
pub const REL_JUMP_SLOT: u32 = R_X86_64_JUMP_SLOT;
/// IRELATIVE relocation type - call function to get address.
pub const REL_IRELATIVE: u32 = R_X86_64_IRELATIVE;
/// COPY relocation type - copy data from shared object.
pub const REL_COPY: u32 = R_X86_64_COPY;

pub(crate) struct Architecture;

impl RelocationValueProvider for Architecture {
    fn relocation_value_kind(
        relocation_type: usize,
    ) -> core::result::Result<RelocationValueKind, RelocationError> {
        use RelocationValueFormula::{Absolute, RelativeToPlace};
        match relocation_type as u32 {
            R_X86_64_NONE => Ok(RelocationValueKind::None),
            R_X86_64_64 => Ok(RelocationValueKind::Address(Absolute)),
            R_X86_64_32 => Ok(RelocationValueKind::Word32(Absolute)),
            R_X86_64_32S => Ok(RelocationValueKind::SWord32(Absolute)),
            R_X86_64_PC32 | R_X86_64_PLT32 | R_X86_64_GOTPCREL => {
                Ok(RelocationValueKind::SWord32(RelativeToPlace))
            }
            _ => Err(RelocationError::UnsupportedRelocationType),
        }
    }
}

/// Map x86_64 relocation type value to human readable name.
///
/// This function converts numeric relocation type constants to their
/// corresponding string names for debugging and error reporting purposes.
///
/// # Arguments
/// * `r_type` - The numeric relocation type value
///
/// # Returns
/// A static string containing the relocation type name, or "UNKNOWN" for unrecognized types.
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_X86_64_NONE => "R_X86_64_NONE",
        R_X86_64_64 => "R_X86_64_64",
        R_X86_64_PC32 => "R_X86_64_PC32",
        R_X86_64_GOT32 => "R_X86_64_GOT32",
        R_X86_64_PLT32 => "R_X86_64_PLT32",
        R_X86_64_COPY => "R_X86_64_COPY",
        R_X86_64_GLOB_DAT => "R_X86_64_GLOB_DAT",
        R_X86_64_JUMP_SLOT => "R_X86_64_JUMP_SLOT",
        R_X86_64_RELATIVE => "R_X86_64_RELATIVE",
        R_X86_64_GOTPCREL => "R_X86_64_GOTPCREL",
        R_X86_64_32 => "R_X86_64_32",
        R_X86_64_32S => "R_X86_64_32S",
        R_X86_64_IRELATIVE => "R_X86_64_IRELATIVE",
        R_X86_64_TPOFF64 => "R_X86_64_TPOFF64",
        R_X86_64_TLSDESC => "R_X86_64_TLSDESC",
        R_X86_64_DTPMOD64 => "R_X86_64_DTPMOD64",
        R_X86_64_DTPOFF64 => "R_X86_64_DTPOFF64",
        _ => "UNKNOWN",
    }
}
