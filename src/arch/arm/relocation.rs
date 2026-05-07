//! 32-bit ARM ELF relocation numbering.

use elf::abi::*;

use crate::elf::{ElfMachine, ElfRelocationType};
use crate::relocation::RelocationArch;

// Place all architecture-specific trait impls on the single `ArmArch` ZST
// below. See `aarch64/relocation.rs` for the full rationale.

/// ARM (32-bit) architecture marker.
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub struct ArmArch;

impl RelocationArch for ArmArch {
    const MACHINE: ElfMachine = ElfMachine::new(super::EM_ARCH);

    const NONE: ElfRelocationType = ElfRelocationType::new(0);
    const RELATIVE: ElfRelocationType = ElfRelocationType::new(R_ARM_RELATIVE);
    const GOT: ElfRelocationType = ElfRelocationType::new(R_ARM_GLOB_DAT);
    const SYMBOLIC: ElfRelocationType = ElfRelocationType::new(R_ARM_ABS32);
    const JUMP_SLOT: ElfRelocationType = ElfRelocationType::new(R_ARM_JUMP_SLOT);
    const IRELATIVE: ElfRelocationType = ElfRelocationType::new(R_ARM_IRELATIVE);
    const COPY: ElfRelocationType = ElfRelocationType::new(R_ARM_COPY);

    const DTPMOD: ElfRelocationType = ElfRelocationType::new(R_ARM_TLS_DTPMOD32);
    const DTPOFF: ElfRelocationType = ElfRelocationType::new(R_ARM_TLS_DTPOFF32);
    const TPOFF: ElfRelocationType = ElfRelocationType::new(R_ARM_TLS_TPOFF32);
    // 32-bit ARM does not define a TLSDESC relocation.
    const TLSDESC: Option<ElfRelocationType> = None;

    // `true` only when this ZST is the host's relocation backend.
    const SUPPORTS_NATIVE_RUNTIME: bool = cfg!(target_arch = "arm");

    #[inline]
    fn rel_type_to_str(r_type: ElfRelocationType) -> &'static str {
        match r_type.raw() {
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
}

impl crate::relocation::RelocationValueProvider for ArmArch {}
impl crate::linker::GotPltTarget for ArmArch {}
