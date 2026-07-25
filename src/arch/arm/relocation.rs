//! 32-bit ARM ELF relocation numbering.

use elf::abi::*;

use crate::arch::ArchKind;
use crate::elf::{Elf32Layout, ElfMachine, ElfRel, ElfRelocationType};
use crate::lazy::{LazyPlacement, LazySlots};
use crate::linker::scan::GotPltTarget;
#[cfg(feature = "object")]
use crate::relocation::ObjectArch;
use crate::relocation::{RelocationArch, RelocationValueProvider};

// Place all architecture-specific trait impls on the single `ArmArch` ZST
// below. See `aarch64/relocation.rs` for the full rationale.

/// ARM (32-bit) architecture marker.
#[derive(Debug, Clone, Copy, Default)]
pub struct ArmArch;

impl RelocationArch for ArmArch {
    const KIND: ArchKind = ArchKind::Arm;
    const MACHINE: ElfMachine = ElfMachine::new(EM_ARM);
    type Layout = Elf32Layout;
    type Relocation = ElfRel<Self::Layout>;

    const NONE: ElfRelocationType = ElfRelocationType::new(0);
    const RELATIVE: ElfRelocationType = ElfRelocationType::new(R_ARM_RELATIVE);
    const GOT: ElfRelocationType = ElfRelocationType::new(R_ARM_GLOB_DAT);
    const SYMBOLIC: ElfRelocationType = ElfRelocationType::new(R_ARM_ABS32);
    const JUMP_SLOT: ElfRelocationType = ElfRelocationType::new(R_ARM_JUMP_SLOT);
    const IRELATIVE: Option<ElfRelocationType> = Some(ElfRelocationType::new(R_ARM_IRELATIVE));
    const COPY: Option<ElfRelocationType> = Some(ElfRelocationType::new(R_ARM_COPY));

    const DTPMOD: Option<ElfRelocationType> = Some(ElfRelocationType::new(R_ARM_TLS_DTPMOD32));
    const DTPOFF: ElfRelocationType = ElfRelocationType::new(R_ARM_TLS_DTPOFF32);
    const TPOFF: ElfRelocationType = ElfRelocationType::new(R_ARM_TLS_TPOFF32);
    // 32-bit ARM does not define a TLSDESC relocation.
    const TLSDESC: Option<ElfRelocationType> = None;
    const LAZY_BINDING: LazyPlacement = LazyPlacement::Slots(LazySlots::new(1, 2));

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

#[cfg(feature = "object")]
impl ObjectArch for ArmArch {
    type State = ();
}

impl RelocationValueProvider for ArmArch {}
impl GotPltTarget for ArmArch {}
