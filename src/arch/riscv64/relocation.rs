//! RISC-V 64-bit ELF relocation numbering.

use elf::abi::*;

use crate::arch::ArchKind;
use crate::elf::{Elf64Layout, ElfMachine, ElfRela, ElfRelocationType};
use crate::relocation::RelocationArch;

/// RISC-V 64-bit architecture marker.
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub struct RiscV64Arch;

impl RelocationArch for RiscV64Arch {
    const KIND: ArchKind = ArchKind::RiscV64;
    const MACHINE: ElfMachine = ElfMachine::new(super::EM_ARCH);
    type Layout = Elf64Layout;
    type Relocation = ElfRela<Self::Layout>;

    const NONE: ElfRelocationType = ElfRelocationType::new(0);
    const RELATIVE: ElfRelocationType = ElfRelocationType::new(R_RISCV_RELATIVE);
    const GOT: ElfRelocationType = ElfRelocationType::new(R_RISCV_64);
    const SYMBOLIC: ElfRelocationType = ElfRelocationType::new(R_RISCV_64);
    const JUMP_SLOT: ElfRelocationType = ElfRelocationType::new(R_RISCV_JUMP_SLOT);
    const IRELATIVE: ElfRelocationType = ElfRelocationType::new(R_RISCV_IRELATIVE);
    const COPY: ElfRelocationType = ElfRelocationType::new(R_RISCV_COPY);

    const DTPMOD: ElfRelocationType = ElfRelocationType::new(R_RISCV_TLS_DTPMOD64);
    const DTPOFF: ElfRelocationType = ElfRelocationType::new(R_RISCV_TLS_DTPREL64);
    const TPOFF: ElfRelocationType = ElfRelocationType::new(R_RISCV_TLS_TPREL64);
    // RISC-V does not define a TLSDESC relocation.
    const TLSDESC: Option<ElfRelocationType> = None;

    // `true` only when this ZST is the host's relocation backend.
    const SUPPORTS_NATIVE_RUNTIME: bool = cfg!(target_arch = "riscv64");

    #[inline]
    fn rel_type_to_str(r_type: ElfRelocationType) -> &'static str {
        match r_type.raw() {
            R_RISCV_NONE => "R_RISCV_NONE",
            R_RISCV_64 => "R_RISCV_64",
            R_RISCV_RELATIVE => "R_RISCV_RELATIVE",
            R_RISCV_COPY => "R_RISCV_COPY",
            R_RISCV_JUMP_SLOT => "R_RISCV_JUMP_SLOT",
            R_RISCV_IRELATIVE => "R_RISCV_IRELATIVE",
            _ => "UNKNOWN",
        }
    }
}

impl crate::relocation::RelocationValueProvider for RiscV64Arch {}
impl crate::linker::GotPltTarget for RiscV64Arch {}
