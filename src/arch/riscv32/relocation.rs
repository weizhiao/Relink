//! RISC-V 32-bit ELF relocation numbering.

use elf::abi::*;

use crate::arch::ArchKind;
use crate::elf::{Elf32Layout, ElfMachine, ElfRela, ElfRelocationType};
use crate::relocation::RelocationArch;

/// RISC-V 32-bit architecture marker.
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub struct RiscV32Arch;

impl RelocationArch for RiscV32Arch {
    const KIND: ArchKind = ArchKind::RiscV32;
    const MACHINE: ElfMachine = ElfMachine::new(super::EM_ARCH);
    type Layout = Elf32Layout;
    type Relocation = ElfRela<Self::Layout>;

    const NONE: ElfRelocationType = ElfRelocationType::new(0);
    const RELATIVE: ElfRelocationType = ElfRelocationType::new(R_RISCV_RELATIVE);
    const GOT: ElfRelocationType = ElfRelocationType::new(R_RISCV_32);
    const SYMBOLIC: ElfRelocationType = ElfRelocationType::new(R_RISCV_32);
    const JUMP_SLOT: ElfRelocationType = ElfRelocationType::new(R_RISCV_JUMP_SLOT);
    const IRELATIVE: ElfRelocationType = ElfRelocationType::new(R_RISCV_IRELATIVE);
    const COPY: ElfRelocationType = ElfRelocationType::new(R_RISCV_COPY);

    const DTPMOD: ElfRelocationType = ElfRelocationType::new(R_RISCV_TLS_DTPMOD32);
    const DTPOFF: ElfRelocationType = ElfRelocationType::new(R_RISCV_TLS_DTPREL32);
    const TPOFF: ElfRelocationType = ElfRelocationType::new(R_RISCV_TLS_TPREL32);
    // RISC-V does not define a TLSDESC relocation.
    const TLSDESC: Option<ElfRelocationType> = None;

    // `true` only when this ZST is the host's relocation backend.
    const SUPPORTS_NATIVE_RUNTIME: bool = cfg!(target_arch = "riscv32");

    #[inline]
    fn rel_type_to_str(r_type: ElfRelocationType) -> &'static str {
        match r_type.raw() {
            R_RISCV_NONE => "R_RISCV_NONE",
            R_RISCV_32 => "R_RISCV_32",
            R_RISCV_RELATIVE => "R_RISCV_RELATIVE",
            R_RISCV_COPY => "R_RISCV_COPY",
            R_RISCV_JUMP_SLOT => "R_RISCV_JUMP_SLOT",
            R_RISCV_IRELATIVE => "R_RISCV_IRELATIVE",
            _ => "UNKNOWN",
        }
    }
}

impl crate::relocation::RelocationValueProvider for RiscV32Arch {}
impl crate::linker::GotPltTarget for RiscV32Arch {}
