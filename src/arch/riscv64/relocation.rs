//! RISC-V 64-bit ELF relocation numbering.

use elf::abi::*;

use crate::Result;
use crate::arch::{ArchKind, riscv};
use crate::elf::{Elf64Layout, ElfMachine, ElfRela, ElfRelocationType};
use crate::lazy::defs::LazyBindingSlots;
use crate::relocation::RelocationArch;

const EF_RISCV_RV64ILP32: u32 = 0x0020;

/// RISC-V 64-bit architecture marker.
#[derive(Debug, Clone, Copy, Default)]
pub struct RiscV64Arch;

impl RelocationArch for RiscV64Arch {
    const KIND: ArchKind = ArchKind::RiscV64;
    const MACHINE: ElfMachine = ElfMachine::new(EM_RISCV);
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
    const TLS_DTV_OFFSET: usize = 0x800;
    const LAZY_BINDING_SLOTS: LazyBindingSlots = LazyBindingSlots::new(1, 0);

    // `true` only when this ZST is the host's relocation backend.
    const SUPPORTS_NATIVE_RUNTIME: bool = cfg!(target_arch = "riscv64");

    #[inline]
    fn validate_e_flags(flags: u32) -> Result<()> {
        if flags & EF_RISCV_RVE != 0 {
            return riscv::invalid_flags(Self::MACHINE, flags, "RVE ABI is not supported");
        }
        if flags & EF_RISCV_RV64ILP32 != 0 {
            return riscv::invalid_flags(Self::MACHINE, flags, "RV64ILP32 ABI is not supported");
        }
        if Self::SUPPORTS_NATIVE_RUNTIME {
            riscv::validate_native_float_abi(Self::MACHINE, flags)?;
        }
        Ok(())
    }

    #[inline]
    fn rel_type_to_str(r_type: ElfRelocationType) -> &'static str {
        match r_type.raw() {
            R_RISCV_NONE => "R_RISCV_NONE",
            R_RISCV_32 => "R_RISCV_32",
            R_RISCV_64 => "R_RISCV_64",
            R_RISCV_RELATIVE => "R_RISCV_RELATIVE",
            R_RISCV_COPY => "R_RISCV_COPY",
            R_RISCV_JUMP_SLOT => "R_RISCV_JUMP_SLOT",
            R_RISCV_IRELATIVE => "R_RISCV_IRELATIVE",
            R_RISCV_BRANCH => "R_RISCV_BRANCH",
            R_RISCV_JAL => "R_RISCV_JAL",
            R_RISCV_CALL => "R_RISCV_CALL",
            R_RISCV_CALL_PLT => "R_RISCV_CALL_PLT",
            R_RISCV_GOT_HI20 => "R_RISCV_GOT_HI20",
            R_RISCV_PCREL_HI20 => "R_RISCV_PCREL_HI20",
            R_RISCV_PCREL_LO12_I => "R_RISCV_PCREL_LO12_I",
            R_RISCV_PCREL_LO12_S => "R_RISCV_PCREL_LO12_S",
            R_RISCV_HI20 => "R_RISCV_HI20",
            R_RISCV_LO12_I => "R_RISCV_LO12_I",
            R_RISCV_LO12_S => "R_RISCV_LO12_S",
            R_RISCV_ADD8 => "R_RISCV_ADD8",
            R_RISCV_ADD16 => "R_RISCV_ADD16",
            R_RISCV_ADD32 => "R_RISCV_ADD32",
            R_RISCV_ADD64 => "R_RISCV_ADD64",
            R_RISCV_SUB8 => "R_RISCV_SUB8",
            R_RISCV_SUB16 => "R_RISCV_SUB16",
            R_RISCV_SUB32 => "R_RISCV_SUB32",
            R_RISCV_SUB64 => "R_RISCV_SUB64",
            R_RISCV_SUB6 => "R_RISCV_SUB6",
            R_RISCV_SET6 => "R_RISCV_SET6",
            R_RISCV_SET8 => "R_RISCV_SET8",
            R_RISCV_SET16 => "R_RISCV_SET16",
            R_RISCV_SET32 => "R_RISCV_SET32",
            R_RISCV_32_PCREL => "R_RISCV_32_PCREL",
            R_RISCV_RVC_BRANCH => "R_RISCV_RVC_BRANCH",
            R_RISCV_RVC_JUMP => "R_RISCV_RVC_JUMP",
            _ => "UNKNOWN",
        }
    }
}

impl crate::relocation::RelocationValueProvider for RiscV64Arch {}
impl crate::linker::scan::GotPltTarget for RiscV64Arch {}
