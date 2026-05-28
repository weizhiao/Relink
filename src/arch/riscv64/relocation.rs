//! RISC-V 64-bit ELF relocation numbering.

use elf::abi::*;

use crate::arch::ArchKind;
#[cfg(feature = "object")]
use crate::arch::object::ObjectRelocationArch;
use crate::elf::{Elf64Layout, ElfMachine, ElfRela, ElfRelocationType};
use crate::relocation::RelocationArch;
#[cfg(feature = "object")]
use crate::{Result, os::HostRegion};

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

    // `true` only when this ZST is the host's relocation backend.
    const SUPPORTS_NATIVE_RUNTIME: bool = cfg!(target_arch = "riscv64");

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

#[cfg(feature = "object")]
impl ObjectRelocationArch for RiscV64Arch {
    type ObjectRelocationState = super::object::RiscV64ObjectRelocationState;

    const OBJECT_RELOCATION_ALLOWS_UNALIGNED_ACCESS: bool = true;

    #[allow(private_bounds)]
    #[allow(private_interfaces)]
    fn prepare_object_relocation<D, PreH, PostH, Obs>(
        state: &mut Self::ObjectRelocationState,
        helper: &mut crate::relocation::RelocHelper<'_, D, Self, HostRegion, PreH, PostH, Obs>,
        sections: &[&'static [crate::elf::ElfRelType<Self>]],
    ) -> Result<()>
    where
        D: 'static,
        PreH: crate::relocation::RelocationHandler<Self> + ?Sized,
        PostH: crate::relocation::RelocationHandler<Self> + ?Sized,
        Obs: crate::observer::RelocationObserver<Self> + ?Sized,
    {
        Self::prepare_object_relocation_impl(state, helper, sections)
    }

    #[allow(private_bounds)]
    #[allow(private_interfaces)]
    fn relocate_object<D, PreH, PostH, Obs>(
        state: &mut Self::ObjectRelocationState,
        helper: &mut crate::relocation::RelocHelper<'_, D, Self, HostRegion, PreH, PostH, Obs>,
        rel: &crate::elf::ElfRelType<Self>,
        pltgot: &mut crate::object::layout::PltGotSection,
    ) -> Result<()>
    where
        D: 'static,
        PreH: crate::relocation::RelocationHandler<Self> + ?Sized,
        PostH: crate::relocation::RelocationHandler<Self> + ?Sized,
        Obs: crate::observer::RelocationObserver<Self> + ?Sized,
    {
        Self::relocate_object_impl(state, helper, rel, pltgot)
    }

    #[inline]
    fn object_needs_got(r_type: ElfRelocationType) -> bool {
        Self::object_needs_got_impl(r_type)
    }

    #[inline]
    fn object_needs_plt(r_type: ElfRelocationType) -> bool {
        Self::object_needs_plt_impl(r_type)
    }
}

impl crate::relocation::RelocationValueProvider for RiscV64Arch {}
impl crate::linker::scan::GotPltTarget for RiscV64Arch {}
