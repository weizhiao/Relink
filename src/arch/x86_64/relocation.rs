//! x86-64 ELF relocation support.

// `X86_64Arch` carries the architecture-specific trait impls for both native
// and cross-architecture relocation. Numeric relocation values come from
// `elf::abi::*`; avoid adding a separate local alias layer to keep in sync.

use core::mem::size_of;
use elf::abi::*;

use crate::arch::ArchKind;
use crate::elf::{Elf64Layout, ElfMachine, ElfRela, ElfRelocationType};
use crate::lazy::LazyPlacement;
use crate::linker::scan::{PltArch, SectionMetadata};
use crate::relocation::{
    RelocationArch, RelocationValueFormula, RelocationValueKind, RelocationValueProvider,
};
use crate::{LinkerError, RelocReason, Result};

/// x86-64 (AMD64) architecture marker.
#[derive(Debug, Clone, Copy, Default)]
pub struct X86_64Arch;

impl RelocationArch for X86_64Arch {
    const KIND: ArchKind = ArchKind::X86_64;
    const MACHINE: ElfMachine = ElfMachine::new(EM_X86_64);
    type Layout = Elf64Layout;
    type Relocation = ElfRela<Self::Layout>;

    const NONE: ElfRelocationType = ElfRelocationType::new(0);
    const RELATIVE: ElfRelocationType = ElfRelocationType::new(R_X86_64_RELATIVE);
    const GOT: ElfRelocationType = ElfRelocationType::new(R_X86_64_GLOB_DAT);
    const SYMBOLIC: ElfRelocationType = ElfRelocationType::new(R_X86_64_64);
    const JUMP_SLOT: ElfRelocationType = ElfRelocationType::new(R_X86_64_JUMP_SLOT);
    const IRELATIVE: Option<ElfRelocationType> = Some(ElfRelocationType::new(R_X86_64_IRELATIVE));
    const COPY: Option<ElfRelocationType> = Some(ElfRelocationType::new(R_X86_64_COPY));

    const DTPMOD: Option<ElfRelocationType> = Some(ElfRelocationType::new(R_X86_64_DTPMOD64));
    const DTPOFF: ElfRelocationType = ElfRelocationType::new(R_X86_64_DTPOFF64);
    const TPOFF: ElfRelocationType = ElfRelocationType::new(R_X86_64_TPOFF64);
    const TLSDESC: Option<ElfRelocationType> = Some(ElfRelocationType::new(R_X86_64_TLSDESC));
    const LAZY_BINDING: LazyPlacement = LazyPlacement::Slots {
        context: 1,
        resolver: 2,
    };

    // `true` only when this ZST is the host's relocation backend (i.e. the
    // crate is compiled for x86_64). When used as a cross-arch backend on
    // some other host, host runtime hooks (IFUNC resolvers, TLSDESC
    // resolver stubs, lazy-binding trampolines, init arrays) are not
    // physically executable here, so this stays `false`.
    const SUPPORTS_NATIVE_RUNTIME: bool = cfg!(target_arch = "x86_64");
    const SUPPORTS_SECTION_REORDER: bool = true;

    #[inline]
    fn rel_type_to_str(r_type: ElfRelocationType) -> &'static str {
        match r_type.raw() {
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
}

impl RelocationValueProvider for X86_64Arch {
    fn relocation_value_kind(
        relocation_type: usize,
    ) -> core::result::Result<RelocationValueKind, RelocReason> {
        use RelocationValueFormula::{Absolute, RelativeToPlace};
        match relocation_type as u32 {
            R_X86_64_NONE => Ok(RelocationValueKind::None),
            R_X86_64_64 => Ok(RelocationValueKind::Address(Absolute)),
            R_X86_64_32 => Ok(RelocationValueKind::Word32(Absolute)),
            R_X86_64_32S => Ok(RelocationValueKind::SWord32(Absolute)),
            R_X86_64_PC32 | R_X86_64_PLT32 | R_X86_64_GOTPCREL => {
                Ok(RelocationValueKind::SWord32(RelativeToPlace))
            }
            _ => Err(RelocReason::Unsupported),
        }
    }
}

impl PltArch for X86_64Arch {
    fn visit_plt_displacements(
        section: &SectionMetadata,
        bytes: &[u8],
        visit: impl FnMut(usize, i32) -> Result<()>,
    ) -> Result<()> {
        super::plt::visit_displacements(section.name(), section.entry_size, bytes, visit)
    }

    fn got_plt_target(
        relocation_type: ElfRelocationType,
        source_place: usize,
        addend: isize,
        read_site: impl FnOnce(&mut [u8]) -> Result<()>,
    ) -> Result<Option<usize>> {
        // PLT32 may name a defined, preemptible symbol. Preserve the target
        // chosen by the static linker, including calls routed through its PLT.
        if !matches!(relocation_type.raw(), R_X86_64_PLT32 | R_X86_64_GOTPCREL) {
            return Ok(None);
        }

        let mut encoded = [0u8; size_of::<i32>()];
        read_site(&mut encoded)?;
        let displacement = i128::from(i32::from_le_bytes(encoded));
        let target = source_place as i128 + displacement - addend as i128;
        usize::try_from(target).map(Some).map_err(|_| {
            LinkerError::metadata_rewrite("retained relocation encoded target is out of range")
                .into()
        })
    }
}
