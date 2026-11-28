//! x86-64 ELF relocation support.

// `X86_64Arch` carries the architecture-specific trait impls for both native
// and cross-architecture relocation. Numeric relocation values come from
// `elf::abi::*`; avoid adding a separate local alias layer to keep in sync.

use elf::abi::*;

use crate::arch::ArchKind;
use crate::elf::{Elf64Layout, ElfMachine, ElfRela, ElfRelocationType};
use crate::lazy::LazyPlacement;
use crate::relocation::RelocationArch;

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
