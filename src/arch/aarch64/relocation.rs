//! AArch64 ELF relocation support.

// `AArch64Arch` carries the architecture-specific trait impls for both native
// and cross-architecture relocation.

use elf::abi::*;

use crate::arch::ArchKind;
use crate::elf::{Elf64Layout, ElfMachine, ElfRela, ElfRelocationType};
use crate::relocation::RelocationArch;

/// AArch64 (ARM64) architecture marker.
#[derive(Debug, Clone, Copy, Default)]
pub struct AArch64Arch;

impl RelocationArch for AArch64Arch {
    const KIND: ArchKind = ArchKind::AArch64;
    const MACHINE: ElfMachine = ElfMachine::new(EM_AARCH64);
    type Layout = Elf64Layout;
    type Relocation = ElfRela<Self::Layout>;

    const NONE: ElfRelocationType = ElfRelocationType::new(0);
    const RELATIVE: ElfRelocationType = ElfRelocationType::new(R_AARCH64_RELATIVE);
    const GOT: ElfRelocationType = ElfRelocationType::new(R_AARCH64_GLOB_DAT);
    const SYMBOLIC: ElfRelocationType = ElfRelocationType::new(R_AARCH64_ABS64);
    const JUMP_SLOT: ElfRelocationType = ElfRelocationType::new(R_AARCH64_JUMP_SLOT);
    const IRELATIVE: ElfRelocationType = ElfRelocationType::new(R_AARCH64_IRELATIVE);
    const COPY: ElfRelocationType = ElfRelocationType::new(R_AARCH64_COPY);

    const DTPMOD: ElfRelocationType = ElfRelocationType::new(R_AARCH64_TLS_DTPMOD);
    const DTPOFF: ElfRelocationType = ElfRelocationType::new(R_AARCH64_TLS_DTPREL);
    const TPOFF: ElfRelocationType = ElfRelocationType::new(R_AARCH64_TLS_TPREL);
    const TLSDESC: Option<ElfRelocationType> = Some(ElfRelocationType::new(R_AARCH64_TLSDESC));

    // `true` only when this ZST is the host's relocation backend.
    // Cross-arch use on a different host keeps it `false` because the
    // AArch64 IFUNC/TLSDESC/lazy-binding hooks cannot run on that host.
    const SUPPORTS_NATIVE_RUNTIME: bool = cfg!(target_arch = "aarch64");

    #[inline]
    fn rel_type_to_str(r_type: ElfRelocationType) -> &'static str {
        match r_type.raw() {
            R_AARCH64_NONE => "R_AARCH64_NONE",
            R_AARCH64_ABS64 => "R_AARCH64_ABS64",
            R_AARCH64_GLOB_DAT => "R_AARCH64_GLOB_DAT",
            R_AARCH64_RELATIVE => "R_AARCH64_RELATIVE",
            R_AARCH64_JUMP_SLOT => "R_AARCH64_JUMP_SLOT",
            R_AARCH64_IRELATIVE => "R_AARCH64_IRELATIVE",
            R_AARCH64_COPY => "R_AARCH64_COPY",
            R_AARCH64_TLS_TPREL => "R_AARCH64_TLS_TPREL",
            R_AARCH64_TLSDESC => "R_AARCH64_TLSDESC",
            _ => "UNKNOWN",
        }
    }
}

impl crate::relocation::RelocationValueProvider for AArch64Arch {}
impl crate::linker::GotPltTarget for AArch64Arch {}
