//! LoongArch 64-bit ELF relocation numbering.

use crate::arch::ArchKind;
use crate::elf::{Elf64Layout, ElfMachine, ElfRela, ElfRelocationType};
use crate::relocation::RelocationArch;

// LoongArch relocation numbers are defined locally in `arch/loongarch64/mod.rs`
// because the elf crate does not always publish them.
use super::{
    R_LARCH_64, R_LARCH_COPY, R_LARCH_IRELATIVE, R_LARCH_JUMP_SLOT, R_LARCH_RELATIVE,
    R_LARCH_TLS_DTPMOD64, R_LARCH_TLS_DTPREL64, R_LARCH_TLS_TPREL64,
};

/// LoongArch 64-bit architecture marker.
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub struct LoongArch64Arch;

impl RelocationArch for LoongArch64Arch {
    const KIND: ArchKind = ArchKind::LoongArch64;
    const MACHINE: ElfMachine = ElfMachine::new(super::EM_ARCH);
    type Layout = Elf64Layout;
    type Relocation = ElfRela<Self::Layout>;

    const NONE: ElfRelocationType = ElfRelocationType::new(0);
    const RELATIVE: ElfRelocationType = ElfRelocationType::new(R_LARCH_RELATIVE);
    const GOT: ElfRelocationType = ElfRelocationType::new(R_LARCH_64);
    const SYMBOLIC: ElfRelocationType = ElfRelocationType::new(R_LARCH_64);
    const JUMP_SLOT: ElfRelocationType = ElfRelocationType::new(R_LARCH_JUMP_SLOT);
    const IRELATIVE: ElfRelocationType = ElfRelocationType::new(R_LARCH_IRELATIVE);
    const COPY: ElfRelocationType = ElfRelocationType::new(R_LARCH_COPY);

    const DTPMOD: ElfRelocationType = ElfRelocationType::new(R_LARCH_TLS_DTPMOD64);
    const DTPOFF: ElfRelocationType = ElfRelocationType::new(R_LARCH_TLS_DTPREL64);
    const TPOFF: ElfRelocationType = ElfRelocationType::new(R_LARCH_TLS_TPREL64);
    // LoongArch 64-bit does not define a TLSDESC relocation.
    const TLSDESC: Option<ElfRelocationType> = None;

    // `true` only when this ZST is the host's relocation backend.
    const SUPPORTS_NATIVE_RUNTIME: bool = cfg!(target_arch = "loongarch64");

    #[inline]
    fn rel_type_to_str(r_type: ElfRelocationType) -> &'static str {
        match r_type.raw() {
            R_LARCH_64 => "R_LARCH_64",
            R_LARCH_RELATIVE => "R_LARCH_RELATIVE",
            R_LARCH_COPY => "R_LARCH_COPY",
            R_LARCH_JUMP_SLOT => "R_LARCH_JUMP_SLOT",
            R_LARCH_TLS_DTPMOD64 => "R_LARCH_TLS_DTPMOD64",
            R_LARCH_TLS_DTPREL64 => "R_LARCH_TLS_DTPREL64",
            R_LARCH_IRELATIVE => "R_LARCH_IRELATIVE",
            _ => "UNKNOWN",
        }
    }
}

impl crate::relocation::RelocationValueProvider for LoongArch64Arch {}
impl crate::linker::GotPltTarget for LoongArch64Arch {}
