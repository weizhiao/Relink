//! x86 (32-bit / i386) ELF relocation numbering.

use crate::arch::ArchKind;
use crate::elf::{Elf32Layout, ElfMachine, ElfRel, ElfRelocationType};
use crate::relocation::RelocationArch;

// The constants below come from `super` because the elf crate does not always
// publish the i386 relocation numbers; they are defined locally in
// `arch/x86/mod.rs`.
use super::{
    R_386_32, R_386_COPY, R_386_GLOB_DAT, R_386_IRELATIVE, R_386_JMP_SLOT, R_386_RELATIVE,
    R_386_TLS_DTPMOD32, R_386_TLS_DTPOFF32, R_386_TLS_TPOFF,
};

/// x86 (i386, 32-bit) architecture marker.
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub struct X86Arch;

impl RelocationArch for X86Arch {
    const KIND: ArchKind = ArchKind::X86;
    const MACHINE: ElfMachine = ElfMachine::new(super::EM_ARCH);
    type Layout = Elf32Layout;
    type Relocation = ElfRel<Self::Layout>;

    const NONE: ElfRelocationType = ElfRelocationType::new(0);
    const RELATIVE: ElfRelocationType = ElfRelocationType::new(R_386_RELATIVE);
    const GOT: ElfRelocationType = ElfRelocationType::new(R_386_GLOB_DAT);
    const SYMBOLIC: ElfRelocationType = ElfRelocationType::new(R_386_32);
    const JUMP_SLOT: ElfRelocationType = ElfRelocationType::new(R_386_JMP_SLOT);
    const IRELATIVE: ElfRelocationType = ElfRelocationType::new(R_386_IRELATIVE);
    const COPY: ElfRelocationType = ElfRelocationType::new(R_386_COPY);

    const DTPMOD: ElfRelocationType = ElfRelocationType::new(R_386_TLS_DTPMOD32);
    const DTPOFF: ElfRelocationType = ElfRelocationType::new(R_386_TLS_DTPOFF32);
    const TPOFF: ElfRelocationType = ElfRelocationType::new(R_386_TLS_TPOFF);
    // x86 (32-bit) does not define a TLSDESC relocation.
    const TLSDESC: Option<ElfRelocationType> = None;

    // `true` only when this ZST is the host's relocation backend.
    const SUPPORTS_NATIVE_RUNTIME: bool = cfg!(target_arch = "x86");

    #[inline]
    fn rel_type_to_str(r_type: ElfRelocationType) -> &'static str {
        match r_type.raw() {
            R_386_32 => "R_386_32",
            R_386_GLOB_DAT => "R_386_GLOB_DAT",
            R_386_COPY => "R_386_COPY",
            R_386_JMP_SLOT => "R_386_JMP_SLOT",
            R_386_RELATIVE => "R_386_RELATIVE",
            R_386_TLS_DTPMOD32 => "R_386_TLS_DTPMOD32",
            R_386_TLS_DTPOFF32 => "R_386_TLS_DTPOFF32",
            R_386_IRELATIVE => "R_386_IRELATIVE",
            R_386_TLS_TPOFF => "R_386_TLS_TPOFF",
            _ => "UNKNOWN",
        }
    }
}

impl crate::relocation::RelocationValueProvider for X86Arch {}
impl crate::linker::GotPltTarget for X86Arch {}
