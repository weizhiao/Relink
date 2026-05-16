//! x86-64 ELF relocation numbering and architecture-specific trait impls.
//!
//! [`X86_64Arch`] is the single ZST that carries every architecture-specific
//! trait for x86-64 ([`crate::relocation::RelocationArch`],
//! [`crate::relocation::RelocationValueProvider`],
//! [`crate::linker::GotPltTarget`]). It is used both as the cross-arch
//! backend (when some other host drives x86-64 relocation) and, via the
//! `crate::arch::NativeArch` re-export, as the host's relocation backend when
//! this crate is compiled for x86-64.
//!
//! Numeric relocation numbers come straight from `elf::abi::*` so this module
//! is the single source of truth and there is no separate layer of `REL_*`
//! re-aliases to keep in sync.

use core::mem::size_of;
use elf::abi::*;

use crate::arch::ArchKind;
use crate::elf::{Elf64Layout, ElfMachine, ElfRela, ElfRelocationType};
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
    const IRELATIVE: ElfRelocationType = ElfRelocationType::new(R_X86_64_IRELATIVE);
    const COPY: ElfRelocationType = ElfRelocationType::new(R_X86_64_COPY);

    const DTPMOD: ElfRelocationType = ElfRelocationType::new(R_X86_64_DTPMOD64);
    const DTPOFF: ElfRelocationType = ElfRelocationType::new(R_X86_64_DTPOFF64);
    const TPOFF: ElfRelocationType = ElfRelocationType::new(R_X86_64_TPOFF64);
    const TLSDESC: Option<ElfRelocationType> = Some(ElfRelocationType::new(R_X86_64_TLSDESC));

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

    #[cfg(feature = "object")]
    #[doc(hidden)]
    #[allow(private_interfaces)]
    fn relocate_object<D, PreH, PostH>(
        helper: &mut crate::relocation::RelocHelper<'_, D, Self, PreH, PostH>,
        rel: &crate::elf::ElfRelType<Self>,
        pltgot: &mut crate::object::layout::PltGotSection,
    ) -> Result<()>
    where
        D: 'static,
        PreH: crate::relocation::RelocationHandler<Self> + ?Sized,
        PostH: crate::relocation::RelocationHandler<Self> + ?Sized,
    {
        Self::relocate_object_impl(helper, rel, pltgot)
    }

    #[cfg(feature = "object")]
    #[doc(hidden)]
    #[inline]
    fn object_needs_got(r_type: ElfRelocationType) -> bool {
        Self::object_needs_got_impl(r_type)
    }

    #[cfg(feature = "object")]
    #[doc(hidden)]
    #[inline]
    fn object_needs_plt(r_type: ElfRelocationType) -> bool {
        Self::object_needs_plt_impl(r_type)
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

impl crate::linker::GotPltTarget for X86_64Arch {
    fn got_plt_target(
        target_bytes: &[u8],
        relocation_type: ElfRelocationType,
        symbol_is_undef: bool,
        section_offset: usize,
        source_place: usize,
        addend: isize,
    ) -> Result<Option<usize>> {
        match relocation_type.raw() {
            // These relocation types target an already-created GOT/PLT slot. For
            // undefined symbols, st_value is zero until the dynamic relocation pass
            // fills that slot, so recover the slot address from the original
            // encoded displacement.
            R_X86_64_GOTPCREL => {}
            R_X86_64_PLT32 if symbol_is_undef => {}
            _ => return Ok(None),
        }

        let end = section_offset
            .checked_add(size_of::<i32>())
            .ok_or_else(|| {
                LinkerError::metadata_rewrite("retained relocation read range overflowed")
            })?;
        let bytes = target_bytes.get(section_offset..end).ok_or_else(|| {
            LinkerError::metadata_rewrite("retained relocation read range exceeds section")
        })?;

        let mut encoded = [0u8; size_of::<i32>()];
        encoded.copy_from_slice(bytes);
        let displacement = i32::from_ne_bytes(encoded) as i128;
        let target = source_place as i128 + displacement - addend as i128;
        usize::try_from(target).map(Some).map_err(|_| {
            LinkerError::metadata_rewrite("retained relocation encoded target is out of range")
                .into()
        })
    }
}
