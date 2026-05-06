use crate::{
    arch,
    elf::{ElfMachine, ElfRelocationType},
};

/// Architecture-specific dynamic relocation numbering.
///
/// This trait describes the relocation type numbers for one ELF target
/// architecture without changing the in-memory relocation entry representation.
/// The native relocation path uses [`NativeRelocationArch`]; cross-architecture
/// callers may provide their own zero-sized implementation and call
/// [`crate::relocation::Relocator::relocate_with_arch`].
pub trait RelocationArch {
    /// ELF machine value accepted by this relocation backend.
    const MACHINE: ElfMachine;

    const NONE: ElfRelocationType;
    const RELATIVE: ElfRelocationType;
    const GOT: ElfRelocationType;
    const SYMBOLIC: ElfRelocationType;
    const JUMP_SLOT: ElfRelocationType;
    const IRELATIVE: ElfRelocationType;
    const COPY: ElfRelocationType;

    const DTPMOD: ElfRelocationType;
    const DTPOFF: ElfRelocationType;
    const TPOFF: ElfRelocationType;
    const TLSDESC: Option<ElfRelocationType> = None;

    /// Whether this backend may execute target code or install target runtime
    /// hooks in the host process.
    ///
    /// Native relocation enables this so IFUNC resolvers, TLS resolver stubs,
    /// lazy binding trampolines, and init arrays keep their current behavior.
    /// Cross-architecture backends should normally leave this as `false`.
    const SUPPORTS_NATIVE_RUNTIME: bool = false;

    #[inline]
    fn is_none(r_type: ElfRelocationType) -> bool {
        r_type == Self::NONE
    }

    #[inline]
    fn is_relative(r_type: ElfRelocationType) -> bool {
        r_type == Self::RELATIVE
    }

    #[inline]
    fn is_irelative(r_type: ElfRelocationType) -> bool {
        r_type == Self::IRELATIVE
    }

    #[inline]
    fn is_tlsdesc(r_type: ElfRelocationType) -> bool {
        Self::TLSDESC.is_some_and(|tlsdesc| r_type == tlsdesc)
    }

    #[inline]
    fn is_tls(r_type: ElfRelocationType) -> bool {
        r_type == Self::DTPMOD
            || r_type == Self::DTPOFF
            || r_type == Self::TPOFF
            || Self::is_tlsdesc(r_type)
    }

    #[inline]
    fn rel_type_to_str(_r_type: ElfRelocationType) -> &'static str {
        "UNKNOWN"
    }
}

/// Relocation numbering for the current compilation target.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeRelocationArch;

impl RelocationArch for NativeRelocationArch {
    const MACHINE: ElfMachine = ElfMachine::new(arch::EM_ARCH);

    const NONE: ElfRelocationType = ElfRelocationType::new(arch::REL_NONE);
    const RELATIVE: ElfRelocationType = ElfRelocationType::new(arch::REL_RELATIVE);
    const GOT: ElfRelocationType = ElfRelocationType::new(arch::REL_GOT);
    const SYMBOLIC: ElfRelocationType = ElfRelocationType::new(arch::REL_SYMBOLIC);
    const JUMP_SLOT: ElfRelocationType = ElfRelocationType::new(arch::REL_JUMP_SLOT);
    const IRELATIVE: ElfRelocationType = ElfRelocationType::new(arch::REL_IRELATIVE);
    const COPY: ElfRelocationType = ElfRelocationType::new(arch::REL_COPY);

    const DTPMOD: ElfRelocationType = ElfRelocationType::new(arch::REL_DTPMOD);
    const DTPOFF: ElfRelocationType = ElfRelocationType::new(arch::REL_DTPOFF);
    const TPOFF: ElfRelocationType = ElfRelocationType::new(arch::REL_TPOFF);
    const TLSDESC: Option<ElfRelocationType> = if arch::REL_TLSDESC == arch::REL_NONE {
        None
    } else {
        Some(ElfRelocationType::new(arch::REL_TLSDESC))
    };

    const SUPPORTS_NATIVE_RUNTIME: bool = true;

    #[inline]
    fn rel_type_to_str(r_type: ElfRelocationType) -> &'static str {
        arch::rel_type_to_str(r_type.raw() as usize)
    }
}
