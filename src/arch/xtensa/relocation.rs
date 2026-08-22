//! Xtensa ELF relocation numbering.

use elf::abi::EM_XTENSA;

use crate::{
    LazyBindingError, RelocationError, Result,
    arch::ArchKind,
    elf::{Elf32Layout, ElfLayout, ElfMachine, ElfRelEntry, ElfRela, ElfRelocationType, ElfWord},
    lazy::LazyPlacement,
    linker::scan::GotPltTarget,
    memory::{ImageMemory, ImageMemoryExt, RegionAccess},
    relocation::{HandleResult, RelocationArch, RelocationEvent, RelocationValueProvider},
    tls::TlsResolver,
};

const R_XTENSA_NONE: u32 = 0;
const R_XTENSA_32: u32 = 1;
const R_XTENSA_RTLD: u32 = 2;
const R_XTENSA_GLOB_DAT: u32 = 3;
const R_XTENSA_JMP_SLOT: u32 = 4;
const R_XTENSA_RELATIVE: u32 = 5;
const R_XTENSA_PLT: u32 = 6;
const R_XTENSA_TLSDESC_FN: u32 = 50;
const R_XTENSA_TLSDESC_ARG: u32 = 51;
const R_XTENSA_TLS_DTPOFF: u32 = 52;
const R_XTENSA_TLS_TPOFF: u32 = 53;
const R_XTENSA_TLS_FUNC: u32 = 54;
const R_XTENSA_TLS_ARG: u32 = 55;
const R_XTENSA_TLS_CALL: u32 = 56;

/// Xtensa 32-bit architecture marker.
///
/// The current backend supports little-endian ELF32 images and eager dynamic
/// relocation, including `TLS_DTPOFF` and `TLS_TPOFF` through a custom TLS
/// resolver. Lazy binding is available through a custom binder; split TLSDESC
/// relocations, object relocation, and same-process native runtime hooks are
/// not yet supported.
#[derive(Debug, Clone, Copy, Default)]
pub struct XtensaArch;

impl RelocationArch for XtensaArch {
    const KIND: ArchKind = ArchKind::Xtensa;
    const MACHINE: ElfMachine = ElfMachine::new(EM_XTENSA);
    type Layout = Elf32Layout;
    type Relocation = ElfRela<Self::Layout>;

    const NONE: ElfRelocationType = ElfRelocationType::new(R_XTENSA_NONE);
    const RELATIVE: ElfRelocationType = ElfRelocationType::new(R_XTENSA_RELATIVE);
    const GOT: ElfRelocationType = ElfRelocationType::new(R_XTENSA_GLOB_DAT);
    const SYMBOLIC: ElfRelocationType = ElfRelocationType::new(R_XTENSA_32);
    const JUMP_SLOT: ElfRelocationType = ElfRelocationType::new(R_XTENSA_JMP_SLOT);
    const IRELATIVE: Option<ElfRelocationType> = None;
    const COPY: Option<ElfRelocationType> = None;

    const DTPMOD: Option<ElfRelocationType> = None;
    const DTPOFF: ElfRelocationType = ElfRelocationType::new(R_XTENSA_TLS_DTPOFF);
    const TPOFF: ElfRelocationType = ElfRelocationType::new(R_XTENSA_TLS_TPOFF);
    const LAZY_BINDING: LazyPlacement = LazyPlacement::Custom;

    #[inline]
    fn apply_relative<Memory>(rel: &Self::Relocation, memory: &Memory) -> Result<()>
    where
        Memory: ImageMemory,
    {
        let base = memory.base();
        let place = base + rel.r_offset();
        let addend =
            unsafe { memory.read_value::<<Self::Layout as ElfLayout>::Word>(place)? }.to_usize();
        let word = <Self::Layout as ElfLayout>::Word::from_usize(base.get().wrapping_add(addend));
        unsafe { memory.write_value(place, word) }
    }

    #[inline]
    fn relocate_custom<D, R, Tls, H>(
        event: &mut RelocationEvent<'_, D, Self, R, Tls, H>,
    ) -> Result<HandleResult>
    where
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<Self>,
    {
        let rel = event.rel();
        if rel.r_type().raw() != R_XTENSA_RTLD {
            return Ok(HandleResult::Unhandled);
        }

        let place = event.lib().base() + rel.r_offset();
        let addend = rel.read_addend(event.lib().segments(), place)?;
        let value = match addend {
            1 => event.lazy().map(|lazy| lazy.resolver()),
            2 => event.lazy().map(|lazy| lazy.context()),
            _ => {
                return Err(RelocationError::LazyBinding(LazyBindingError::Unsupported).into());
            }
        };

        // Eager binding overwrites every JUMP_SLOT, so these runtime entries
        // are only needed when a lazy binder is active.
        if let Some(value) = value {
            let word = <Self::Layout as ElfLayout>::Word::from_usize(value.get());
            unsafe { event.lib().segments().write_value(place, word)? };
        }
        Ok(HandleResult::Handled)
    }

    #[inline]
    fn rel_type_to_str(r_type: ElfRelocationType) -> &'static str {
        match r_type.raw() {
            R_XTENSA_NONE => "R_XTENSA_NONE",
            R_XTENSA_32 => "R_XTENSA_32",
            R_XTENSA_RTLD => "R_XTENSA_RTLD",
            R_XTENSA_GLOB_DAT => "R_XTENSA_GLOB_DAT",
            R_XTENSA_JMP_SLOT => "R_XTENSA_JMP_SLOT",
            R_XTENSA_RELATIVE => "R_XTENSA_RELATIVE",
            R_XTENSA_PLT => "R_XTENSA_PLT",
            R_XTENSA_TLSDESC_FN => "R_XTENSA_TLSDESC_FN",
            R_XTENSA_TLSDESC_ARG => "R_XTENSA_TLSDESC_ARG",
            R_XTENSA_TLS_DTPOFF => "R_XTENSA_TLS_DTPOFF",
            R_XTENSA_TLS_TPOFF => "R_XTENSA_TLS_TPOFF",
            R_XTENSA_TLS_FUNC => "R_XTENSA_TLS_FUNC",
            R_XTENSA_TLS_ARG => "R_XTENSA_TLS_ARG",
            R_XTENSA_TLS_CALL => "R_XTENSA_TLS_CALL",
            _ => "UNKNOWN",
        }
    }
}

impl RelocationValueProvider for XtensaArch {}
impl GotPltTarget for XtensaArch {}
