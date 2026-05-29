use crate::{
    RelocReason,
    arch::x86_64::relocation::X86_64Arch,
    elf::ElfRelType,
    object::layout::{GotEntry, PltEntry, PltGotSection},
    os::{RegionAccess, VmAddr},
    relocation::{
        RelocHelper, RelocValue, RelocationHandler, RelocationValueProvider, reloc_error,
    },
    segment::ElfSegments,
};
use elf::abi::*;

pub(crate) const PLT_ENTRY_SIZE: usize = 16;

pub(crate) const PLT_ENTRY: [u8; PLT_ENTRY_SIZE] = [
    0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25, 0, 0, 0, 0, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

enum ObjectWrite {
    None,
    Addr(VmAddr),
    Word32(RelocValue<u32>),
    SWord32(RelocValue<i32>),
}

impl X86_64Arch {
    #[inline]
    fn object_relocation_value(
        r_type: usize,
        target: usize,
        append: isize,
        place: usize,
    ) -> core::result::Result<ObjectWrite, RelocReason> {
        <Self as RelocationValueProvider>::relocation_value(
            r_type,
            target,
            append,
            place,
            |_| ObjectWrite::None,
            ObjectWrite::Addr,
            ObjectWrite::Word32,
            ObjectWrite::SWord32,
        )
    }

    #[inline]
    fn write_object_value<R: RegionAccess>(
        segments: &ElfSegments<R>,
        place: VmAddr,
        value: ObjectWrite,
    ) -> crate::Result<()> {
        unsafe {
            match value {
                ObjectWrite::None => {}
                ObjectWrite::Addr(value) => {
                    segments.write_value(place, RelocValue::new(value.get()))?
                }
                ObjectWrite::Word32(value) => segments.write_value(place, value)?,
                ObjectWrite::SWord32(value) => segments.write_value(place, value)?,
            }
        }
        Ok(())
    }

    pub(crate) fn relocate_object_impl<D, R, PreH, PostH, Obs>(
        helper: &mut RelocHelper<'_, D, Self, R, PreH, PostH, Obs, crate::object::CustomHash>,
        rel: &ElfRelType<Self>,
        pltgot: &mut PltGotSection,
    ) -> crate::Result<()>
    where
        D: 'static,
        R: RegionAccess,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: crate::observer::RelocationObserver<Self> + ?Sized,
    {
        let r_sym = rel.r_symbol();
        let r_type = rel.r_type();
        let core = helper.core;
        let segments = core.segments();
        let base = core.base();
        let append = rel.r_addend(base);
        let place = base + rel.r_offset();
        let unknown_symbol = || reloc_error(rel, crate::RelocReason::UnknownSymbol, core);
        let value_error = |reason| reloc_error(rel, reason, core);
        let relocation_target_value = |target| {
            Self::object_relocation_value(r_type.raw() as usize, target, append, place.get())
        };
        let write_relocation_target = |target| -> crate::Result<()> {
            Self::write_object_value(
                segments,
                place,
                relocation_target_value(target).map_err(value_error)?,
            )
        };

        match r_type.raw() {
            R_X86_64_NONE => {}
            R_X86_64_64 => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                write_relocation_target(sym.get())?;
            }
            R_X86_64_PC32 => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                write_relocation_target(sym.get())?;
            }
            R_X86_64_PLT32 => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                match relocation_target_value(sym.get()) {
                    Ok(value) => Self::write_object_value(segments, place, value)?,
                    Err(RelocReason::IntConversionOutOfRange) => {
                        let plt_entry = pltgot.add_plt_entry(r_sym);
                        let plt_entry_addr = match plt_entry {
                            PltEntry::Occupied(plt_entry_addr) => plt_entry_addr,
                            PltEntry::Vacant { plt, mut got } => {
                                let plt_entry_addr = VmAddr::from_ptr(plt.as_ptr());
                                got.update(sym);
                                let call_offset = VmAddr::new(
                                    got.get_addr()
                                        .get()
                                        .wrapping_sub(plt_entry_addr.get())
                                        .wrapping_sub(10),
                                );
                                let call_offset_val =
                                    call_offset.try_into_sword32().map_err(value_error)?;
                                plt[6..10].copy_from_slice(&call_offset_val.to_ne_bytes());
                                plt_entry_addr
                            }
                        };
                        write_relocation_target(plt_entry_addr.get())?;
                    }
                    Err(reason) => return Err(value_error(reason)),
                }
            }
            R_X86_64_GOTPCREL => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                let got_entry = pltgot.add_got_entry(r_sym);
                let got_entry_addr = match got_entry {
                    GotEntry::Occupied(got_entry_addr) => got_entry_addr,
                    GotEntry::Vacant(mut got) => {
                        got.update(sym);
                        got.get_addr()
                    }
                };
                write_relocation_target(got_entry_addr.get())?;
            }
            R_X86_64_32 => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                write_relocation_target(sym.get())?;
            }
            R_X86_64_32S => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                write_relocation_target(sym.get())?;
            }
            _ => return Err(unknown_symbol()),
        }

        Ok(())
    }

    pub(crate) fn object_needs_got_impl(rel_type: crate::elf::ElfRelocationType) -> bool {
        matches!(rel_type.raw(), R_X86_64_GOTPCREL | R_X86_64_PLT32)
    }

    pub(crate) fn object_needs_plt_impl(rel_type: crate::elf::ElfRelocationType) -> bool {
        rel_type.raw() == R_X86_64_PLT32
    }
}
