use crate::{
    RelocReason,
    arch::x86_64::relocation::X86_64Arch,
    elf::{ElfRelType, ElfShdr},
    memory::{ImageMemory, RegionAccess, VmAddr},
    object::{
        layout::{GotEntry, ObjectRelocKey, PltEntry, PltGotSection},
        object_relocation_addend,
    },
    relocation::{
        RelocHelper, RelocValue, RelocationHandler, RelocationValueProvider, reloc_error,
    },
};
use elf::abi::*;

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) const PLT_ENTRY_SIZE: usize = 16;

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
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
    fn write_object_value<Memory>(
        memory: &Memory,
        place: VmAddr,
        value: ObjectWrite,
    ) -> crate::Result<()>
    where
        Memory: ImageMemory,
    {
        unsafe {
            match value {
                ObjectWrite::None => {}
                ObjectWrite::Addr(value) => memory.write_value(place, value.get())?,
                ObjectWrite::Word32(value) => memory.write_value(place, value.into_inner())?,
                ObjectWrite::SWord32(value) => memory.write_value(place, value.into_inner())?,
            }
        }
        Ok(())
    }

    pub(crate) fn relocate_object_impl<D, R, PreH, PostH, Obs, H, Memory>(
        helper: &mut RelocHelper<'_, D, Self, R, PreH, PostH, Obs, H, Memory>,
        rel: &ElfRelType<Self>,
        target: &ElfShdr<<Self as crate::relocation::RelocationArch>::Layout>,
        pltgot: &mut PltGotSection,
    ) -> crate::Result<()>
    where
        D: 'static,
        R: RegionAccess,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: crate::observer::RelocationObserver<Self> + ?Sized,
        Memory: ImageMemory,
    {
        let r_type = rel.r_type();
        let core = helper.core;
        let append = object_relocation_addend::<Self, _>(helper.memory(), target, rel)?;
        let place = VmAddr::new(target.sh_addr()) + rel.r_offset();
        let unknown_symbol = || {
            reloc_error(
                rel,
                crate::RelocReason::UnknownSymbol,
                core,
                helper.symbols(),
            )
        };
        let value_error = |reason| reloc_error(rel, reason, core, helper.symbols());
        let relocation_target_value = |target| {
            Self::object_relocation_value(r_type.raw() as usize, target, append, place.get())
        };
        let write_relocation_target = |memory: &Memory, target| -> crate::Result<()> {
            Self::write_object_value(
                memory,
                place,
                relocation_target_value(target).map_err(value_error)?,
            )
        };

        match r_type.raw() {
            R_X86_64_NONE => {}
            R_X86_64_64 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                write_relocation_target(helper.memory(), sym.get())?;
            }
            R_X86_64_PC32 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                write_relocation_target(helper.memory(), sym.get())?;
            }
            R_X86_64_PLT32 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                match relocation_target_value(sym.get()) {
                    Ok(value) => Self::write_object_value(helper.memory(), place, value)?,
                    Err(RelocReason::IntConversionOutOfRange) => {
                        let key = ObjectRelocKey::new::<Self>(rel);
                        let plt_entry = pltgot.add_plt_entry(key);
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
                        write_relocation_target(helper.memory(), plt_entry_addr.get())?;
                    }
                    Err(reason) => return Err(value_error(reason)),
                }
            }
            R_X86_64_GOTPCREL => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let key = ObjectRelocKey::new::<Self>(rel);
                let got_entry = pltgot.add_got_entry(key);
                let got_entry_addr = match got_entry {
                    GotEntry::Occupied(got_entry_addr) => got_entry_addr,
                    GotEntry::Vacant(mut got) => {
                        got.update(sym);
                        got.get_addr()
                    }
                };
                write_relocation_target(helper.memory(), got_entry_addr.get())?;
            }
            R_X86_64_32 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                write_relocation_target(helper.memory(), sym.get())?;
            }
            R_X86_64_32S => {
                let sym = helper.symbol_addr(rel.r_symbol());
                write_relocation_target(helper.memory(), sym.get())?;
            }
            _ => return Err(unknown_symbol()),
        }

        Ok(())
    }

    pub(crate) fn object_needs_got_impl(r_type: crate::elf::ElfRelocationType) -> bool {
        r_type.raw() == R_X86_64_GOTPCREL
    }

    pub(crate) fn object_needs_plt_impl(r_type: crate::elf::ElfRelocationType) -> bool {
        r_type.raw() == R_X86_64_PLT32
    }
}
