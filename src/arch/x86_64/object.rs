use crate::{
    RelocReason, Result,
    arch::x86_64::X86_64Arch,
    elf::{ElfRelEntry, ElfRelType, ElfRelocationType, ElfShdr},
    memory::{ImageMemory, ImageMemoryExt, RegionAccess, VmAddr},
    object::layout::{GotEntry, ObjectRelocKey, PltEntry, PltGotSection},
    observer::RelocationObserver,
    relocation::{ObjectRelocation, RelocHelper, RelocationArch},
    tls::TlsResolver,
};
use elf::abi::*;

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) const PLT_ENTRY_SIZE: usize = 16;

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) const PLT_ENTRY: [u8; PLT_ENTRY_SIZE] = [
    0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25, 0, 0, 0, 0, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

fn displacement(
    target: VmAddr,
    addend: isize,
    place: VmAddr,
) -> core::result::Result<i32, core::num::TryFromIntError> {
    i32::try_from(target.get() as i128 + addend as i128 - place.get() as i128)
}

impl ObjectRelocation for X86_64Arch {
    type State = ();

    fn relocate<D, R, Tls, Obs, Memory>(
        _state: &mut Self::State,
        helper: &mut RelocHelper<'_, D, Self, R, Tls, Obs, Memory>,
        rel: &ElfRelType<Self>,
        target: &ElfShdr<<Self as RelocationArch>::Layout>,
        pltgot: &mut PltGotSection,
    ) -> Result<()>
    where
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<Self>,
        Obs: RelocationObserver<Self> + ?Sized,
        Memory: ImageMemory,
    {
        let place = VmAddr::new(target.sh_addr()) + rel.r_offset();
        let addend = rel.read_addend(helper.memory(), place)?;
        let out_of_range = |_| helper.reloc_error(rel, RelocReason::IntConversionOutOfRange);
        match rel.r_type().raw() {
            R_X86_64_NONE => {}
            R_X86_64_64 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let value = (sym.get() as u64).wrapping_add_signed(addend as i64);
                unsafe { helper.memory().write_value(place, value)? };
            }
            R_X86_64_32 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let value =
                    u32::try_from(sym.get() as i128 + addend as i128).map_err(out_of_range)?;
                unsafe { helper.memory().write_value(place, value)? };
            }
            R_X86_64_32S => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let value =
                    i32::try_from(sym.get() as i128 + addend as i128).map_err(out_of_range)?;
                unsafe { helper.memory().write_value(place, value)? };
            }
            R_X86_64_PC32 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let value = displacement(sym, addend, place).map_err(out_of_range)?;
                unsafe { helper.memory().write_value(place, value)? };
            }
            R_X86_64_PLT32 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let value = match displacement(sym, addend, place) {
                    Ok(value) => value,
                    Err(_) => {
                        let key = ObjectRelocKey::new::<Self>(rel, addend);
                        let stub = match pltgot.add_plt_entry(key) {
                            PltEntry::Occupied(addr) => addr,
                            PltEntry::Vacant { plt, mut got } => {
                                let stub = VmAddr::from_ptr(plt.as_ptr());
                                got.update(sym);
                                // The indirect jump reads the GOT relative to the end of the instruction.
                                let offset = displacement(got.get_addr(), -10, stub)
                                    .map_err(out_of_range)?;
                                plt[6..10].copy_from_slice(&offset.to_le_bytes());
                                stub
                            }
                        };
                        displacement(stub, addend, place).map_err(out_of_range)?
                    }
                };
                unsafe { helper.memory().write_value(place, value)? };
            }
            R_X86_64_GOTPCREL => {
                let key = ObjectRelocKey::new::<Self>(rel, addend);
                let addr = match pltgot.add_got_entry(key) {
                    GotEntry::Occupied(addr) => addr,
                    GotEntry::Vacant(mut got) => {
                        got.update(helper.symbol_addr(rel.r_symbol()));
                        got.get_addr()
                    }
                };
                let value = displacement(addr, addend, place).map_err(out_of_range)?;
                unsafe { helper.memory().write_value(place, value)? };
            }
            _ => return Err(helper.reloc_error(rel, RelocReason::UnknownSymbol)),
        }

        Ok(())
    }

    #[inline]
    fn needs_got(r_type: ElfRelocationType) -> bool {
        r_type.raw() == R_X86_64_GOTPCREL
    }

    #[inline]
    fn needs_plt(r_type: ElfRelocationType) -> bool {
        r_type.raw() == R_X86_64_PLT32
    }
}
